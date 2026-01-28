"""Core Modbus TCP honeypot engine (standard library only).

This module implements real Modbus TCP framing per the Modbus
Application Protocol Specification V1.1b3:

  MBAP header (7 bytes):
    Transaction Id (2), Protocol Id (2), Length (2), Unit Id (1)
  PDU:
    Function code (1) + function-specific data

It decodes the common data-access function codes, builds plausible
honeypot responses, and classifies each request into a JSON threat
event with severity. No third-party imports.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Iterator

TOOL_NAME = "modpot"
TOOL_VERSION = "1.0.0"

# Modbus function codes we understand.
FUNCTION_NAMES = {
    0x01: "read_coils",
    0x02: "read_discrete_inputs",
    0x03: "read_holding_registers",
    0x04: "read_input_registers",
    0x05: "write_single_coil",
    0x06: "write_single_register",
    0x0F: "write_multiple_coils",
    0x10: "write_multiple_registers",
    0x16: "mask_write_register",
    0x17: "read_write_multiple_registers",
    0x2B: "encapsulated_interface_transport",
    0x08: "diagnostics",
    0x11: "report_server_id",
}

READ_CODES = {0x01, 0x02, 0x03, 0x04}
WRITE_CODES = {0x05, 0x06, 0x0F, 0x10, 0x16}
# Function codes that are unusual coming from an unauthenticated peer
# against a field device -- strong recon / tampering signals.
SUSPICIOUS_CODES = {0x08, 0x11, 0x2B, 0x16}

MODBUS_PROTOCOL_ID = 0x0000
MBAP_LEN = 7


class ParseError(ValueError):
    """Raised when a byte buffer is not a well-formed Modbus TCP frame."""


@dataclass
class ModbusFrame:
    """A decoded Modbus TCP request frame."""

    transaction_id: int
    protocol_id: int
    length: int
    unit_id: int
    function_code: int
    function_name: str
    # Decoded, function-specific fields (best effort).
    address: int | None = None
    quantity: int | None = None
    value: int | None = None
    values: list[int] = field(default_factory=list)
    raw: bytes = b""
    decoded: bool = True
    note: str = ""

    def to_dict(self) -> dict:
        d = {
            "transaction_id": self.transaction_id,
            "protocol_id": self.protocol_id,
            "length": self.length,
            "unit_id": self.unit_id,
            "function_code": self.function_code,
            "function_name": self.function_name,
            "address": self.address,
            "quantity": self.quantity,
            "value": self.value,
            "values": list(self.values),
            "decoded": self.decoded,
            "note": self.note,
        }
        return d


def parse_frame(buf: bytes) -> ModbusFrame:
    """Parse a single Modbus TCP frame from *buf*.

    Validates the MBAP header and decodes the PDU for known function
    codes. Raises :class:`ParseError` on malformed input.
    """
    if len(buf) < MBAP_LEN + 1:
        raise ParseError(f"frame too short: {len(buf)} bytes")
    tid, pid, length, uid = struct.unpack(">HHHB", buf[:7])
    if pid != MODBUS_PROTOCOL_ID:
        raise ParseError(f"bad protocol id 0x{pid:04x} (expected 0x0000)")
    # length counts unit id + PDU.
    if length < 2:
        raise ParseError(f"bad MBAP length {length}")
    pdu = buf[7:7 + (length - 1)]
    if len(pdu) < 1:
        raise ParseError("missing function code")
    fc = pdu[0]
    name = FUNCTION_NAMES.get(fc, f"unknown_0x{fc:02x}")
    frame = ModbusFrame(
        transaction_id=tid,
        protocol_id=pid,
        length=length,
        unit_id=uid,
        function_code=fc,
        function_name=name,
        raw=buf[:7 + (length - 1)],
    )
    body = pdu[1:]
    try:
        _decode_pdu(frame, fc, body)
    except (struct.error, IndexError):
        frame.decoded = False
        frame.note = "truncated or malformed PDU body"
    return frame


def _decode_pdu(frame: ModbusFrame, fc: int, body: bytes) -> None:
    if fc in (0x01, 0x02, 0x03, 0x04):
        addr, qty = struct.unpack(">HH", body[:4])
        frame.address = addr
        frame.quantity = qty
    elif fc in (0x05, 0x06):
        addr, val = struct.unpack(">HH", body[:4])
        frame.address = addr
        frame.value = val
    elif fc == 0x0F:  # write multiple coils
        addr, qty, bytecount = struct.unpack(">HHB", body[:5])
        frame.address = addr
        frame.quantity = qty
        bits: list[int] = []
        for b in body[5:5 + bytecount]:
            for i in range(8):
                if len(bits) >= qty:
                    break
                bits.append((b >> i) & 1)
        frame.values = bits
    elif fc == 0x10:  # write multiple registers
        addr, qty, bytecount = struct.unpack(">HHB", body[:5])
        frame.address = addr
        frame.quantity = qty
        regs = body[5:5 + bytecount]
        frame.values = [
            struct.unpack(">H", regs[i:i + 2])[0]
            for i in range(0, len(regs) - 1, 2)
        ]
    elif fc == 0x16:  # mask write register
        addr, and_mask, or_mask = struct.unpack(">HHH", body[:6])
        frame.address = addr
        frame.values = [and_mask, or_mask]
    else:
        frame.decoded = False
        frame.note = "function code body not decoded"


def build_response(frame: ModbusFrame) -> bytes:
    """Build a plausible honeypot response for a parsed request *frame*.

    Reads return zeroed register/coil data of the requested size; writes
    echo back the request per spec. Unknown/unsupported codes return a
    Modbus exception response (code 0x01, illegal function) so the
    honeypot looks like a real but minimal device.
    """
    fc = frame.function_code
    if fc in (0x01, 0x02):
        qty = frame.quantity or 0
        nbytes = (qty + 7) // 8
        pdu = bytes([fc, nbytes]) + b"\x00" * nbytes
    elif fc in (0x03, 0x04):
        qty = frame.quantity or 0
        nbytes = qty * 2
        pdu = bytes([fc, nbytes]) + b"\x00" * nbytes
    elif fc in (0x05, 0x06):
        pdu = bytes([fc]) + struct.pack(">HH", frame.address or 0, frame.value or 0)
    elif fc in (0x0F, 0x10):
        pdu = bytes([fc]) + struct.pack(">HH", frame.address or 0, frame.quantity or 0)
    else:
        # Exception response: function code | 0x80, exception 0x01.
        pdu = bytes([(fc | 0x80) & 0xFF, 0x01])
    length = len(pdu) + 1  # + unit id
    mbap = struct.pack(
        ">HHHB", frame.transaction_id, MODBUS_PROTOCOL_ID, length, frame.unit_id
    )
    return mbap + pdu


def classify_event(frame: ModbusFrame) -> tuple[str, str, list[str]]:
    """Classify a frame into (category, severity, reasons).

    Severity is one of: info, low, medium, high.
    """
    fc = frame.function_code
    reasons: list[str] = []
    if fc in WRITE_CODES:
        category = "write"
    elif fc in READ_CODES:
        category = "read"
    elif fc in FUNCTION_NAMES:
        category = "control"
    else:
        category = "unknown"

    severity = "info"
    if category == "read":
        severity = "low"
        if frame.quantity and frame.quantity > 125:
            severity = "medium"
            reasons.append(f"oversized read quantity {frame.quantity} (>125)")
    if category == "write":
        # Any unauthenticated write to a control device is high-signal.
        severity = "high"
        reasons.append("register/coil write attempt against control device")
    if fc in SUSPICIOUS_CODES:
        severity = "high"
        reasons.append(f"suspicious function {frame.function_name} (recon/tamper)")
    if category == "unknown":
        severity = "medium"
        reasons.append(f"unknown function code 0x{fc:02x} (scanner/fuzzing)")
    if not frame.decoded:
        if severity in ("info", "low"):
            severity = "medium"
        reasons.append("undecodable PDU (malformed/fuzz traffic)")
    if not reasons:
        reasons.append("benign register read")
    return category, severity, reasons


def frame_to_event(
    frame: ModbusFrame,
    src: str = "",
    ts: str | None = None,
) -> dict:
    """Convert a parsed frame into a JSON-ready threat event dict."""
    category, severity, reasons = classify_event(frame)
    if ts is None:
        ts = datetime.now(timezone.utc).isoformat()
    return {
        "timestamp": ts,
        "src": src,
        "category": category,
        "severity": severity,
        "reasons": reasons,
        "unit_id": frame.unit_id,
        "function_code": frame.function_code,
        "function_name": frame.function_name,
        "address": frame.address,
        "quantity": frame.quantity,
        "value": frame.value,
        "values": list(frame.values),
        "transaction_id": frame.transaction_id,
        "decoded": frame.decoded,
    }


def _clean_hex(text: str) -> str:
    out = []
    for ch in text:
        if ch in "0123456789abcdefABCDEF":
            out.append(ch)
    return "".join(out)


def iter_frames_from_hexlog(lines: Iterable[str]) -> Iterator[tuple[str, bytes]]:
    """Yield (src, raw_bytes) tuples from a hex capture log.

    Each non-empty, non-comment line is one captured frame. A line may
    optionally be prefixed with a source identifier and a tab or '|':

        10.0.0.9 | 000100000006010300000001
        deadc0de\t0001000000060106000100ff

    Whitespace and ``0x`` prefixes inside the hex are ignored.
    """
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        src = ""
        hexpart = line
        for sep in ("|", "\t"):
            if sep in line:
                src, hexpart = line.split(sep, 1)
                src = src.strip()
                break
        hexpart = hexpart.replace("0x", "").replace("0X", "")
        cleaned = _clean_hex(hexpart)
        if len(cleaned) < 2:
            continue
        if len(cleaned) % 2 != 0:
            cleaned = cleaned[:-1]
        try:
            raw = bytes.fromhex(cleaned)
        except ValueError:
            continue
        yield src, raw


def analyze_capture(lines: Iterable[str]) -> list[dict]:
    """Parse + classify every frame in a hex capture log into events.

    Malformed frames still produce an event (severity medium) so nothing
    silently disappears -- a honeypot must record the fuzz traffic too.
    """
    events: list[dict] = []
    for src, raw in iter_frames_from_hexlog(lines):
        try:
            frame = parse_frame(raw)
        except ParseError as exc:
            events.append(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "src": src,
                    "category": "unknown",
                    "severity": "medium",
                    "reasons": [f"unparseable frame: {exc}"],
                    "unit_id": None,
                    "function_code": None,
                    "function_name": None,
                    "address": None,
                    "quantity": None,
                    "value": None,
                    "values": [],
                    "transaction_id": None,
                    "decoded": False,
                    "raw_hex": raw.hex(),
                }
            )
            continue
        events.append(frame_to_event(frame, src=src))
    return events
