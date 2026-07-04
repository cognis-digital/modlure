"""modlure.probe — AUTHORIZATION-GATED active Modbus client probe.

MODLURE is a DEFENSIVE Modbus TCP tool. Everything else in this package is
*passive*: it decodes captures and runs a honeypot listener (you own the
socket). This module is the one **active** capability — it opens an outbound
Modbus/TCP connection to a device and issues *read-only* requests to confirm
reachability and fingerprint the unit (function 0x2B/0x11 device identity plus
a small holding-register read).

Active scanning of equipment you are not explicitly authorized to test can be
illegal and unsafe on a live OT/ICS network. Therefore active mode is:

  * **OFF by default.** It only runs from ``modlure probe`` with ``--authorized``.
  * **Scope-enforced.** Every target must appear in an allowlist (``--target``
    repeatable, or ``--scope-file``). Targets outside scope are skipped with a
    loud refusal — never probed.
  * **Read-only.** It issues *only* read / identity function codes. Write and
    control codes are refused before a byte leaves the host.
  * **Rate-limited.** A minimum inter-request delay (``--rate``, default 1.0s)
    throttles traffic so a fragile PLC is not overwhelmed.

This module performs no writes, no exploitation, and fabricates no data. It is
for confirming the posture of devices you operate or are contracted to assess.
"""
from __future__ import annotations

import ipaddress
import socket
import struct
import time
from dataclasses import dataclass, field

from .core import MODBUS_PROTOCOL_ID, FUNCTION_NAMES

AUTHORIZED_USE_BANNER = (
    "================================================================\n"
    " modlure ACTIVE PROBE — AUTHORIZED USE ONLY\n"
    " You are issuing live, outbound Modbus requests. Only probe\n"
    " devices you own or are explicitly contracted to assess.\n"
    " Read-only, scope-enforced, rate-limited. No writes are sent.\n"
    "================================================================"
)

# The only function codes active mode is ever allowed to transmit. All are
# non-mutating reads / identity queries.
READONLY_PROBE_CODES = {
    0x03,  # read_holding_registers
    0x04,  # read_input_registers
    0x01,  # read_coils
    0x02,  # read_discrete_inputs
    0x11,  # report_server_id
    0x2B,  # encapsulated_interface_transport (read device identification)
}

# Codes that mutate device state — categorically refused in active mode.
FORBIDDEN_ACTIVE_CODES = {0x05, 0x06, 0x0F, 0x10, 0x16, 0x08}


class ScopeError(PermissionError):
    """Raised when a target is not inside the authorized allowlist."""


class UnauthorizedError(PermissionError):
    """Raised when active probing is attempted without --authorized."""


class UnsafeFunctionError(ValueError):
    """Raised when a non-read-only function code is requested in active mode."""


@dataclass
class Target:
    host: str
    port: int = 502

    @classmethod
    def parse(cls, spec: str) -> "Target":
        """Parse ``host`` or ``host:port`` into a :class:`Target`."""
        spec = spec.strip()
        if not spec:
            raise ValueError("empty target")
        # Bracketed IPv6, e.g. [::1]:502
        if spec.startswith("["):
            host, _, rest = spec[1:].partition("]")
            port = int(rest.lstrip(":")) if rest.lstrip(":") else 502
            return cls(host, port)
        if spec.count(":") == 1:
            host, _, p = spec.partition(":")
            return cls(host, int(p) if p else 502)
        return cls(spec, 502)

    def key(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass
class Scope:
    """An allowlist of authorized targets. A target must match exactly."""

    targets: list[Target] = field(default_factory=list)

    @classmethod
    def from_specs(cls, specs) -> "Scope":
        return cls([Target.parse(s) for s in specs if s and s.strip()])

    @classmethod
    def from_file(cls, path: str) -> "Scope":
        out: list[Target] = []
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                out.append(Target.parse(line))
        return cls(out)

    def keys(self) -> set[str]:
        return {t.key() for t in self.targets}

    def allows(self, target: Target) -> bool:
        return target.key() in self.keys()

    def check(self, target: Target) -> None:
        if not self.allows(target):
            raise ScopeError(
                f"target {target.key()} is NOT in the authorized scope "
                f"(allowed: {sorted(self.keys()) or 'none'}) — refusing to probe"
            )


def build_request(tid: int, unit_id: int, fc: int, body: bytes = b"") -> bytes:
    """Build a Modbus/TCP request frame. Refuses non-read-only codes."""
    if fc not in READONLY_PROBE_CODES:
        raise UnsafeFunctionError(
            f"function 0x{fc:02x} ({FUNCTION_NAMES.get(fc, 'unknown')}) "
            f"is not a read-only probe code — refused in active mode"
        )
    pdu = bytes([fc]) + body
    mbap = struct.pack(">HHHB", tid, MODBUS_PROTOCOL_ID, len(pdu) + 1, unit_id)
    return mbap + pdu


def read_holding_request(tid: int, unit_id: int, addr: int, qty: int) -> bytes:
    return build_request(tid, unit_id, 0x03, struct.pack(">HH", addr, qty))


def report_server_id_request(tid: int, unit_id: int) -> bytes:
    return build_request(tid, unit_id, 0x11)


def device_identification_request(tid: int, unit_id: int) -> bytes:
    # MEI type 0x0E read device id, read-device-id code 0x01 (basic), object 0x00
    return build_request(tid, unit_id, 0x2B, bytes([0x0E, 0x01, 0x00]))


def _recv_exact(conn: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def read_response(conn: socket.socket) -> bytes | None:
    """Read one MBAP-framed Modbus response from *conn* (or None on EOF)."""
    head = _recv_exact(conn, 7)
    if head is None:
        return None
    _, _, length, _ = struct.unpack(">HHHB", head)
    rest = _recv_exact(conn, max(length - 1, 0))
    if rest is None:
        return head
    return head + rest


def interpret_response(raw: bytes) -> dict:
    """Interpret a probe response frame into a flat dict (no exceptions)."""
    if len(raw) < 8:
        return {"ok": False, "error": "short response", "raw_hex": raw.hex()}
    tid, pid, length, uid = struct.unpack(">HHHB", raw[:7])
    fc = raw[7]
    out: dict = {"transaction_id": tid, "unit_id": uid, "function_code": fc}
    if fc & 0x80:
        out["ok"] = False
        out["exception_code"] = raw[8] if len(raw) > 8 else None
        out["function_name"] = FUNCTION_NAMES.get(fc & 0x7F, f"unknown_0x{fc & 0x7F:02x}")
        return out
    out["ok"] = True
    out["function_name"] = FUNCTION_NAMES.get(fc, f"unknown_0x{fc:02x}")
    body = raw[8:]
    if fc in (0x01, 0x02, 0x03, 0x04) and body:
        bytecount = body[0]
        out["byte_count"] = bytecount
        out["data_hex"] = body[1:1 + bytecount].hex()
    elif fc == 0x11:
        out["server_id_hex"] = body.hex()
    elif fc == 0x2B:
        out["device_id_hex"] = body.hex()
    return out


class Probe:
    """An authorization-gated, scope-enforced, rate-limited active probe.

    Connections and reads are *only* possible once ``authorized=True`` and the
    requested target is inside ``scope``. Construct it, then call
    :meth:`probe_target` per allowed target.
    """

    def __init__(
        self,
        scope: Scope,
        *,
        authorized: bool = False,
        rate: float = 1.0,
        timeout: float = 3.0,
        unit_id: int = 1,
        _clock=time.monotonic,
        _sleep=time.sleep,
    ) -> None:
        self.scope = scope
        self.authorized = authorized
        self.rate = max(0.0, float(rate))
        self.timeout = timeout
        self.unit_id = unit_id
        self._tid = 0
        self._last_send = 0.0
        self._clock = _clock
        self._sleep = _sleep

    def _require_authorized(self) -> None:
        if not self.authorized:
            raise UnauthorizedError(
                "active probing is OFF by default — pass --authorized "
                "(authorized-use-only) to enable it"
            )

    def _next_tid(self) -> int:
        self._tid = (self._tid + 1) & 0xFFFF
        return self._tid

    def _throttle(self) -> None:
        """Enforce the minimum inter-request delay (rate limit)."""
        if self.rate <= 0:
            return
        now = self._clock()
        wait = self.rate - (now - self._last_send)
        if wait > 0:
            self._sleep(wait)
        self._last_send = self._clock()

    def probe_target(
        self,
        target: Target,
        *,
        addr: int = 0,
        qty: int = 1,
        _connect=None,
    ) -> dict:
        """Probe one in-scope target read-only. Returns a result dict.

        ``_connect`` is an injectable ``(host, port, timeout) -> socket``
        factory so tests can drive this against a localhost fixture without
        monkeypatching the stdlib.
        """
        self._require_authorized()
        self.scope.check(target)  # raises ScopeError if out of scope
        if qty < 1 or qty > 125:
            raise ValueError("holding-register read qty must be 1..125")

        result: dict = {
            "target": target.key(),
            "host": target.host,
            "port": target.port,
            "reachable": False,
            "responses": [],
        }
        connect = _connect or _default_connect
        try:
            conn = connect(target.host, target.port, self.timeout)
        except OSError as exc:
            result["error"] = f"connect failed: {exc}"
            return result
        result["reachable"] = True
        try:
            requests = [
                ("read_holding_registers", read_holding_request(
                    self._next_tid(), self.unit_id, addr, qty)),
                ("report_server_id", report_server_id_request(
                    self._next_tid(), self.unit_id)),
                ("device_identification", device_identification_request(
                    self._next_tid(), self.unit_id)),
            ]
            for label, req in requests:
                self._throttle()
                conn.sendall(req)
                raw = read_response(conn)
                if raw is None:
                    result["responses"].append({"query": label, "ok": False,
                                                 "error": "no response (EOF)"})
                    break
                info = interpret_response(raw)
                info["query"] = label
                result["responses"].append(info)
        finally:
            try:
                conn.close()
            except OSError:
                pass
        return result

    def run(self, targets, **kw) -> list[dict]:
        """Probe a batch of targets, skipping any outside scope (loudly)."""
        self._require_authorized()
        out: list[dict] = []
        for t in targets:
            tgt = t if isinstance(t, Target) else Target.parse(t)
            try:
                self.scope.check(tgt)
            except ScopeError as exc:
                out.append({"target": tgt.key(), "skipped": True,
                            "reason": str(exc)})
                continue
            out.append(self.probe_target(tgt, **kw))
        return out


def _default_connect(host: str, port: int, timeout: float) -> socket.socket:
    conn = socket.create_connection((host, port), timeout=timeout)
    conn.settimeout(timeout)
    return conn


def is_loopback(host: str) -> bool:
    """True if *host* is a loopback address (used by tests / safety checks)."""
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host in ("localhost",)
