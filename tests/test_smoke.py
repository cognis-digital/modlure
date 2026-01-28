"""Smoke tests for MODPOT. No network access."""
import os
import struct

import pytest

from modpot import core
from modpot.cli import main

DEMO = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "demos", "01-basic", "capture.hexlog"
)


def _build_read_holding(tid=1, uid=1, addr=0, qty=1):
    pdu = bytes([0x03]) + struct.pack(">HH", addr, qty)
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, uid) + pdu


def _build_write_single(tid=2, uid=1, addr=1, val=0x00FF):
    pdu = bytes([0x06]) + struct.pack(">HH", addr, val)
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, uid) + pdu


def test_parse_read_holding_registers():
    frame = core.parse_frame(_build_read_holding(addr=7, qty=10))
    assert frame.function_code == 0x03
    assert frame.function_name == "read_holding_registers"
    assert frame.address == 7
    assert frame.quantity == 10
    assert frame.decoded


def test_parse_write_single_register():
    frame = core.parse_frame(_build_write_single(addr=1, val=0x00FF))
    assert frame.function_code == 0x06
    assert frame.address == 1
    assert frame.value == 0x00FF


def test_write_multiple_registers_decodes_values():
    addr, qty = 0x10, 2
    regs = struct.pack(">HH", 0x1234, 0x5678)
    pdu = bytes([0x10]) + struct.pack(">HHB", addr, qty, len(regs)) + regs
    raw = struct.pack(">HHHB", 3, 0, len(pdu) + 1, 1) + pdu
    frame = core.parse_frame(raw)
    assert frame.function_name == "write_multiple_registers"
    assert frame.values == [0x1234, 0x5678]


def test_bad_protocol_id_raises():
    raw = struct.pack(">HHHB", 1, 0xDEAD, 6, 1) + bytes([0x03, 0, 0, 0, 1])
    with pytest.raises(core.ParseError):
        core.parse_frame(raw)


def test_classify_write_is_high():
    frame = core.parse_frame(_build_write_single())
    category, severity, reasons = core.classify_event(frame)
    assert category == "write"
    assert severity == "high"
    assert reasons


def test_classify_read_is_low():
    frame = core.parse_frame(_build_read_holding())
    category, severity, _ = core.classify_event(frame)
    assert category == "read"
    assert severity == "low"


def test_oversized_read_is_medium():
    frame = core.parse_frame(_build_read_holding(qty=200))
    _, severity, _ = core.classify_event(frame)
    assert severity == "medium"


def test_build_response_read_returns_zeroed_data():
    frame = core.parse_frame(_build_read_holding(qty=3))
    resp = core.build_response(frame)
    # MBAP(7) + fc(1) + bytecount(1) + 3*2 data bytes
    assert len(resp) == 7 + 2 + 6
    assert resp[7] == 0x03
    assert resp[8] == 6  # byte count


def test_build_response_unknown_is_exception():
    raw = struct.pack(">HHHB", 9, 0, 2, 1) + bytes([0x11])  # report server id
    frame = core.parse_frame(raw)
    resp = core.build_response(frame)
    assert resp[7] == (0x11 | 0x80)
    assert resp[8] == 0x01  # illegal function exception


def test_analyze_capture_on_demo():
    with open(DEMO, "r", encoding="utf-8") as fh:
        events = core.analyze_capture(fh.read().splitlines())
    assert len(events) == 6
    sevs = [e["severity"] for e in events]
    assert sevs.count("high") == 3
    assert "low" in sevs
    assert "medium" in sevs
    # a malformed frame must still be recorded
    assert any("unparseable" in r for e in events for r in e["reasons"])


def test_cli_exits_nonzero_on_high(capsys):
    rc = main(["analyze", DEMO, "--format", "json"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "function_name" in out
    assert "\"severity\": \"high\"" in out


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert core.TOOL_VERSION in capsys.readouterr().out


def test_cli_table_format(capsys):
    rc = main(["analyze", DEMO])
    assert rc == 1
    out = capsys.readouterr().out
    assert "SEV" in out and "FUNCTION" in out
    assert "total=6" in out
