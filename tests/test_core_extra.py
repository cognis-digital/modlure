"""Extended OFFLINE tests for modlure.core — parsing, classification,
response building, SARIF, hexlog iteration, and the passive summary.
"""
import struct

import pytest

from modlure import core
from modlure.core import (
    parse_frame,
    build_response,
    classify_event,
    frame_to_event,
    to_sarif,
    summarize_events,
    iter_frames_from_hexlog,
    analyze_capture,
    ParseError,
)


def _frame(fc, body=b"", tid=1, uid=1):
    pdu = bytes([fc]) + body
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, uid) + pdu


# ------------------------------- parsing ---------------------------------- #

def test_parse_read_coils():
    f = parse_frame(_frame(0x01, struct.pack(">HH", 0, 16)))
    assert f.function_name == "read_coils"
    assert f.quantity == 16


def test_parse_read_discrete_inputs():
    f = parse_frame(_frame(0x02, struct.pack(">HH", 5, 8)))
    assert f.function_name == "read_discrete_inputs"
    assert f.address == 5


def test_parse_read_input_registers():
    f = parse_frame(_frame(0x04, struct.pack(">HH", 100, 4)))
    assert f.function_name == "read_input_registers"
    assert f.quantity == 4


def test_parse_write_single_coil():
    f = parse_frame(_frame(0x05, struct.pack(">HH", 3, 0xFF00)))
    assert f.function_name == "write_single_coil"
    assert f.value == 0xFF00


def test_parse_write_multiple_coils():
    qty = 10
    bits = bytes([0b10101010, 0b00000011])
    body = struct.pack(">HHB", 0, qty, len(bits)) + bits
    f = parse_frame(_frame(0x0F, body))
    assert f.function_name == "write_multiple_coils"
    assert len(f.values) == qty
    assert set(f.values) <= {0, 1}


def test_parse_mask_write_register():
    body = struct.pack(">HHH", 4, 0x00FF, 0xFF00)
    f = parse_frame(_frame(0x16, body))
    assert f.function_name == "mask_write_register"
    assert f.values == [0x00FF, 0xFF00]


def test_parse_unknown_function_code():
    f = parse_frame(_frame(0x63))
    assert f.function_name.startswith("unknown_0x63")
    assert f.decoded is False


def test_parse_too_short_raises():
    with pytest.raises(ParseError):
        parse_frame(b"\x00\x01\x00")


def test_parse_bad_length_raises():
    raw = struct.pack(">HHHB", 1, 0, 1, 1) + b"\x03"
    with pytest.raises(ParseError):
        parse_frame(raw)


def test_parse_truncated_pdu_marks_undecoded():
    # claims length for a read but body is missing the qty
    pdu = bytes([0x03, 0x00])  # only 1 of 4 expected body bytes
    raw = struct.pack(">HHHB", 1, 0, len(pdu) + 1, 1) + pdu
    f = parse_frame(raw)
    assert f.decoded is False
    assert "malformed" in f.note or "truncated" in f.note


def test_to_dict_roundtrip_keys():
    f = parse_frame(_frame(0x03, struct.pack(">HH", 0, 1)))
    d = f.to_dict()
    for k in ("transaction_id", "function_code", "function_name", "address",
              "quantity", "decoded"):
        assert k in d


# --------------------------- classification ------------------------------- #

def test_classify_read_coils_low():
    f = parse_frame(_frame(0x01, struct.pack(">HH", 0, 8)))
    cat, sev, _ = classify_event(f)
    assert cat == "read" and sev == "low"


def test_classify_oversized_coil_read_medium():
    f = parse_frame(_frame(0x01, struct.pack(">HH", 0, 200)))
    _, sev, reasons = classify_event(f)
    assert sev == "medium"
    assert any("oversized" in r for r in reasons)


def test_classify_write_multiple_high():
    qty = 2
    regs = struct.pack(">HH", 1, 2)
    body = struct.pack(">HHB", 0, qty, len(regs)) + regs
    f = parse_frame(_frame(0x10, body))
    _, sev, _ = classify_event(f)
    assert sev == "high"


def test_classify_diagnostics_suspicious_high():
    f = parse_frame(_frame(0x08, struct.pack(">HH", 0, 0)))
    _, sev, reasons = classify_event(f)
    assert sev == "high"
    assert any("suspicious" in r for r in reasons)


def test_classify_report_server_id_high():
    f = parse_frame(_frame(0x11))
    _, sev, _ = classify_event(f)
    assert sev == "high"


def test_classify_encapsulated_transport_high():
    f = parse_frame(_frame(0x2B, bytes([0x0E, 0x01, 0x00])))
    _, sev, _ = classify_event(f)
    assert sev == "high"


def test_classify_unknown_medium():
    f = parse_frame(_frame(0x63))
    cat, sev, _ = classify_event(f)
    assert cat == "unknown" and sev == "medium"


def test_classify_mask_write_is_high():
    body = struct.pack(">HHH", 0, 1, 2)
    f = parse_frame(_frame(0x16, body))
    _, sev, _ = classify_event(f)
    assert sev == "high"


@pytest.mark.parametrize("fc", [0x01, 0x02, 0x03, 0x04])
def test_all_read_codes_classify_read(fc):
    f = parse_frame(_frame(fc, struct.pack(">HH", 0, 1)))
    cat, _, _ = classify_event(f)
    assert cat == "read"


@pytest.mark.parametrize("fc", [0x05, 0x06])
def test_simple_write_codes_classify_write(fc):
    f = parse_frame(_frame(fc, struct.pack(">HH", 0, 1)))
    cat, sev, _ = classify_event(f)
    assert cat == "write" and sev == "high"


# ---------------------------- response build ------------------------------ #

def test_build_response_read_coils_bytecount():
    f = parse_frame(_frame(0x01, struct.pack(">HH", 0, 16)))
    resp = build_response(f)
    assert resp[7] == 0x01
    assert resp[8] == 2  # 16 coils -> 2 bytes


def test_build_response_input_registers():
    f = parse_frame(_frame(0x04, struct.pack(">HH", 0, 5)))
    resp = build_response(f)
    assert resp[8] == 10  # 5 regs * 2 bytes


def test_build_response_write_single_echoes():
    f = parse_frame(_frame(0x06, struct.pack(">HH", 7, 0x1234)))
    resp = build_response(f)
    addr, val = struct.unpack(">HH", resp[8:12])
    assert addr == 7 and val == 0x1234


def test_build_response_write_multiple_echoes_addr_qty():
    regs = struct.pack(">HH", 1, 2)
    body = struct.pack(">HHB", 9, 2, len(regs)) + regs
    f = parse_frame(_frame(0x10, body))
    resp = build_response(f)
    addr, qty = struct.unpack(">HH", resp[8:12])
    assert addr == 9 and qty == 2


def test_build_response_preserves_transaction_and_unit():
    f = parse_frame(_frame(0x03, struct.pack(">HH", 0, 1), tid=0xABCD, uid=7))
    resp = build_response(f)
    tid, pid, _, uid = struct.unpack(">HHHB", resp[:7])
    assert tid == 0xABCD and pid == 0 and uid == 7


# ------------------------------- events ----------------------------------- #

def test_frame_to_event_has_fields():
    f = parse_frame(_frame(0x03, struct.pack(">HH", 0, 1)))
    ev = frame_to_event(f, src="1.2.3.4:5")
    assert ev["src"] == "1.2.3.4:5"
    assert ev["function_name"] == "read_holding_registers"
    assert "timestamp" in ev and ev["severity"] == "low"


def test_frame_to_event_explicit_ts():
    f = parse_frame(_frame(0x03, struct.pack(">HH", 0, 1)))
    ev = frame_to_event(f, ts="2026-01-01T00:00:00+00:00")
    assert ev["timestamp"] == "2026-01-01T00:00:00+00:00"


# ------------------------------ hexlog iter ------------------------------- #

def test_iter_skips_comments_and_blanks():
    lines = ["# comment", "", "  ", "10.0.0.1 | 000100000006010300000001"]
    out = list(iter_frames_from_hexlog(lines))
    assert len(out) == 1
    assert out[0][0] == "10.0.0.1"


def test_iter_tab_separator():
    out = list(iter_frames_from_hexlog(["src1\t000100000006010300000001"]))
    assert out[0][0] == "src1"


def test_iter_strips_0x_and_whitespace():
    out = list(iter_frames_from_hexlog(["0x00 0x01 00 00 00 06 01 03 00 00 00 01"]))
    assert len(out) == 1
    assert out[0][1][:2] == b"\x00\x01"


def test_iter_drops_invalid_hex():
    out = list(iter_frames_from_hexlog(["zzzz"]))
    assert out == []


def test_iter_odd_length_truncated():
    out = list(iter_frames_from_hexlog(["abc"]))  # 3 nibbles -> 1 byte
    assert out and len(out[0][1]) == 1


# ------------------------------ analyze ----------------------------------- #

def test_analyze_records_unparseable():
    events = analyze_capture(["bad | 00"])  # too short to be a frame
    assert events
    assert any("unparseable" in r for e in events for r in e["reasons"])


def test_analyze_empty_input():
    assert analyze_capture([]) == []


# ------------------------------ summary ----------------------------------- #

def test_summarize_counts():
    events = analyze_capture([
        "a | 000100000006010300000001",   # read
        "a | 000200000006010600010001",   # write -> high
    ])
    s = summarize_events(events)
    assert s["total"] == 2
    assert s["has_high"] is True
    assert s["by_category"].get("write") == 1


def test_summarize_recon_sweep_detection():
    lines = [f"scanner | 0001000000060103{i:04x}0001" for i in range(10)]
    events = analyze_capture(lines)
    s = summarize_events(events)
    assert "scanner" in s["recon_sources"]


def test_summarize_no_recon_for_few_addresses():
    events = analyze_capture(["a | 000100000006010300000001"])
    s = summarize_events(events)
    assert s["recon_sources"] == []


def test_summarize_distinct_sources():
    events = analyze_capture([
        "10.0.0.1 | 000100000006010300000001",
        "10.0.0.2 | 000100000006010300000001",
    ])
    s = summarize_events(events)
    assert set(s["distinct_sources"]) == {"10.0.0.1", "10.0.0.2"}


# ------------------------------- SARIF ------------------------------------ #

def test_sarif_empty_events():
    doc = to_sarif([])
    assert doc["runs"][0]["results"] == []


def test_sarif_dedups_rules_by_function():
    events = [
        {"severity": "high", "function_name": "write_single_coil", "reasons": ["w"]},
        {"severity": "high", "function_name": "write_single_coil", "reasons": ["w2"]},
    ]
    doc = to_sarif(events)
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert len([r for r in rules if r["id"] == "write_single_coil"]) == 1


def test_sarif_location_default_uri():
    doc = to_sarif([{"severity": "info", "function_name": "x", "reasons": []}])
    loc = doc["runs"][0]["results"][0]["locations"][0]
    assert loc["physicalLocation"]["artifactLocation"]["uri"] == "modbus://capture"
