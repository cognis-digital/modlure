"""Hardening tests: bad input, edge cases, and error-path coverage."""
from __future__ import annotations

import struct

from modpot import core
from modpot.cli import main


# ---------------------------------------------------------------------------
# build_response: oversized quantity must not crash (byte-count overflow fix)
# ---------------------------------------------------------------------------

def _build_raw(fc: int, addr: int = 0, qty: int = 1, tid: int = 1, uid: int = 1) -> bytes:
    pdu = bytes([fc]) + struct.pack(">HH", addr, qty)
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, uid) + pdu


def test_build_response_coils_oversized_qty_no_crash():
    """build_response must not raise ValueError when quantity > 2000 (coils)."""
    raw = _build_raw(0x01, qty=65535)
    frame = core.parse_frame(raw)
    resp = core.build_response(frame)
    # Response byte-count field (resp[8]) must fit in one byte.
    assert 0 <= resp[8] <= 255
    assert resp[7] == 0x01  # function code echoed


def test_build_response_registers_oversized_qty_no_crash():
    """build_response must not raise when quantity > 125 (holding registers)."""
    raw = _build_raw(0x03, qty=60000)
    frame = core.parse_frame(raw)
    resp = core.build_response(frame)
    assert 0 <= resp[8] <= 255
    assert resp[7] == 0x03


# ---------------------------------------------------------------------------
# analyze_capture: empty / blank / comment-only input
# ---------------------------------------------------------------------------

def test_analyze_capture_empty_list():
    events = core.analyze_capture([])
    assert events == []


def test_analyze_capture_blank_and_comment_lines():
    events = core.analyze_capture(["", "  ", "# this is a comment", "\t"])
    assert events == []


# ---------------------------------------------------------------------------
# CLI: missing file -> exit 2, clear stderr message
# ---------------------------------------------------------------------------

def test_cli_missing_file_exits_2(capsys):
    rc = main(["analyze", "/nonexistent/path/capture.hexlog"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "error:" in err.lower()
    assert "nonexistent" in err or "capture.hexlog" in err


# ---------------------------------------------------------------------------
# CLI: binary (non-UTF-8) file -> exit 2, not a traceback
# ---------------------------------------------------------------------------

def test_cli_binary_file_exits_2(capsys, tmp_path):
    bad = tmp_path / "binary.hexlog"
    bad.write_bytes(b"\xff\xfe\x00\x01\x80\x90")  # not valid UTF-8
    rc = main(["analyze", str(bad)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "error:" in err.lower()


# ---------------------------------------------------------------------------
# CLI: no subcommand -> exit 2 (help printed)
# ---------------------------------------------------------------------------

def test_cli_no_subcommand_exits_2(capsys):
    rc = main([])
    assert rc == 2


# ---------------------------------------------------------------------------
# CLI: out-of-range port -> exit 2
# ---------------------------------------------------------------------------

def test_cli_serve_port_zero_exits_2(capsys):
    rc = main(["serve", "--port", "0"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "port" in err.lower()
    assert "range" in err.lower() or "0" in err


def test_cli_serve_port_too_large_exits_2(capsys):
    rc = main(["serve", "--port", "99999"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "port" in err.lower()


# ---------------------------------------------------------------------------
# mcp_server: module imports without errors (no dependency on mcp package)
# ---------------------------------------------------------------------------

def test_mcp_server_importable():
    """mcp_server must import cleanly even when the 'mcp' extra is absent."""
    import importlib
    mod = importlib.import_module("modpot.mcp_server")
    assert callable(mod.serve)
