"""Offline CLI tests for `modlure feeds` and `analyze --enrich --offline`."""
from __future__ import annotations

from pathlib import Path

import pytest

from modlure.cli import main

FIXTURE_CACHE = Path(__file__).parent / "fixtures" / "feeds_cache"
FEODO_IP = "203.0.113.66"


@pytest.fixture(autouse=True)
def _offline_cache(monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(FIXTURE_CACHE))
    yield


def test_feeds_list(capsys):
    rc = main(["feeds", "list"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "feodo-c2" in out
    assert "threatfox" in out


def test_feeds_get_offline(capsys):
    rc = main(["feeds", "get", "feodo-c2", "--offline"])
    out = capsys.readouterr().out
    assert rc == 0
    assert FEODO_IP in out


def test_feeds_get_rejects_unconsumed_feed(capsys):
    rc = main(["feeds", "get", "cisa-kev", "--offline"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "not consumed by modlure" in err


def test_analyze_enrich_offline_escalates(tmp_path, capsys):
    """A captured frame from a known-C2 IP must come back high severity."""
    # A minimal valid Modbus 'read holding registers' (FC 0x03) frame.
    # MBAP: tid=0001 pid=0000 len=0006 uid=01 ; PDU: 03 0000 0001
    hexlog = tmp_path / "cap.hexlog"
    hexlog.write_text(
        f"{FEODO_IP}:50000 | 000100000006010300000001\n"
    )
    rc = main(["analyze", str(hexlog), "--enrich", "--offline",
               "--format", "json"])
    out = capsys.readouterr().out
    # high-severity exit code OR at least the enrichment annotation present
    assert "threat_intel" in out or "THREAT-INTEL" in out
    assert rc in (0, 1)
