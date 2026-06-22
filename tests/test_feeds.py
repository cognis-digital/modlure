"""Offline tests for MODPOT's threat-intel feed enrichment.

These tests NEVER touch the network. They point ``COGNIS_FEEDS_CACHE`` at the
trimmed fixture cache under ``tests/fixtures/feeds_cache`` and load every feed
with ``offline=True``, so the suite is green on an air-gapped box.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

FIXTURE_CACHE = Path(__file__).parent / "fixtures" / "feeds_cache"

# Known IPs injected into the fixtures (see tests/fixtures/feeds_cache/*.data)
FEODO_IP = "203.0.113.66"          # Emotet C2 in the Feodo fixture
THREATFOX_IP = "198.51.100.23"     # Cobalt Strike ip:port IOC in ThreatFox
CLEAN_IP = "10.0.0.5"              # not in any feed


@pytest.fixture(autouse=True)
def _offline_cache(monkeypatch):
    """Force all feed access at the fixture cache, offline."""
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(FIXTURE_CACHE))
    yield


def _reload_datafeeds():
    # datafeeds reads the env at call time, so no reload needed; just import.
    from modpot import datafeeds
    return datafeeds


def test_fixture_cache_present():
    assert (FIXTURE_CACHE / "feodo-c2.data").exists()
    assert (FIXTURE_CACHE / "threatfox.data").exists()


def test_load_feodo_offline_indexes_by_ip():
    from modpot import feeds
    idx = feeds.load_feodo_c2(offline=True)
    assert FEODO_IP in idx
    assert idx[FEODO_IP]["malware"] == "Emotet"


def test_load_threatfox_offline_extracts_ip_iocs():
    from modpot import feeds
    idx = feeds.load_threatfox_ips(offline=True)
    assert THREATFOX_IP in idx
    assert idx[THREATFOX_IP]["malware_printable"] == "Cobalt Strike"


def test_offline_get_never_hits_network(monkeypatch):
    """If anything calls fetch() while offline, the test must fail."""
    df = _reload_datafeeds()

    def _boom(*a, **k):  # pragma: no cover - only fires on a bug
        raise AssertionError("network fetch attempted during offline test")

    monkeypatch.setattr(df, "fetch", _boom)
    from modpot import feeds
    feeds.load_feodo_c2(offline=True)
    feeds.load_threatfox_ips(offline=True)


def test_score_ip_feodo_hit():
    from modpot import feeds
    feodo = feeds.load_feodo_c2(offline=True)
    tf = feeds.load_threatfox_ips(offline=True)
    hit = feeds.score_ip(FEODO_IP, feodo, tf)
    assert hit is not None
    assert "feodo-c2" in hit["ti_source"]
    assert "Emotet" in hit["ti_malware"]
    assert hit["ti_confidence"] == 100


def test_score_ip_threatfox_hit_with_port_suffix():
    from modpot import feeds
    feodo = feeds.load_feodo_c2(offline=True)
    tf = feeds.load_threatfox_ips(offline=True)
    # source comes in as ip:port from a honeypot connection
    hit = feeds.score_ip(f"{THREATFOX_IP}:55123", feodo, tf)
    assert hit is not None
    assert "threatfox" in hit["ti_source"]
    assert "Cobalt Strike" in hit["ti_malware"]


def test_score_ip_clean_returns_none():
    from modpot import feeds
    feodo = feeds.load_feodo_c2(offline=True)
    tf = feeds.load_threatfox_ips(offline=True)
    assert feeds.score_ip(CLEAN_IP, feodo, tf) is None


def test_enrich_event_escalates_to_high():
    from modpot import feeds
    feodo = feeds.load_feodo_c2(offline=True)
    tf = feeds.load_threatfox_ips(offline=True)
    ev = {"src": f"{FEODO_IP}:40000", "severity": "low",
          "category": "read", "reasons": ["benign register read"]}
    out = feeds.enrich_event(ev, feodo, tf)
    assert out["severity"] == "high"
    assert "threat_intel" in out
    assert out["reasons"][0].startswith("THREAT-INTEL")


def test_enrich_event_clean_unchanged():
    from modpot import feeds
    feodo = feeds.load_feodo_c2(offline=True)
    tf = feeds.load_threatfox_ips(offline=True)
    ev = {"src": f"{CLEAN_IP}:40000", "severity": "low",
          "category": "read", "reasons": ["benign register read"]}
    out = feeds.enrich_event(ev, feodo, tf)
    assert out["severity"] == "low"
    assert "threat_intel" not in out


def test_enrich_events_batch_offline():
    from modpot import feeds
    events = [
        {"src": f"{FEODO_IP}:1", "severity": "low", "reasons": []},
        {"src": f"{THREATFOX_IP}:2", "severity": "low", "reasons": []},
        {"src": f"{CLEAN_IP}:3", "severity": "low", "reasons": []},
    ]
    out = feeds.enrich_events(events, offline=True)
    assert out[0]["severity"] == "high"
    assert out[1]["severity"] == "high"
    assert out[2]["severity"] == "low"


def test_feed_ids_restricted_to_catalog():
    from modpot import feeds, datafeeds
    catalog_ids = {f["id"] for f in datafeeds.load_catalog().get("feeds", [])}
    for fid in feeds.FEED_IDS:
        assert fid in catalog_ids, f"{fid} not in bundled catalog"
