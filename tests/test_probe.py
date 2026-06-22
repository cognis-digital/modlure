"""Tests for the AUTHORIZATION-GATED active probe.

All network activity targets ONLY a localhost fixture server or mocks — never
a real external host. Tests assert the gating itself: off-by-default,
scope-enforcement, read-only, and rate-limiting.
"""
import struct

import pytest

from modpot import probe
from modpot.probe import (
    Probe,
    Scope,
    Target,
    ScopeError,
    UnauthorizedError,
    UnsafeFunctionError,
    build_request,
    interpret_response,
)
from .modbus_fixture import LocalModbusServer


# ----------------------------- Target parsing ---------------------------- #

def test_target_parse_host_only():
    t = Target.parse("10.0.0.5")
    assert t.host == "10.0.0.5" and t.port == 502


def test_target_parse_host_port():
    t = Target.parse("127.0.0.1:5020")
    assert t.host == "127.0.0.1" and t.port == 5020


def test_target_parse_ipv6_bracketed():
    t = Target.parse("[::1]:502")
    assert t.host == "::1" and t.port == 502


def test_target_parse_empty_raises():
    with pytest.raises(ValueError):
        Target.parse("   ")


def test_target_key():
    assert Target("1.2.3.4", 502).key() == "1.2.3.4:502"


# ------------------------------ Scope logic ------------------------------- #

def test_scope_allows_exact_match():
    s = Scope.from_specs(["10.0.0.5:502"])
    assert s.allows(Target("10.0.0.5", 502))


def test_scope_denies_different_port():
    s = Scope.from_specs(["10.0.0.5:502"])
    assert not s.allows(Target("10.0.0.5", 5020))


def test_scope_denies_unlisted_host():
    s = Scope.from_specs(["10.0.0.5"])
    assert not s.allows(Target("10.0.0.6"))


def test_scope_check_raises_for_out_of_scope():
    s = Scope.from_specs(["10.0.0.5"])
    with pytest.raises(ScopeError):
        s.check(Target("8.8.8.8"))


def test_scope_from_file(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("# authorized devices\n10.0.0.5:502\n10.0.0.6\n\n", encoding="utf-8")
    s = Scope.from_file(str(f))
    assert s.allows(Target("10.0.0.5", 502))
    assert s.allows(Target("10.0.0.6", 502))


def test_scope_from_specs_ignores_blanks():
    s = Scope.from_specs(["", "  ", "10.0.0.5"])
    assert len(s.targets) == 1


# --------------------------- Authorization gate --------------------------- #

def test_probe_off_by_default_run_refuses():
    p = Probe(Scope.from_specs(["127.0.0.1:502"]))  # authorized defaults False
    assert p.authorized is False
    with pytest.raises(UnauthorizedError):
        p.run(["127.0.0.1:502"])


def test_probe_off_by_default_probe_target_refuses():
    p = Probe(Scope.from_specs(["127.0.0.1:502"]))
    with pytest.raises(UnauthorizedError):
        p.probe_target(Target("127.0.0.1", 502))


def test_authorized_out_of_scope_target_is_skipped_not_probed():
    called = {"n": 0}

    def _connect(host, port, timeout):
        called["n"] += 1
        raise AssertionError("must not connect to an out-of-scope target")

    p = Probe(Scope.from_specs(["127.0.0.1:502"]), authorized=True, rate=0)
    results = p.run(["8.8.8.8:502"], _connect=_connect)
    assert results[0]["skipped"] is True
    assert called["n"] == 0


# ---------------------------- Read-only safety ---------------------------- #

@pytest.mark.parametrize("fc", sorted(probe.FORBIDDEN_ACTIVE_CODES))
def test_build_request_refuses_write_codes(fc):
    with pytest.raises(UnsafeFunctionError):
        build_request(1, 1, fc, b"\x00\x00\x00\x00")


@pytest.mark.parametrize("fc", sorted(probe.READONLY_PROBE_CODES))
def test_build_request_allows_readonly_codes(fc):
    raw = build_request(1, 1, fc)
    assert raw[7] == fc


def test_readonly_and_forbidden_sets_are_disjoint():
    assert not (probe.READONLY_PROBE_CODES & probe.FORBIDDEN_ACTIVE_CODES)


# ------------------------------ Rate limiting ----------------------------- #

def test_rate_limit_sleeps_between_requests():
    sleeps = []
    clock = {"t": 0.0}

    def fake_clock():
        return clock["t"]

    def fake_sleep(s):
        sleeps.append(s)
        clock["t"] += s

    p = Probe(Scope.from_specs(["127.0.0.1:502"]), authorized=True,
              rate=2.0, _clock=fake_clock, _sleep=fake_sleep)
    p._throttle()  # first call: last_send was 0, now-0 = 0 -> waits 2.0
    p._throttle()  # immediately after -> waits ~2.0 again
    assert len(sleeps) >= 1
    assert all(s <= 2.0 + 1e-9 for s in sleeps)


def test_rate_zero_does_not_sleep():
    called = []
    p = Probe(Scope.from_specs(["x"]), authorized=True, rate=0,
              _sleep=lambda s: called.append(s))
    p._throttle()
    assert called == []


# ------------------------ Response interpretation ------------------------- #

def test_interpret_read_response():
    pdu = bytes([0x03, 0x02, 0x00, 0x2A])
    raw = struct.pack(">HHHB", 1, 0, len(pdu) + 1, 1) + pdu
    info = interpret_response(raw)
    assert info["ok"] is True
    assert info["function_name"] == "read_holding_registers"
    assert info["byte_count"] == 2
    assert info["data_hex"] == "002a"


def test_interpret_exception_response():
    pdu = bytes([0x83, 0x02])  # 0x03 | 0x80, illegal data address
    raw = struct.pack(">HHHB", 1, 0, len(pdu) + 1, 1) + pdu
    info = interpret_response(raw)
    assert info["ok"] is False
    assert info["exception_code"] == 0x02


def test_interpret_short_response():
    info = interpret_response(b"\x00\x01")
    assert info["ok"] is False


# ------------------------ End-to-end vs localhost ------------------------- #

def test_probe_against_localhost_fixture():
    with LocalModbusServer() as srv:
        scope = Scope.from_specs([srv.address])
        p = Probe(scope, authorized=True, rate=0, timeout=2.0)
        results = p.run(scope.targets, qty=2)
    assert len(results) == 1
    r = results[0]
    assert r["reachable"] is True
    assert len(r["responses"]) == 3
    # the fixture only ever saw read/identity codes
    assert set(srv.requests).issubset(probe.READONLY_PROBE_CODES)
    # the holding-register read came back ok
    first = r["responses"][0]
    assert first["query"] == "read_holding_registers"
    assert first["ok"] is True


def test_probe_unreachable_target_is_in_scope_but_down():
    # An in-scope localhost port nobody is listening on -> reachable False.
    scope = Scope.from_specs(["127.0.0.1:1"])  # port 1, refused
    p = Probe(scope, authorized=True, rate=0, timeout=1.0)
    results = p.run(scope.targets)
    assert results[0]["reachable"] is False
    assert "error" in results[0]


def test_probe_target_rejects_bad_quantity():
    p = Probe(Scope.from_specs(["127.0.0.1:502"]), authorized=True, rate=0)
    with pytest.raises(ValueError):
        p.probe_target(Target("127.0.0.1", 502), qty=999)


def test_is_loopback():
    assert probe.is_loopback("127.0.0.1")
    assert probe.is_loopback("::1")
    assert probe.is_loopback("localhost")
    assert not probe.is_loopback("8.8.8.8")
