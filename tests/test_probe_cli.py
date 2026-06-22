"""CLI-level tests for `modpot probe` (active, gated) and `analyze --summary`.

Active-mode CLI tests run only against a localhost fixture or assert refusal
paths that never open a socket.
"""
import json

from modpot.cli import main
from .modbus_fixture import LocalModbusServer


def test_probe_without_authorized_refuses(capsys):
    rc = main(["probe", "--target", "127.0.0.1:502"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "AUTHORIZED USE ONLY" in err
    assert "OFF by default" in err


def test_probe_authorized_without_targets_errors(capsys):
    rc = main(["probe", "--authorized"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "no targets in scope" in err


def test_probe_banner_always_printed(capsys):
    main(["probe", "--target", "127.0.0.1:502"])
    err = capsys.readouterr().err
    assert "authorized-use" in err.lower() or "AUTHORIZED USE ONLY" in err


def test_probe_authorized_against_fixture_json(capsys):
    with LocalModbusServer() as srv:
        rc = main([
            "probe", "--authorized", "--target", srv.address,
            "--rate", "0", "--timeout", "2", "--format", "json",
        ])
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data[0]["reachable"] is True
    assert len(data[0]["responses"]) == 3


def test_probe_authorized_table_output(capsys):
    with LocalModbusServer() as srv:
        rc = main(["probe", "--authorized", "--target", srv.address,
                   "--rate", "0", "--timeout", "2"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "up" in out and srv.address in out


def test_probe_scope_file(tmp_path, capsys):
    with LocalModbusServer() as srv:
        sf = tmp_path / "scope.txt"
        sf.write_text(f"# authorized\n{srv.address}\n", encoding="utf-8")
        rc = main(["probe", "--authorized", "--scope-file", str(sf),
                   "--rate", "0", "--timeout", "2", "--format", "json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["reachable"] is True


def test_probe_unreachable_returns_one(capsys):
    rc = main(["probe", "--authorized", "--target", "127.0.0.1:1",
               "--rate", "0", "--timeout", "1", "--format", "json"])
    assert rc == 1
    data = json.loads(capsys.readouterr().out)
    assert data[0]["reachable"] is False


def test_probe_bad_scope_file(capsys):
    rc = main(["probe", "--authorized", "--scope-file", "/no/such/file.txt"])
    assert rc == 2
    assert "cannot read scope file" in capsys.readouterr().err


# ----------------------------- analyze --summary -------------------------- #

import os

DEMO = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "demos", "01-basic", "capture.hexlog"
)


def test_analyze_summary_json(capsys):
    rc = main(["analyze", DEMO, "--summary"])
    assert rc == 1  # demo has high events
    summary = json.loads(capsys.readouterr().out)
    assert summary["total"] == 6
    assert summary["has_high"] is True
    assert "by_severity" in summary and "by_function" in summary
