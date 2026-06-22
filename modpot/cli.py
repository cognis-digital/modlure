"""Command-line interface for MODPOT.

Subcommands
-----------
  analyze   Decode + classify Modbus TCP frames from a hex capture log
            and emit threat events (table or JSON).
  serve     Run a live Modbus TCP honeypot listener that logs every
            request as a JSON threat event.

Examples
--------
  # Analyze a captured hex log and pretty-print a table
  modpot analyze demos/01-basic/capture.hexlog

  # Emit JSON for piping into a SIEM / CI gate
  modpot analyze demos/01-basic/capture.hexlog --format json

  # Read frames from stdin
  cat capture.hexlog | modpot analyze -

  # Run a real honeypot on port 5020 (no root needed)
  modpot serve --host 0.0.0.0 --port 5020

Exit codes
----------
  0  no high-severity findings
  1  at least one high-severity event (write/control/recon) -- use as a
     CI / alerting gate
  2  usage error
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
from datetime import datetime, timezone
from typing import Sequence

from .core import (
    TOOL_NAME,
    TOOL_VERSION,
    analyze_capture,
    build_response,
    frame_to_event,
    parse_frame,
    to_sarif,
    ParseError,
)
from .feeds import add_feeds_subparser, enrich_events

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}


def _read_lines(path: str) -> list[str]:
    if path == "-":
        return sys.stdin.read().splitlines()
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read().splitlines()


def _print_table(events: list[dict]) -> None:
    if not events:
        print("no frames found")
        return
    header = f"{'SEV':<7} {'SRC':<16} {'FUNCTION':<26} {'ADDR':>6} {'QTY':>5}  REASONS"
    print(header)
    print("-" * len(header))
    for e in events:
        addr = "" if e["address"] is None else str(e["address"])
        qty = "" if e["quantity"] is None else str(e["quantity"])
        fn = e["function_name"] or "(unparsed)"
        reasons = "; ".join(e["reasons"])
        print(
            f"{e['severity']:<7} {(e['src'] or '-'):<16} {fn:<26} "
            f"{addr:>6} {qty:>5}  {reasons}"
        )
    counts: dict[str, int] = {}
    for e in events:
        counts[e["severity"]] = counts.get(e["severity"], 0) + 1
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    print("-" * len(header))
    print(f"total={len(events)}  {summary}")


def _emit(events: list[dict], fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(events, indent=2))
    elif fmt == "sarif":
        print(json.dumps(to_sarif(events), indent=2))
    else:
        _print_table(events)


def _has_high(events: list[dict]) -> bool:
    return any(e.get("severity") == "high" for e in events)


def _cmd_analyze(args: argparse.Namespace) -> int:
    try:
        lines = _read_lines(args.path)
    except OSError as exc:
        print(f"error: cannot read {args.path}: {exc}", file=sys.stderr)
        return 2
    events = analyze_capture(lines)
    if getattr(args, "enrich", False):
        try:
            enrich_events(events, offline=getattr(args, "offline", False))
        except (FileNotFoundError, ConnectionError) as exc:
            print(f"warning: threat-intel enrichment skipped: {exc}",
                  file=sys.stderr)
    if args.min_severity:
        floor = _SEV_RANK.get(args.min_severity, 0)
        events = [e for e in events if _SEV_RANK.get(e["severity"], 0) >= floor]
    # A --format given after the subcommand wins over the global one.
    fmt = getattr(args, "format_sub", None) or args.format
    _emit(events, fmt)
    return 1 if _has_high(events) else 0


def _cmd_serve(args: argparse.Namespace) -> int:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((args.host, args.port))
    except OSError as exc:
        print(f"error: cannot bind {args.host}:{args.port}: {exc}", file=sys.stderr)
        return 2
    srv.listen(8)
    print(
        f"[modpot] honeypot listening on {args.host}:{args.port} "
        f"(Ctrl-C to stop)",
        file=sys.stderr,
    )
    saw_high = False
    try:
        while True:
            conn, addr = srv.accept()
            src = f"{addr[0]}:{addr[1]}"
            with conn:
                while True:
                    head = _recv_exact(conn, 7)
                    if head is None:
                        break
                    import struct

                    _, _, length, _ = struct.unpack(">HHHB", head)
                    rest = _recv_exact(conn, max(length - 1, 0))
                    if rest is None:
                        break
                    raw = head + rest
                    try:
                        frame = parse_frame(raw)
                        event = frame_to_event(frame, src=src)
                        conn.sendall(build_response(frame))
                    except ParseError as exc:
                        event = {
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "src": src,
                            "category": "unknown",
                            "severity": "medium",
                            "reasons": [f"unparseable frame: {exc}"],
                            "raw_hex": raw.hex(),
                        }
                    if event.get("severity") == "high":
                        saw_high = True
                    print(json.dumps(event), flush=True)
    except KeyboardInterrupt:
        print("\n[modpot] stopped", file=sys.stderr)
    finally:
        srv.close()
    return 1 if saw_high else 0


def _recv_exact(conn: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="MODPOT - a standard-library Modbus TCP honeypot that "
        "logs attacker register reads/writes as JSON.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}"
    )
    p.add_argument(
        "--format",
        choices=["table", "json", "sarif"],
        default="table",
        help="output format (default: table). Accepted before OR after the "
        "subcommand.",
    )
    sub = p.add_subparsers(dest="command")

    a = sub.add_parser(
        "analyze",
        help="decode + classify Modbus frames from a hex capture log",
        description="Decode and classify Modbus TCP frames from a hex "
        "capture log into JSON threat events.",
    )
    # Allow --format after the subcommand too (natural position), e.g.
    #   modpot analyze capture.hexlog --format json
    a.add_argument(
        "--format",
        choices=["table", "json", "sarif"],
        default=None,
        dest="format_sub",
        help="output format (default: table)",
    )
    a.add_argument(
        "path",
        help="hex capture log file, or '-' for stdin",
    )
    a.add_argument(
        "--min-severity",
        choices=["info", "low", "medium", "high"],
        default=None,
        help="only show events at or above this severity",
    )
    a.add_argument(
        "--enrich",
        action="store_true",
        help="score each source IP against the bundled abuse.ch Feodo C2 + "
        "ThreatFox IOC feeds; a hit forces the event to high severity",
    )
    a.add_argument(
        "--offline",
        action="store_true",
        help="with --enrich, use only the on-disk feed cache (air-gap mode)",
    )
    a.set_defaults(func=_cmd_analyze)

    s = sub.add_parser(
        "serve",
        help="run a live Modbus TCP honeypot listener",
        description="Run a live Modbus TCP honeypot; every request is logged "
        "as a JSON threat event on stdout.",
    )
    s.add_argument("--host", default="127.0.0.1", help="bind host")
    s.add_argument("--port", type=int, default=5020, help="bind port (default 5020)")
    s.set_defaults(func=_cmd_serve)

    add_feeds_subparser(sub)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
