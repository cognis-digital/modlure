"""Command-line interface for MODLURE.

Subcommands
-----------
  analyze   Decode + classify Modbus TCP frames from a hex capture log
            and emit threat events (table or JSON).
  serve     Run a live Modbus TCP honeypot listener that logs every
            request as a JSON threat event.

Examples
--------
  # Analyze a captured hex log and pretty-print a table
  modlure analyze demos/01-basic/capture.hexlog

  # Emit JSON for piping into a SIEM / CI gate
  modlure analyze demos/01-basic/capture.hexlog --format json

  # Read frames from stdin
  cat capture.hexlog | modlure analyze -

  # Run a real honeypot on port 5020 (no root needed)
  modlure serve --host 0.0.0.0 --port 5020

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
from . import probe as _probe

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
    high = _has_high(events)
    if getattr(args, "summary", False):
        from .core import summarize_events
        print(json.dumps(summarize_events(events), indent=2))
        return 1 if high else 0
    # A --format given after the subcommand wins over the global one.
    fmt = getattr(args, "format_sub", None) or args.format
    _emit(events, fmt)
    return 1 if high else 0


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
        f"[modlure] honeypot listening on {args.host}:{args.port} "
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
        print("\n[modlure] stopped", file=sys.stderr)
    finally:
        srv.close()
    return 1 if saw_high else 0


def _cmd_probe(args: argparse.Namespace) -> int:
    """ACTIVE mode — authorization-gated, scope-enforced, rate-limited.

    Default OFF: without --authorized this refuses with exit code 2 and emits
    the authorized-use banner. Targets must be inside the allowlist built from
    --target / --scope-file; out-of-scope targets are skipped, never probed.
    """
    print(_probe.AUTHORIZED_USE_BANNER, file=sys.stderr)
    if not args.authorized:
        print(
            "error: active probing is OFF by default. Re-run with --authorized "
            "AND a target scope (--target/--scope-file) to confirm you are "
            "authorized to test these devices.",
            file=sys.stderr,
        )
        return 2

    specs: list[str] = list(args.target or [])
    if args.scope_file:
        try:
            scope = _probe.Scope.from_file(args.scope_file)
            specs.extend(t.key() for t in scope.targets)
        except OSError as exc:
            print(f"error: cannot read scope file {args.scope_file}: {exc}",
                  file=sys.stderr)
            return 2
    if not specs:
        print("error: no targets in scope. Provide --target HOST[:PORT] "
              "(repeatable) and/or --scope-file FILE.", file=sys.stderr)
        return 2

    scope = _probe.Scope.from_specs(specs)
    p = _probe.Probe(
        scope,
        authorized=True,
        rate=args.rate,
        timeout=args.timeout,
        unit_id=args.unit_id,
    )
    # The targets to probe are exactly the authorized scope.
    results = p.run(scope.targets, addr=args.address, qty=args.quantity)
    fmt = getattr(args, "format_sub", None) or args.format
    if fmt in ("json", "sarif"):
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            if r.get("skipped"):
                print(f"SKIP  {r['target']}  (out of scope)")
                continue
            status = "up" if r.get("reachable") else "down"
            extra = r.get("error", "")
            nresp = len(r.get("responses", []))
            print(f"{status:<5} {r['target']:<22} responses={nresp} {extra}")
    # Non-zero if any authorized target was unreachable (operational signal).
    probed = [r for r in results if not r.get("skipped")]
    if probed and all(not r.get("reachable") for r in probed):
        return 1
    return 0


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
        description="MODLURE - a standard-library Modbus TCP honeypot that "
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
    #   modlure analyze capture.hexlog --format json
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
    a.add_argument(
        "--summary",
        action="store_true",
        help="print an aggregated passive scan summary (counts by severity/"
        "category/function, distinct sources, recon-sweep heuristic) as JSON",
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

    pr = sub.add_parser(
        "probe",
        help="ACTIVE: read-only probe of an AUTHORIZED, in-scope device "
        "(OFF by default; requires --authorized + a target scope)",
        description="AUTHORIZED-USE-ONLY active Modbus client. Off by default. "
        "Issues only read/identity requests to devices you explicitly list in "
        "scope; out-of-scope targets are refused. Scope-enforced and "
        "rate-limited. Never sends writes/control codes.",
    )
    pr.add_argument(
        "--authorized",
        action="store_true",
        help="REQUIRED to enable active probing: confirms you are authorized "
        "to test the in-scope devices (authorized-use only)",
    )
    pr.add_argument(
        "--target",
        action="append",
        metavar="HOST[:PORT]",
        help="add a target to the authorized allowlist (repeatable; "
        "default port 502)",
    )
    pr.add_argument(
        "--scope-file",
        default=None,
        help="file of authorized targets, one HOST[:PORT] per line "
        "(# comments allowed)",
    )
    pr.add_argument(
        "--rate",
        type=float,
        default=1.0,
        help="minimum seconds between requests (rate limit; default 1.0)",
    )
    pr.add_argument("--timeout", type=float, default=3.0,
                    help="per-connection socket timeout seconds (default 3.0)")
    pr.add_argument("--unit-id", type=int, default=1,
                    help="Modbus unit/slave id to query (default 1)")
    pr.add_argument("--address", type=int, default=0,
                    help="holding-register start address to read (default 0)")
    pr.add_argument("--quantity", type=int, default=1,
                    help="number of holding registers to read, 1..125 "
                    "(default 1)")
    pr.add_argument("--format", choices=["table", "json", "sarif"],
                    default=None, dest="format_sub", help="output format")
    pr.set_defaults(func=_cmd_probe)

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
