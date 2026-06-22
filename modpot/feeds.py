"""modpot.feeds — threat-intel enrichment for honeypot events.

MODPOT is a Modbus TCP honeypot: every attacker request becomes a JSON threat
event carrying the source IP (``src`` = ``"<ip>:<port>"``). This module turns
that raw ``src`` into actionable intelligence by scoring it against two
authoritative, keyless abuse.ch feeds from the bundled Cognis catalog:

  * ``feodo-c2``  — abuse.ch Feodo Tracker active botnet C2 IP blocklist
                    (Emotet / Dridex / QakBot / ...).
  * ``threatfox`` — abuse.ch ThreatFox recent IOCs (the ``ip:port`` IOCs are
                    extracted; malware family + confidence are preserved).

Edge / air-gap deployable: feed data is fetched once over HTTPS, cached to disk
by :mod:`modpot.datafeeds`, and re-served with ``offline=True`` so enrichment
keeps working on a disconnected OT / ICS network. See the README for the
snapshot (sneakernet) workflow.

Defensive / authorized-use only — this scores *inbound attacker* IPs hitting
your own honeypot against public C2/IOC blocklists. It does not target anyone.
"""
from __future__ import annotations

import json
from typing import Any, Iterable, Optional

from . import datafeeds

# The only feed ids this repo consumes from the catalog.
FEED_IDS = ("feodo-c2", "threatfox")


def _norm_ip(value: Optional[str]) -> str:
    """Strip a trailing ``:port`` and whitespace from an IP-ish string."""
    if not value:
        return ""
    value = value.strip()
    # IPv4[:port] only — IPv6 IOCs are not emitted by these feeds for this tool.
    if value.count(":") == 1 and "." in value:
        value = value.split(":", 1)[0]
    return value


def load_feodo_c2(*, offline: bool = False,
                  max_age_hours: float = 1.0) -> dict[str, dict]:
    """Return ``{ip -> record}`` of active botnet C2 IPs from Feodo Tracker."""
    raw = datafeeds.get("feodo-c2", offline=offline, max_age_hours=max_age_hours)
    out: dict[str, dict] = {}
    if isinstance(raw, list):
        for rec in raw:
            ip = _norm_ip(rec.get("ip_address"))
            if ip:
                out[ip] = rec
    return out


def load_threatfox_ips(*, offline: bool = False,
                       max_age_hours: float = 1.0) -> dict[str, dict]:
    """Return ``{ip -> record}`` for the ``ip:port`` IOCs in ThreatFox.

    ThreatFox's recent export is a dict keyed by IOC id, each value a list of
    one record. Only ``ioc_type == "ip:port"`` records are indexed by IP.
    """
    raw = datafeeds.get("threatfox", offline=offline, max_age_hours=max_age_hours)
    out: dict[str, dict] = {}
    if isinstance(raw, dict):
        groups: Iterable = raw.values()
    elif isinstance(raw, list):
        groups = ([r] for r in raw)
    else:
        groups = ()
    for recs in groups:
        for rec in recs:
            if rec.get("ioc_type") != "ip:port":
                continue
            ip = _norm_ip(rec.get("ioc_value"))
            if ip:
                out[ip] = rec
    return out


def score_ip(ip: str,
             feodo: dict[str, dict],
             threatfox: dict[str, dict]) -> Optional[dict]:
    """Return a threat-intel hit for ``ip`` or ``None`` if it is unknown.

    The returned dict is intentionally flat so it can be merged straight into a
    MODPOT event::

        {"ti_source": ["feodo-c2"], "ti_malware": ["Emotet"],
         "ti_confidence": 100, "ti_reasons": [...]}
    """
    ip = _norm_ip(ip)
    if not ip:
        return None
    sources: list[str] = []
    malware: list[str] = []
    reasons: list[str] = []
    confidence = 0

    if ip in feodo:
        rec = feodo[ip]
        sources.append("feodo-c2")
        fam = rec.get("malware")
        if fam:
            malware.append(fam)
        status = rec.get("status", "")
        reasons.append(
            f"source IP {ip} is a known {fam or 'botnet'} C2 "
            f"(abuse.ch Feodo Tracker, status={status or 'listed'})"
        )
        confidence = max(confidence, 100)

    if ip in threatfox:
        rec = threatfox[ip]
        sources.append("threatfox")
        fam = rec.get("malware_printable") or rec.get("malware")
        if fam and fam not in malware:
            malware.append(fam)
        conf = rec.get("confidence_level")
        if isinstance(conf, int):
            confidence = max(confidence, conf)
        reasons.append(
            f"source IP {ip} matches a {fam or 'malicious'} IOC "
            f"(abuse.ch ThreatFox, {rec.get('threat_type', 'ioc')})"
        )

    if not sources:
        return None
    return {
        "ti_source": sources,
        "ti_malware": malware,
        "ti_confidence": confidence,
        "ti_reasons": reasons,
    }


def enrich_event(event: dict,
                 feodo: dict[str, dict],
                 threatfox: dict[str, dict]) -> dict:
    """Enrich a single MODPOT event in place against the C2/IOC indices.

    A feed hit is a REAL change of posture, not cosmetic: it forces the event's
    severity to ``high`` (a known-C2 host touching an ICS device is critical),
    annotates the malware family / source / confidence, and prepends a reason.
    """
    src_ip = _norm_ip(event.get("src"))
    hit = score_ip(src_ip, feodo, threatfox)
    if not hit:
        return event
    event["threat_intel"] = hit
    event["severity"] = "high"  # known-bad source against an ICS honeypot
    fams = "/".join(hit["ti_malware"]) or "known-bad"
    srcs = "+".join(hit["ti_source"])
    reasons = event.setdefault("reasons", [])
    reasons.insert(0, f"THREAT-INTEL: source IP flagged by {srcs} ({fams})")
    return event


def enrich_events(events: list[dict], *, offline: bool = False,
                  max_age_hours: float = 1.0) -> list[dict]:
    """Enrich a batch of events; loads each feed once.

    With ``offline=True`` no network call is made — the feeds are served from
    the local cache populated by ``modpot feeds update`` / a snapshot import.
    """
    feodo = load_feodo_c2(offline=offline, max_age_hours=max_age_hours)
    threatfox = load_threatfox_ips(offline=offline, max_age_hours=max_age_hours)
    for ev in events:
        enrich_event(ev, feodo, threatfox)
    return events


# --------------------------------------------------------------------------- #
# CLI glue: `modpot feeds list|update|get <id> [--offline]`
# --------------------------------------------------------------------------- #
def cmd_feeds(args) -> int:
    """Handle the ``modpot feeds`` subcommand (restricted to FEED_IDS)."""
    catalog = datafeeds.load_catalog()
    allowed = {f["id"]: f for f in catalog.get("feeds", [])
               if f["id"] in FEED_IDS}

    action = getattr(args, "feeds_action", None)
    if action == "list":
        for fid in FEED_IDS:
            f = allowed.get(fid)
            if not f:
                continue
            age = datafeeds.cached_age_hours(fid)
            fresh = "uncached" if age is None else f"{age:.1f}h old"
            print(f"  {fid:12} {f.get('domain',''):13} [{fresh}]  {f['name']}")
        return 0

    if action == "update":
        rc = 0
        for fid in (args.ids or FEED_IDS):
            if fid not in allowed:
                print(f"  {fid}: not consumed by modpot "
                      f"(allowed: {', '.join(FEED_IDS)})", file=__import__('sys').stderr)
                rc = 2
                continue
            try:
                pth = datafeeds.update(fid, catalog=catalog)
                print(f"  updated {fid} -> {pth} ({pth.stat().st_size} bytes)")
            except (KeyError, ConnectionError) as exc:
                print(f"  {fid}: {exc}", file=__import__('sys').stderr)
                rc = 1
        return rc

    if action == "get":
        fid = args.id
        if fid not in allowed:
            print(f"error: {fid} is not consumed by modpot "
                  f"(allowed: {', '.join(FEED_IDS)})",
                  file=__import__('sys').stderr)
            return 2
        try:
            data = datafeeds.get(fid, offline=args.offline,
                                 max_age_hours=1.0, catalog=catalog)
        except (KeyError, FileNotFoundError, ConnectionError) as exc:
            print(f"error: {exc}", file=__import__('sys').stderr)
            return 1
        text = json.dumps(data, indent=2) if isinstance(data, (dict, list)) else str(data)
        print(text[:4000])
        return 0

    print("usage: modpot feeds {list|update|get} ...  "
          f"(feeds: {', '.join(FEED_IDS)})", file=__import__('sys').stderr)
    return 2


def add_feeds_subparser(sub) -> None:
    """Register `modpot feeds ...` on an argparse subparsers object."""
    fp = sub.add_parser(
        "feeds",
        help="manage the bundled threat-intel feeds (feodo-c2, threatfox)",
        description="List, update (fetch+cache), or print the abuse.ch C2/IOC "
        "feeds MODPOT consumes. Supports --offline (air-gap) re-serve.",
    )
    fsub = fp.add_subparsers(dest="feeds_action")
    fsub.add_parser("list", help="list consumed feeds + cache freshness")
    fu = fsub.add_parser("update", help="fetch + cache feed(s)")
    fu.add_argument("ids", nargs="*", help=f"feed ids (default: {', '.join(FEED_IDS)})")
    fg = fsub.add_parser("get", help="print a cached/fetched feed")
    fg.add_argument("id", help=f"one of: {', '.join(FEED_IDS)}")
    fg.add_argument("--offline", action="store_true",
                    help="serve from cache only; never touch the network")
    fp.set_defaults(func=cmd_feeds)
