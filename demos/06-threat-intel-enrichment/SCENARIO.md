# Demo 06 — threat-intel enrichment (offline / air-gap)

This capture contains three Modbus requests. One of them comes from
`203.0.113.66`, a source IP that appears in the bundled abuse.ch **Feodo
Tracker** C2 blocklist fixture (Emotet).

## Run it (air-gap, no network)

The repo ships a trimmed feed cache under `tests/fixtures/feeds_cache`. Point
MODPOT at it and analyze with enrichment:

```sh
COGNIS_FEEDS_CACHE=tests/fixtures/feeds_cache \
  python -m modpot analyze demos/06-threat-intel-enrichment/capture.hexlog \
  --enrich --offline --format json
```

The event from `203.0.113.66` is escalated to **high** severity with a
`threat_intel` block:

```json
{
  "src": "203.0.113.66:50000",
  "severity": "high",
  "reasons": ["THREAT-INTEL: source IP flagged by feodo-c2 (Emotet)", "..."],
  "threat_intel": {
    "ti_source": ["feodo-c2"],
    "ti_malware": ["Emotet"],
    "ti_confidence": 100
  }
}
```

## Live feeds

On a connected box, populate the real cache first, then drop `--offline`:

```sh
python -m modpot feeds update            # fetch feodo-c2 + threatfox
python -m modpot analyze ... --enrich    # scores against live data
```
