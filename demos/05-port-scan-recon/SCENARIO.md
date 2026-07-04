# Demo 05 - Internet-wide ICS scanner fingerprinting

## Where this came from

An internet-facing honeypot on TCP/502. A single host (`198.51.100.23`,
TEST-NET-2 documentation range) sweeps the service the way mass scanners
(Shodan/Censys/zmap-style) enumerate Modbus devices: identity queries,
device-identification reads, a diagnostics echo, a single register probe,
and a junk function code to see how the stack reacts.

## Input

`capture.hexlog`:

1. `report_server_id` (FC 0x11) -> HIGH (recon)
2. `encapsulated_interface_transport` / MEI Read Device ID (FC 0x2B) -> HIGH
3. `diagnostics` return-query-data echo (FC 0x08) -> HIGH
4. `read_holding_registers` qty 1 probe (FC 0x03) -> low
5. unknown function code `0x63` -> medium (scanner/fuzzing)

## Run it

```bash
python -m modlure analyze demos/05-port-scan-recon/capture.hexlog
python -m modlure --format sarif analyze demos/05-port-scan-recon/capture.hexlog > recon.sarif
```

## Expected result

Five events from one source: three `high` (the fingerprinting functions),
one `medium` (unknown FC), one `low`. Exit status **1**. The SARIF file
uploads cleanly to GitHub code-scanning / any SARIF viewer.

## How to act

This is pre-attack reconnaissance, not yet a control action. Treat the
source as an indicator: add it to a watchlist/blocklist, confirm the
device should not be internet-reachable at all, and expect follow-on
write attempts (see demo 04) if it stays exposed.
