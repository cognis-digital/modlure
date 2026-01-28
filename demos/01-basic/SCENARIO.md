# Demo 01 - Basic Modbus honeypot capture analysis

This demo shows MODPOT decoding a small hex capture log of Modbus TCP
frames hitting a honeypot and classifying each one into a JSON threat
event with a severity.

## Input

`capture.hexlog` is a plain-text capture where each line is one Modbus
TCP frame in hex, optionally prefixed with the source IP and a `|`.
Comments (`#`) and blank lines are ignored. The frames represent:

1. `10.0.0.5` - a benign **read holding registers** (FC 0x03), qty 1 -> low
2. `45.13.9.21` - **write single register** 0x0001 = 0x00FF (FC 0x06) -> HIGH
3. `45.13.9.21` - **write multiple registers** at 0x0010 (FC 0x10) -> HIGH
4. `45.13.9.21` - **report server id** recon (FC 0x11) -> HIGH
5. `45.13.9.21` - an **oversized read** of 200 registers (FC 0x03) -> medium
6. `66.66.66.66` - a malformed / fuzzing frame (bad protocol id) -> medium

## Run it

```
python -m modpot analyze demos/01-basic/capture.hexlog
python -m modpot analyze demos/01-basic/capture.hexlog --format json
```

## Expected result

The table lists six events. Three are `high` severity (the two writes
and the report-server-id recon), one `medium` (oversized read), one
`medium` (malformed frame), and one `low` (the benign read).

Because at least one `high`-severity event is present, the process exits
with status **1** -- making `modpot analyze ... --format json` usable
directly as a CI / alerting gate against a captured honeypot log.
