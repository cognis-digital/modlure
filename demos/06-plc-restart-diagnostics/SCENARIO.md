# Demo 06 - PLC restart / counter-clear via diagnostics

## Where this came from

A honeypot emulating a field PLC. A hostile peer (`45.83.193.150`) uses
the Modbus **diagnostics** function (FC 0x08) sub-functions that, against
a real device, can disrupt operations or hide tracks: restart
communications, clear counters and the diagnostic register, and force
listen-only mode. A legitimate input-register read follows from the HMI.

## Input

`capture.hexlog`:

1. `diagnostics` sub-fn 0x0001 (restart communications option) -> HIGH
2. `diagnostics` sub-fn 0x000A (clear counters & diagnostic register) -> HIGH
3. `diagnostics` sub-fn 0x0004 (force listen-only mode) -> HIGH
4. `10.0.4.10` - `read_input_registers` (normal HMI) -> low

## Run it

```bash
python -m modpot analyze demos/06-plc-restart-diagnostics/capture.hexlog
```

## Expected result

Four events; three `high` diagnostics from `45.83.193.150`, one `low`.
Exit status **1**.

## How to act

Diagnostics sub-functions from an untrusted peer are an availability and
anti-forensics threat (force-listen-only silences the device; clear-
counters wipes evidence). Block the source and audit whether the real PLC
entered listen-only mode or lost its diagnostic counters.
