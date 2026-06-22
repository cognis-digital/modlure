# Demo 09 - Turbine overspeed-trip setpoint override

## Where this came from

A honeypot mirroring a generation-asset controller. A peer
(`91.205.230.12`) reads the safety setpoint block, then uses a
**mask-write** plus targeted register writes to raise the overspeed-trip
limit and zero out an interlock - the kind of safety-system tampering that
matters far more than a data read.

## Input

`capture.hexlog`:

1. `10.0.4.10` - `read_holding_registers` of the setpoint block -> low
2. `91.205.230.12` - `mask_write_register` on the trip register -> HIGH
   (both a write *and* a suspicious function)
3. `91.205.230.12` - `write_single_register` raises the overspeed limit -> HIGH
4. `91.205.230.12` - `write_multiple_registers` disables the interlock -> HIGH

## Run it

```bash
python -m modpot analyze demos/09-setpoint-override/capture.hexlog
python -m modpot --format json analyze demos/09-setpoint-override/capture.hexlog --min-severity high | jq '.[].reasons'
```

## Expected result

Four events; three `high` writes from the hostile source, one `low` poll.
Exit status **1**. Note the mask-write carries two reasons (write + recon/
tamper) because `mask_write_register` is also in the suspicious-code set.

## How to act

Treat as a safety-instrumented-system incident. Isolate the controller,
restore the trip/interlock setpoints from a verified backup, and confirm
no physical asset ran outside its protection envelope while the values
were altered.
