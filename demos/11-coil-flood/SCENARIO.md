# Demo 11 - Coil flood (mass actuator flip)

## Where this came from

A honeypot fronting a discrete-output panel (breakers, relays, solenoids).
After a baseline coil read, a hostile peer (`77.91.78.55`) drives the
outputs en masse: force a whole block of coils ON, toggle one specific
coil, then force another block OFF - a crude but destructive
"flip everything" attack on physical actuators.

## Input

`capture.hexlog`:

1. `10.0.4.10` - `read_coils` qty 32 (baseline) -> low
2. `77.91.78.55` - `write_multiple_coils` 32 coils ON -> HIGH
3. `77.91.78.55` - `write_single_coil` ON -> HIGH
4. `77.91.78.55` - `write_multiple_coils` 16 coils OFF -> HIGH

## Run it

```bash
python -m modlure analyze demos/11-coil-flood/capture.hexlog
python -m modlure --format sarif analyze demos/11-coil-flood/capture.hexlog > coil-flood.sarif
```

## Expected result

Four events; three `high` coil writes from `77.91.78.55`, one `low`
baseline read. Exit status **1**.

## How to act

Block the source immediately and physically/operationally verify actuator
state - this attack pattern aims to trip breakers or cycle equipment.
Coil writes from any non-allowlisted source should page on-call.
