# Demo 04 - Water-treatment chemical dosing tamper

## Where this came from

A small municipal water utility exposed a Modbus PLC on TCP/502 through a
misconfigured cellular gateway. `modlure` was deployed as a decoy in front
of the real control LAN. Overnight, a peer from a Tor exit range
(`185.220.101.7`) connected after the normal HMI (`10.0.4.10`) baseline
poll and began issuing control writes against the chlorine dosing loop.

## Input

`capture.hexlog` - one Modbus TCP frame per line, `<src> | <hex>`:

1. `10.0.4.10` - HMI reads holding registers (baseline poll) -> low
2. `185.220.101.7` - `report_server_id` device fingerprint -> HIGH (recon)
3. `185.220.101.7` - `write_single_coil` opens a dosing valve -> HIGH
4. `185.220.101.7` - `write_single_register` raises a dose setpoint -> HIGH
5. `185.220.101.7` - `write_multiple_coils` flips several pumps -> HIGH

## Run it

```bash
python -m modlure analyze demos/04-water-treatment-tamper/capture.hexlog
python -m modlure --format json analyze demos/04-water-treatment-tamper/capture.hexlog --min-severity high
```

## Expected result

Five events; four `high` (one recon + three control writes) from a single
hostile source, one `low` (the HMI). Exit status **1**.

## How to act

Block `185.220.101.7` at the gateway, pull the device off the public
internet behind a VPN/segmented firewall, and verify the real PLC's dosing
registers/coils against the last known-good values - the writes here would
attempt to over-chlorinate the supply.
