# Demo 03 - Mixed real-world traffic

A realistic day on an exposed honeypot: mostly benign HMI polling with one
hostile source mixed in (recon + a control write) and one oversized read.

## Input

`capture.hexlog`:

1. `10.0.4.10` - `read_holding_registers` qty 10 -> low
2. `10.0.4.10` - `read_input_registers` qty 6 -> low
3. `45.13.9.21` - `report_server_id` fingerprint -> HIGH (recon)
4. `45.13.9.21` - `write_single_register` -> HIGH
5. `10.0.4.11` - oversized read qty 200 -> medium

## Run it

```bash
python -m modlure analyze demos/03-mixed/capture.hexlog
python -m modlure --format json analyze demos/03-mixed/capture.hexlog --min-severity medium
```

## Expected result

Five events: two `high` (both from `45.13.9.21`), two `low`, one `medium`.
Exit status **1**.
