# Demo 10 - Multi-unit address sweep behind a gateway

## Where this came from

Many Modbus deployments put several RTUs/PLCs behind a single TCP gateway,
addressed by **unit id**. A peer (`212.34.5.9`) walks unit ids 1..6 with
identical small reads to map which slave addresses are alive, then issues
one oversized read to bulk-grab a register range.

## Input

`capture.hexlog`:

1-6. `read_holding_registers` qty 1, unit ids 1..6 -> low (each)
7. `read_holding_registers` qty 200 (> 125) -> medium (oversized read)

## Run it

```bash
python -m modlure analyze demos/10-multi-unit-sweep/capture.hexlog
echo "exit=$?"   # expect 0 - reads only, no control writes
```

## Expected result

Seven events: six `low` plus one `medium` (the oversized read). Exit
status **0**, because enumeration is reads-only and `modlure` reserves
`high` for control/recon-function activity.

## How to act

This is a deliberately *sub-`high`* case: a CI gate on `high` will not
trip, but a SIEM rule keying on **one source touching many unit ids in a
short window** should. Use `--format json` and group events by `src` +
`unit_id` to catch the sweep pattern, then watch that source for the
follow-on writes seen in demos 04 and 09.
