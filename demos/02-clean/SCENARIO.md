# Demo 02 - Clean baseline (zero high findings)

A trusted-only capture: three read frames from internal HMI stations. Use
it as the negative control for your alerting rules and CI gate.

## Input

`capture.hexlog` - `read_holding_registers`, `read_input_registers`, and
`read_coils`, all from `10.0.4.x` at reasonable quantities.

## Run it

```bash
python -m modlure analyze demos/02-clean/capture.hexlog
echo "exit=$?"   # expect 0
```

## Expected result

Three `low` events, zero `high`. Exit status **0** - passes a
`--min-severity high` gate cleanly.
