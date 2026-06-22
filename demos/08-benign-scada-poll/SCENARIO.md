# Demo 08 - Benign SCADA polling (clean baseline)

## Where this came from

The control LAN's own HMI/SCADA stations (`10.0.4.10`, `10.0.4.11`)
cyclically polling a PLC: holding registers, input registers, coils, and
discrete inputs. This is the "what normal looks like" baseline so you can
recognize the hostile demos by contrast.

## Input

`capture.hexlog` - five read-only frames from trusted internal sources,
all reasonable quantities (<= 125):

1. `read_holding_registers` qty 10 -> low
2. `read_input_registers` qty 8 -> low
3. `read_coils` qty 16 -> low
4. `read_discrete_inputs` qty 16 -> low
5. `read_holding_registers` qty 4 -> low

## Run it

```bash
python -m modpot analyze demos/08-benign-scada-poll/capture.hexlog
echo "exit=$?"   # expect 0
```

## Expected result

Five `low` events, zero `high`. Exit status **0** - so this capture passes
a `--min-severity high` CI gate cleanly. Use it to confirm your alerting
rule does not false-positive on routine polling.

## How to act

Nothing. This is the negative control. If a capture that *looks* like this
ever produces a `high`, investigate the new function code or source.
