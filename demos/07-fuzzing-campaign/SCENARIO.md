# Demo 07 - Protocol fuzzing campaign

## Where this came from

A honeypot recording a protocol fuzzer (`203.0.113.66`, TEST-NET-3 range)
that throws deliberately broken Modbus frames to find a crash or parser
bug. A honeypot must record fuzz traffic too - nothing silently
disappears, which is exactly what this demo proves.

## Input

`capture.hexlog` - intentionally malformed frames:

1. Bad protocol id `0xdead` (should be `0x0000`) -> medium (unparseable)
2. Truncated frame, MBAP header only -> medium (unparseable, too short)
3. Absurd MBAP length with unknown FC `0x7d` -> medium (scanner/fuzzing)
4. Truncated `write_multiple_registers` PDU body -> HIGH (write + undecodable)
5. Unknown function code `0xfe` -> medium (scanner/fuzzing)

## Run it

```bash
python -m modlure analyze demos/07-fuzzing-campaign/capture.hexlog
python -m modlure --format json analyze demos/07-fuzzing-campaign/capture.hexlog
```

## Expected result

Five events: one `high` (the malformed write), four `medium`. Every
malformed frame is still recorded with a reason. Exit status **1**.

## How to act

Fuzzing rarely succeeds against `modlure` (it is a tiny stdlib parser), but
a fuzzing campaign signals targeted interest. Capture full PCAP for the
source, rate-limit/block it, and make sure the real device behind the
decoy is not directly reachable.
