# Ports of modpot

The same **core check** ported across languages: decode one Modbus/TCP frame
from hex and classify it into a severity (`info` / `low` / `medium` / `high`)
with the same category + reason logic as the Python reference. Each port is a
single dependency-free binary/script and exits `1` when the frame is
high-severity (write/control/recon) — handy as a CI gate.

| Language | Path | Run | Tests |
|---|---|---|---|
| Python (reference) | `../modpot/` | `modpot analyze capture.hexlog` | `pytest` (135+) |
| JavaScript / Node | `javascript/` | `echo 000200000006010600010001 \| node ports/javascript/index.js` | `node test.js` |
| TypeScript | `typescript/` | `npm run build && node dist/...` | `npm test` (tsc + node --test) |
| Go | `go/` | `cd ports/go && go run . 000100000006010300000001` | `go test ./...` |
| Rust | `rust/` | `cd ports/rust && cargo run -- 000100000006010300000001` | `cargo test` |

Run them all locally with `scripts/ports-test.sh` (each is skipped if its
toolchain is missing). The Go, Rust, JS, and TS ports are built and tested on
GitHub Actions by `.github/workflows/ports.yml`.

Input is a Modbus/TCP frame as hex (MBAP header + PDU), e.g.
`000200000006010600010001` is a `write_single_register` (high severity).

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see ../CONTRIBUTING.md.
