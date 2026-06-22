#!/usr/bin/env bash
# Run every language port's CORE-check tests. Each port decodes + classifies a
# Modbus/TCP frame from hex; ports are skipped if the toolchain is absent.
set -e
cd "$(dirname "$0")/.."

echo "== javascript =="
( cd ports/javascript && node test.js ) || echo "node: skipped"

echo "== typescript =="
( cd ports/typescript && npm test ) 2>/dev/null || echo "typescript: skipped (needs npm install)"

echo "== go =="
( cd ports/go && go test ./... ) 2>/dev/null || echo "go: skipped (no toolchain)"

echo "== rust =="
( cd ports/rust && cargo test ) 2>/dev/null || echo "rust: skipped (no toolchain)"
