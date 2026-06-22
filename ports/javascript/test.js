// Minimal zero-dependency test runner for the JS port.
import assert from "node:assert/strict";
import { decodeHex, parseAndClassify, cleanHex } from "./index.js";

let pass = 0;
function t(name, fn) {
  fn();
  pass++;
  console.log("ok - " + name);
}

t("read holding is low", () => {
  const e = parseAndClassify(decodeHex("000100000006010300000001"));
  assert.equal(e.function_name, "read_holding_registers");
  assert.equal(e.severity, "low");
});

t("write single is high", () => {
  const e = parseAndClassify(decodeHex("000200000006010600010001"));
  assert.equal(e.category, "write");
  assert.equal(e.severity, "high");
});

t("oversized read is medium", () => {
  const e = parseAndClassify(decodeHex("0001000000060103000000C9"));
  assert.equal(e.severity, "medium");
});

t("report server id is high", () => {
  const e = parseAndClassify(decodeHex("0009000000020111"));
  assert.equal(e.severity, "high");
});

t("bad protocol id throws", () => {
  assert.throws(() => parseAndClassify(decodeHex("0001DEAD0006010300000001")));
});

t("short frame throws", () => {
  assert.throws(() => parseAndClassify([0, 1, 0]));
});

t("unknown function is medium", () => {
  const e = parseAndClassify(decodeHex("0001000000020163"));
  assert.equal(e.category, "unknown");
  assert.equal(e.severity, "medium");
});

t("cleanHex strips", () => {
  assert.equal(cleanHex("00 01 ab"), "0001ab");
});

console.log(`\n${pass} passed`);
