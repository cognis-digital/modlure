import { test } from "node:test";
import assert from "node:assert/strict";
import { decodeHex, parseAndClassify, cleanHex } from "./modpot.js";

test("read holding is low", () => {
  const e = parseAndClassify(decodeHex("000100000006010300000001"));
  assert.equal(e.function_name, "read_holding_registers");
  assert.equal(e.severity, "low");
});

test("write single is high", () => {
  const e = parseAndClassify(decodeHex("000200000006010600010001"));
  assert.equal(e.category, "write");
  assert.equal(e.severity, "high");
});

test("oversized read is medium", () => {
  const e = parseAndClassify(decodeHex("0001000000060103000000C9"));
  assert.equal(e.severity, "medium");
});

test("report server id is high", () => {
  const e = parseAndClassify(decodeHex("0009000000020111"));
  assert.equal(e.severity, "high");
});

test("bad protocol id throws", () => {
  assert.throws(() => parseAndClassify(decodeHex("0001DEAD0006010300000001")));
});

test("unknown function is medium", () => {
  const e = parseAndClassify(decodeHex("0001000000020163"));
  assert.equal(e.category, "unknown");
  assert.equal(e.severity, "medium");
});

test("cleanHex strips", () => {
  assert.equal(cleanHex("00 01 ab"), "0001ab");
});
