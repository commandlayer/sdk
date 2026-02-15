import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { loadFixture, loadTextFixture } from "./helpers.mjs";

const require = createRequire(import.meta.url);
const { recomputeReceiptHashSha256 } = require("../dist/index.cjs");

test("stable JSON produces deterministic hash", () => {
  const receipt = loadFixture("receipt_valid.json");
  const hash1 = recomputeReceiptHashSha256(receipt).hash_sha256;
  const hash2 = recomputeReceiptHashSha256(JSON.parse(JSON.stringify(receipt))).hash_sha256;

  assert.equal(hash1, hash2);
  assert.equal(hash1, loadTextFixture("expected_hash.txt"));
});
