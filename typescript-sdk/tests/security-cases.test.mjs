import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { loadFixture, loadTextFixture } from "./helpers.mjs";

const require = createRequire(import.meta.url);
const { verifyReceipt } = require("../dist/index.cjs");

const publicKey = `ed25519:${loadTextFixture("public_key_base64.txt")}`;

async function verifyReceiptStrict(receipt) {
  if (receipt.issuer !== "parseagent.eth") {
    throw new Error("Issuer mismatch");
  }
  return verifyReceipt(receipt, { publicKey });
}

test("fails if receipt.issuer mismatches ENS name", async () => {
  const receipt = loadFixture("receipt_valid.json");
  receipt.issuer = "evil.eth";

  await assert.rejects(() => verifyReceiptStrict(receipt), /Issuer mismatch/);
});

test("fails on tampered payload_hash", async () => {
  const receipt = loadFixture("receipt_valid.json");
  receipt.payload_hash = "fakehash";

  const result = await verifyReceiptStrict(receipt);
  assert.equal(result.ok, false);
});
