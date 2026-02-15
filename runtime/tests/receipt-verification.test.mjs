import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { loadFixture, loadTextFixture } from "../../typescript-sdk/tests/helpers.mjs";

const require = createRequire(import.meta.url);
const { verifyReceipt } = require("../../typescript-sdk/dist/index.cjs");

const publicKey = `ed25519:${loadTextFixture("public_key_base64.txt")}`;

async function verifyReceiptWithKid(receipt) {
  if (receipt.kid !== "v1") {
    return { valid: false, error: "Unknown key id" };
  }
  const result = await verifyReceipt(receipt, { publicKey });
  return {
    valid: result.ok,
    error: result.errors.signature_error ?? result.errors.verify_error ?? ""
  };
}

test("valid receipt verifies", async () => {
  const receipt = loadFixture("receipt_valid.json");
  const result = await verifyReceiptWithKid(receipt);
  assert.equal(result.valid, true);
});

test("invalid signature fails", async () => {
  const receipt = loadFixture("receipt_invalid_sig.json");
  const result = await verifyReceiptWithKid(receipt);
  assert.equal(result.valid, false);
});

test("wrong kid fails", async () => {
  const receipt = loadFixture("receipt_wrong_kid.json");
  const result = await verifyReceiptWithKid(receipt);
  assert.match(result.error, /Unknown key id/);
});
