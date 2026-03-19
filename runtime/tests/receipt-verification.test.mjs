import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { installMockEns, loadFixture, loadTextFixture } from "../../typescript-sdk/tests/helpers.mjs";

installMockEns();

const require = createRequire(import.meta.url);
const { verifyReceipt } = require("../../typescript-sdk/dist/index.cjs");

const publicKey = `ed25519:${loadTextFixture("public_key_base64.txt")}`;

test("valid receipt verifies", async () => {
  const receipt = loadFixture("receipt_valid.json");
  const result = await verifyReceipt(receipt, { publicKey });
  assert.equal(result.ok, true);
});

test("invalid signature fails", async () => {
  const receipt = loadFixture("receipt_invalid_sig.json");
  const result = await verifyReceipt(receipt, { publicKey });
  assert.equal(result.ok, false);
});

test("wrong kid fails when ENS cannot route to a matching key", async () => {
  const receipt = loadFixture("receipt_wrong_kid.json");
  const result = await verifyReceipt(receipt, {
    ens: { name: "rotatingagent.eth", rpcUrl: "http://mock-rpc.local" }
  });
  assert.equal(result.ok, false);
  assert.match(result.errors.signature_error ?? "", /unknown key id/i);
});
