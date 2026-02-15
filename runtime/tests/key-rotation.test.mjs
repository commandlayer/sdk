import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { loadFixture, loadTextFixture } from "../../typescript-sdk/tests/helpers.mjs";

const require = createRequire(import.meta.url);
const { verifyReceipt } = require("../../typescript-sdk/dist/index.cjs");

const publicKey = `ed25519:${loadTextFixture("public_key_base64.txt")}`;

test("v1 receipt still verifies after v2 key added", async () => {
  const receipt = loadFixture("receipt_valid_v1.json");
  const result = await verifyReceipt(receipt, { publicKey });
  assert.equal(result.ok, true);
});
