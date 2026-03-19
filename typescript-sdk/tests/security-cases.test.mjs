import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { loadFixture, loadTextFixture } from "./helpers.mjs";

const require = createRequire(import.meta.url);
const { verifyReceipt } = require("../dist/index.cjs");

const publicKey = `ed25519:${loadTextFixture("public_key_base64.txt")}`;

test("fails if caller-side issuer check mismatches expected agent", async () => {
  const receipt = loadFixture("receipt_valid.json");
  receipt.issuer = "evil.eth";

  await assert.rejects(
    async () => {
      if (receipt.issuer !== "parseagent.eth") {
        throw new Error("Issuer mismatch");
      }
      await verifyReceipt(receipt, { publicKey });
    },
    /Issuer mismatch/
  );
});

test("fails on tampered result payload", async () => {
  const receipt = loadFixture("receipt_valid.json");
  receipt.result.summary = "tampered";
  const result = await verifyReceipt(receipt, { publicKey });
  assert.equal(result.ok, false);
});
