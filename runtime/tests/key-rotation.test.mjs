import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { installMockEns, loadFixture } from "../../typescript-sdk/tests/helpers.mjs";

const require = createRequire(import.meta.url);
const { verifyReceipt } = require("../../typescript-sdk/dist/index.cjs");

installMockEns();

test("routes rotated ENS keys by receipt kid and rejects unknown kids", async () => {
  const receiptV1 = loadFixture("receipt_valid_v1.json");
  const receiptV2 = loadFixture("receipt_valid_v2.json");
  const wrongKidReceipt = loadFixture("receipt_wrong_kid.json");
  const removedKidReceipt = loadFixture("receipt_removed_kid.json");

  const v1Result = await verifyReceipt(receiptV1, {
    ens: { name: "rotatingagent.eth", rpcUrl: "http://mock-rpc.local" }
  });
  assert.equal(v1Result.ok, true, "v1 receipt should verify using cl.sig.pub.v1 after rotation");
  assert.equal(v1Result.values.pubkey_source, "ens");

  const v2Result = await verifyReceipt(receiptV2, {
    ens: { name: "rotatingagent.eth", rpcUrl: "http://mock-rpc.local" }
  });
  assert.equal(v2Result.ok, true, "v2 receipt should verify using the current rotated key");
  assert.equal(v2Result.values.pubkey_source, "ens");

  const wrongKidResult = await verifyReceipt(wrongKidReceipt, {
    ens: { name: "rotatingagent.eth", rpcUrl: "http://mock-rpc.local" }
  });
  assert.equal(wrongKidResult.ok, false);
  assert.match(wrongKidResult.errors.signature_error ?? "", /unknown key id/i);

  const removedKidResult = await verifyReceipt(removedKidReceipt, {
    ens: { name: "removed-agent.eth", rpcUrl: "http://mock-rpc.local" }
  });
  assert.equal(removedKidResult.ok, false);
  assert.match(removedKidResult.errors.signature_error ?? "", /unknown key id/i);
});
