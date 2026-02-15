import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { installMockEns } from "../../typescript-sdk/tests/helpers.mjs";

const require = createRequire(import.meta.url);
const { resolveSignerKey } = require("../../typescript-sdk/dist/index.cjs");

installMockEns();

test("resolves cl.sig.pub and cl.sig.kid", async () => {
  const key = await resolveSignerKey("parseagent.eth", "http://mock-rpc.local");
  assert.equal(key.kid, "v1");
  assert.equal(key.rawPublicKeyBytes.length, 32);
});

test("fails if cl.sig.pub missing", async () => {
  await assert.rejects(
    () => resolveSignerKey("bad-signer.eth", "http://mock-rpc.local"),
    /cl\.sig\.pub missing/
  );
});

test("fails if pubkey malformed", async () => {
  await assert.rejects(
    () => resolveSignerKey("malformed.eth", "http://mock-rpc.local"),
    /cl\.sig\.pub malformed/
  );
});
