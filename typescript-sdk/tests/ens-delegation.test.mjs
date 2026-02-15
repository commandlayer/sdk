import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { installMockEns } from "./helpers.mjs";

const require = createRequire(import.meta.url);
const { resolveSignerKey } = require("../dist/index.cjs");

installMockEns();

test("agent delegates to runtime signer", async () => {
  const { algorithm, kid, rawPublicKeyBytes } = await resolveSignerKey(
    "parseagent.eth",
    "http://mock-rpc.local"
  );

  assert.equal(algorithm, "ed25519");
  assert.equal(kid, "v1");
  assert.equal(rawPublicKeyBytes.length, 32);
});
