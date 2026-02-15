import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { installMockEns, ensFixtures, ethers } from "../../typescript-sdk/tests/helpers.mjs";

const require = createRequire(import.meta.url);
const { resolveSignerKey } = require("../../typescript-sdk/dist/index.cjs");

installMockEns();

async function resolveSigner(name) {
  const provider = new ethers.JsonRpcProvider("http://mock-rpc.local");
  const resolver = await provider.getResolver(name);
  if (!resolver) throw new Error("Missing cl.receipt.signer");
  const signer = (await resolver.getText("cl.receipt.signer"))?.trim();
  if (!signer) throw new Error("Missing cl.receipt.signer");
  return signer;
}

test("resolves cl.receipt.signer correctly", async () => {
  const signer = await resolveSigner("parseagent.eth");
  assert.equal(signer, "runtime.commandlayer.eth");
  const key = await resolveSignerKey("parseagent.eth", "http://mock-rpc.local");
  assert.equal(key.kid, ensFixtures["runtime.commandlayer.eth"]["cl.sig.kid"]);
});

test("fails if cl.receipt.signer missing", async () => {
  await assert.rejects(() => resolveSigner("invalidagent.eth"), /Missing cl\.receipt\.signer/);
});
