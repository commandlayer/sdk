import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { createClient, commandlayer, CommandLayerClient, verifyReceipt } = require("../dist/index.cjs");

test("createClient uses default baseUrl", () => {
  const client = createClient();
  assert.equal(client.runtime, "https://runtime.commandlayer.org");
});

test("custom baseUrl override works", () => {
  const client = createClient({ baseUrl: "https://example.com/runtime/" });
  assert.equal(client.runtime, "https://example.com/runtime");
});

test("commandlayer.run delegates to client.run", async () => {
  const originalRun = CommandLayerClient.prototype.run;
  CommandLayerClient.prototype.run = async function(action, input, options) {
    return { receipt: { status: "success" }, runtime_metadata: { action, input, options } };
  };

  try {
    const result = await commandlayer.run("summarize", { text: "hello" });
    assert.equal(result.runtime_metadata.action, "summarize");
    assert.deepEqual(result.runtime_metadata.input, { text: "hello" });
  } finally {
    CommandLayerClient.prototype.run = originalRun;
  }
});

test("commandlayer.verify delegates to verification logic", async () => {
  const originalVerify = CommandLayerClient.prototype.verify;
  const sentinel = { ok: true, checks: {}, values: {}, errors: {} };

  CommandLayerClient.prototype.verify = async function(receipt, options) {
    assert.equal(typeof verifyReceipt, "function");
    assert.deepEqual(receipt, { receipt: { status: "success" } });
    assert.deepEqual(options, { publicKey: "ed25519:abc" });
    return sentinel;
  };

  try {
    const result = await commandlayer.verify(
      { receipt: { status: "success" } },
      { publicKey: "ed25519:abc" }
    );
    assert.equal(result.ok, true);
    assert.equal(result.valid, true);
  } finally {
    CommandLayerClient.prototype.verify = originalVerify;
  }
});
