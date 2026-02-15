/**
 * Unit tests for core SDK logic (canonicalization, hashing, verification).
 * Uses tweetnacl for Ed25519 key generation — no external test framework needed.
 */
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);

const {
  canonicalizeStableJsonV1,
  sha256HexUtf8,
  parseEd25519Pubkey,
  verifyEd25519SignatureOverUtf8HashString,
  recomputeReceiptHashSha256,
  verifyReceipt,
  CommandLayerError,
  CommandLayerClient,
} = require("../dist/index.cjs");

const nacl = require("tweetnacl");

let passed = 0;
let failed = 0;

function assert(condition, name) {
  if (!condition) {
    failed++;
    console.error(`FAIL: ${name}`);
  } else {
    passed++;
    console.log(`PASS: ${name}`);
  }
}

function assertThrows(fn, name) {
  try {
    fn();
    failed++;
    console.error(`FAIL: ${name} (did not throw)`);
  } catch {
    passed++;
    console.log(`PASS: ${name}`);
  }
}

// ---- Canonicalization ----

assert(canonicalizeStableJsonV1(null) === "null", "canonicalize null");
assert(canonicalizeStableJsonV1(true) === "true", "canonicalize true");
assert(canonicalizeStableJsonV1(false) === "false", "canonicalize false");
assert(canonicalizeStableJsonV1(42) === "42", "canonicalize int");
assert(canonicalizeStableJsonV1(3.14) === "3.14", "canonicalize float");
assert(canonicalizeStableJsonV1("hello") === '"hello"', "canonicalize string");
assert(canonicalizeStableJsonV1([1, 2, 3]) === "[1,2,3]", "canonicalize array");
assert(
  canonicalizeStableJsonV1({ b: 2, a: 1 }) === '{"a":1,"b":2}',
  "canonicalize sorts keys"
);
assert(
  canonicalizeStableJsonV1({ z: { b: 1, a: 2 } }) === '{"z":{"a":2,"b":1}}',
  "canonicalize nested sorted"
);
assertThrows(
  () => canonicalizeStableJsonV1(BigInt(1)),
  "canonicalize rejects bigint"
);
assertThrows(
  () => canonicalizeStableJsonV1(Infinity),
  "canonicalize rejects Infinity"
);
assertThrows(
  () => canonicalizeStableJsonV1({ a: undefined }),
  "canonicalize rejects undefined value"
);

// Negative zero
assert(canonicalizeStableJsonV1(-0) === "0", "canonicalize -0 => 0");

// ---- SHA-256 ----

const knownHash = sha256HexUtf8("hello");
assert(knownHash.length === 64, "sha256 returns 64 hex chars");
assert(sha256HexUtf8("hello") === knownHash, "sha256 deterministic");
assert(sha256HexUtf8("hello") !== sha256HexUtf8("world"), "sha256 differs for different inputs");

// ---- Ed25519 pubkey parsing ----

const kp = nacl.sign.keyPair();
const b64Key = Buffer.from(kp.publicKey).toString("base64");
const hexKey = Buffer.from(kp.publicKey).toString("hex");

const pk1 = parseEd25519Pubkey(b64Key);
assert(pk1.length === 32, "parse base64 pubkey");

const pk2 = parseEd25519Pubkey(`ed25519:${b64Key}`);
assert(pk2.length === 32, "parse ed25519: prefixed pubkey");

const pk3 = parseEd25519Pubkey(hexKey);
assert(pk3.length === 32, "parse hex pubkey");

const pk4 = parseEd25519Pubkey(`0x${hexKey}`);
assert(pk4.length === 32, "parse 0x-prefixed hex pubkey");

assertThrows(
  () => parseEd25519Pubkey("not_valid_key!!"),
  "rejects invalid pubkey"
);

// ---- Signature verification ----

const hashHex = sha256HexUtf8('{"test":true}');
const msg = Buffer.from(hashHex, "utf8");
const sig = nacl.sign.detached(new Uint8Array(msg), kp.secretKey);
const sigB64 = Buffer.from(sig).toString("base64");

assert(
  verifyEd25519SignatureOverUtf8HashString(hashHex, sigB64, kp.publicKey) === true,
  "valid signature verifies"
);

const badKp = nacl.sign.keyPair();
assert(
  verifyEd25519SignatureOverUtf8HashString(hashHex, sigB64, badKp.publicKey) === false,
  "wrong key rejects"
);

// ---- Receipt verification (end-to-end) ----

const receipt = {
  status: "success",
  x402: { verb: "summarize", version: "1.0.0", entry: "x402://summarizeagent.eth/summarize/v1.0.0" },
  result: { summary: "test" },
  metadata: {
    proof: {
      alg: "ed25519-sha256",
      canonical: "cl-stable-json-v1",
      signer_id: "runtime.commandlayer.eth",
    },
  },
};

const { hash_sha256 } = recomputeReceiptHashSha256(receipt);
const receiptMsg = Buffer.from(hash_sha256, "utf8");
const receiptSig = nacl.sign.detached(new Uint8Array(receiptMsg), kp.secretKey);

receipt.metadata.proof.hash_sha256 = hash_sha256;
receipt.metadata.proof.signature_b64 = Buffer.from(receiptSig).toString("base64");
receipt.metadata.receipt_id = hash_sha256;

const vr = await verifyReceipt(receipt, { publicKey: `ed25519:${b64Key}` });
assert(vr.ok === true, "verifyReceipt ok for valid receipt");
assert(vr.checks.hash_matches === true, "verifyReceipt hash matches");
assert(vr.checks.signature_valid === true, "verifyReceipt signature valid");
assert(vr.checks.receipt_id_matches === true, "verifyReceipt receipt_id matches");

// Tampered receipt
const tamperedReceipt = JSON.parse(JSON.stringify(receipt));
tamperedReceipt.result.summary = "tampered";
const vr2 = await verifyReceipt(tamperedReceipt, { publicKey: `ed25519:${b64Key}` });
assert(vr2.ok === false, "verifyReceipt rejects tampered receipt");
assert(vr2.checks.hash_matches === false, "tampered receipt hash mismatch");

// ---- Client verb validation ----

const client = new CommandLayerClient();
try {
  await client.call("nonexistent", {});
  failed++;
  console.error("FAIL: client.call accepts unknown verb");
} catch (err) {
  assert(err instanceof CommandLayerError, "client.call rejects unknown verb with CommandLayerError");
}

// ---- Summary ----

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
