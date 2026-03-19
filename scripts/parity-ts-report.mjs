import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");
const require = createRequire(path.join(repoRoot, "typescript-sdk", "package.json"));
const { ethers } = require("ethers");
const sdk = require(path.join(repoRoot, "typescript-sdk", "dist", "index.cjs"));
const manifest = JSON.parse(fs.readFileSync(path.join(repoRoot, "test_vectors", "parity_manifest.json"), "utf8"));
const publicKey = `ed25519:${fs.readFileSync(path.join(repoRoot, "test_vectors", "public_key_base64.txt"), "utf8").trim()}`;

const ensFixtures = {
  "parseagent.eth": { "cl.receipt.signer": "runtime.commandlayer.eth" },
  "runtime.commandlayer.eth": { "cl.sig.pub": publicKey, "cl.sig.kid": "v1" },
  "invalidagent.eth": {},
  "malformed.eth": { "cl.receipt.signer": "malformed-signer.eth" },
  "malformed-signer.eth": { "cl.sig.pub": "ed25519:not-base64", "cl.sig.kid": "v1" }
};

class MockResolver {
  constructor(name) {
    this.name = name;
  }
  async getText(key) {
    return ensFixtures[this.name]?.[key] ?? "";
  }
}

ethers.JsonRpcProvider.prototype.getResolver = async function (name) {
  if (!(name in ensFixtures)) return null;
  return new MockResolver(name);
};

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(repoRoot, "test_vectors", name), "utf8"));
}

const vectorResults = [];
for (const vector of manifest.verification_vectors) {
  const receipt = loadFixture(vector.name);
  const verification = await sdk.verifyReceipt(receipt, { publicKey });
  const recomputed = sdk.recomputeReceiptHashSha256(receipt);
  vectorResults.push({
    name: vector.name,
    expected_ok: vector.expected_ok,
    ok: verification.ok,
    checks: verification.checks,
    values: verification.values,
    errors: verification.errors,
    recomputed_hash: recomputed.hash_sha256
  });
}

const ensResults = [];
for (const caseDef of manifest.ens_resolution_cases) {
  try {
    const resolution = await sdk.resolveSignerKey(caseDef.name, "https://rpc.example");
    ensResults.push({
      name: caseDef.name,
      ok: true,
      algorithm: resolution.algorithm,
      kid: resolution.kid,
      signer_name: ensFixtures[caseDef.name]?.["cl.receipt.signer"] ?? null,
      public_key_b64: Buffer.from(resolution.rawPublicKeyBytes).toString("base64"),
      error: null
    });
  } catch (error) {
    ensResults.push({
      name: caseDef.name,
      ok: false,
      algorithm: null,
      kid: null,
      signer_name: ensFixtures[caseDef.name]?.["cl.receipt.signer"] ?? null,
      public_key_b64: null,
      error: error instanceof Error ? error.message : String(error)
    });
  }
}

console.log(JSON.stringify({ sdk: "typescript", public_key_length: sdk.parseEd25519Pubkey(publicKey).length, vector_results: vectorResults, ens_results: ensResults }, null, 2));
