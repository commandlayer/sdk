import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
export const { ethers } = require("ethers");

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "../..");

export function loadFixture(name) {
  const fixturePath = path.join(repoRoot, "test_vectors", name);
  return JSON.parse(fs.readFileSync(fixturePath, "utf8"));
}

export function loadTextFixture(name) {
  const fixturePath = path.join(repoRoot, "test_vectors", name);
  return fs.readFileSync(fixturePath, "utf8").trim();
}

const pub = loadTextFixture("public_key_base64.txt");

export const ensFixtures = {
  "parseagent.eth": { "cl.receipt.signer": "runtime.commandlayer.eth" },
  "runtime.commandlayer.eth": { "cl.sig.pub": `ed25519:${pub}`, "cl.sig.kid": "v1" },
  "invalidagent.eth": {},
  "bad-signer.eth": { "cl.receipt.signer": "missing-pub.eth" },
  "missing-pub.eth": { "cl.sig.kid": "v1" },
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

export function installMockEns() {
  ethers.JsonRpcProvider.prototype.getResolver = async function (name) {
    if (!(name in ensFixtures)) {
      return null;
    }
    return new MockResolver(name);
  };
}
