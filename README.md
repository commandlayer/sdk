# CommandLayer SDK

Official SDK repo for CommandLayer Protocol-Commons v1.1.0.

## Start Here

- Quickstart → `QUICKSTART.md`
- Full usage → `EXAMPLES.md`
- Contributing → `CONTRIBUTING.md`
- Maintainers → `MAINTAINER_GUIDE.md`
- Releases → `RELEASE_GUIDE.md`
- Test vectors → `test_vectors/README.md`
- Changelog → `CHANGELOG.md`

This repository ships the public developer surfaces for CommandLayer:
- the TypeScript SDK: `@commandlayer/sdk`,
- the Python SDK: `commandlayer`,
- the `commandlayer` CLI shipped with the npm package,
- verification helpers and test vectors, and
- repo-level docs for install, release, and reproducibility.

## Supported protocol line

This repo is aligned to the current CommandLayer v1.1.0 surface:
- Protocol-Commons v1.1.0,
- Agent-Cards v1.1.0 for ENS-backed signer discovery,
- canonical signed receipts as the verification contract payload, and
- optional `runtime_metadata` as unsigned execution context.

Protocol-Commercial / x402 payment flows are not a first-class SDK surface in this repo today. If a runtime still includes `receipt.x402`, treat it as compatibility metadata rather than the primary Commons contract surface or a commercial feature signal.

## Install

### TypeScript / JavaScript

```bash
npm install @commandlayer/sdk
```

Node.js 20+ is supported.

### Python

```bash
pip install commandlayer
```

Python 3.10+ is supported.

## First call: TypeScript

```ts
import { createClient, verifyReceipt } from "@commandlayer/sdk";

const client = createClient({ actor: "my-app" });

const response = await client.summarize({
  content: "CommandLayer turns agent calls into signed receipts.",
  style: "bullet_points"
});

console.log(response.receipt.result?.summary);
console.log(response.receipt.metadata?.proof?.hash_sha256);
console.log(response.runtime_metadata?.duration_ms);

const verification = await verifyReceipt(response.receipt, {
  publicKey: process.env.COMMANDLAYER_PUBLIC_KEY!
});

console.log(verification.ok);
```

## First call: Python

```python
from commandlayer import create_client, verify_receipt

client = create_client(actor="my-app")
response = client.summarize(
    content="CommandLayer turns agent calls into signed receipts.",
    style="bullet_points",
)

print(response["receipt"]["result"]["summary"])
print(response["receipt"]["metadata"]["proof"]["hash_sha256"])
print(response.get("runtime_metadata", {}).get("duration_ms"))

verification = verify_receipt(
    response["receipt"],
    public_key="ed25519:BASE64_PUBLIC_KEY",
)
print(verification["ok"])
```

## Return shape

Client methods now return a command response envelope:

```json
{
  "receipt": {
    "status": "success",
    "verb": "summarize",
    "schema_version": "1.1.0",
    "result": {
      "summary": "..."
    },
    "metadata": {
      "proof": {
        "alg": "ed25519-sha256",
        "canonical": "cl-stable-json-v1",
        "signer_id": "runtime.commandlayer.eth",
        "hash_sha256": "...",
        "signature_b64": "..."
      }
    }
  },
  "runtime_metadata": {
    "trace_id": "trace_123",
    "duration_ms": 118,
    "provider": "runtime.commandlayer.org"
  }
}
```

The canonical signed object is `receipt`. In Commons v1.1.0 the stable receipt identity comes from the recomputed proof hash (`metadata.proof.hash_sha256`), while `runtime_metadata` stays optional and unsigned.

The SDK still normalizes older blended runtime responses for compatibility, but that normalization is legacy-only. The repo documents the v1.1.0 envelope as the single canonical public contract.

## Verification

### Offline verification

```ts
import { verifyReceipt } from "@commandlayer/sdk";

const result = await verifyReceipt(response.receipt, {
  publicKey: "ed25519:BASE64_PUBLIC_KEY"
});
```

### ENS-backed verification

```ts
const result = await verifyReceipt(response.receipt, {
  ens: {
    name: "summarizeagent.eth",
    rpcUrl: process.env.MAINNET_RPC_URL!
  }
});
```

ENS signer discovery resolves:
1. `cl.receipt.signer` on the agent ENS name,
2. `cl.sig.pub` on the signer ENS name,
3. `cl.sig.kid` on the signer ENS name.

## CLI

Install the npm package and use the bundled CLI:

```bash
commandlayer summarize --content "Test text" --style bullet_points --json
commandlayer verify --file receipt.json --public-key "ed25519:BASE64_PUBLIC_KEY"
```

The CLI is intended for demos, CI smoke tests, debugging, and reproducing SDK flows without writing app code.

## Repo guide

- Fast onboarding: `QUICKSTART.md`
- Cookbook examples: `EXAMPLES.md`
- Maintainer / architecture notes: `DEVELOPER_EXPERIENCE.md`
- Release guide: `RELEASE_GUIDE.md`
- Deployment checklist: `DEPLOYMENT_GUIDE.md`
- Changelog: `CHANGELOG.md`
- TypeScript package docs: `typescript-sdk/README.md`
- Python package docs: `python-sdk/README.md`
