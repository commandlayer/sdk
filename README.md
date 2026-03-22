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

Protocol-Commercial / x402 payment flows are not a first-class SDK surface in this repo today. The retained `receipt.x402` metadata block is part of the Commons receipt schema here; it should not be read as a Commons request envelope or commercial feature coverage.

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

const client = createClient();

const response = await client.summarize({
  input: "CommandLayer turns agent calls into signed receipts.",
  mode: "brief"
});

console.log(response.receipt.result?.summary);
console.log(response.receipt.metadata?.receipt_id);
console.log(response.runtime_metadata?.duration_ms);

const verification = await verifyReceipt(response.receipt, {
  publicKey: process.env.COMMANDLAYER_PUBLIC_KEY!
});

console.log(verification.ok);
```

## Commons request contract

The active Protocol-Commons v1.1.0 request contract is flat and top-level:

```json
{
  "verb": "summarize",
  "version": "1.1.0",
  "input": "CommandLayer turns agent calls into signed receipts.",
  "mode": "brief"
}
```

Commons requests should not be wrapped in nested request bodies, actor envelopes, `limits`, or `x402` request metadata.

## First call: Python

```python
from commandlayer import create_client, verify_receipt

client = create_client(actor="my-app")
response = client.summarize(
    content="CommandLayer turns agent calls into signed receipts.",
    style="bullet_points",
)

print(response["receipt"]["result"]["summary"])
print(response["receipt"]["metadata"]["receipt_id"])
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
    "x402": {
      "verb": "summarize",
      "version": "1.1.0"
    },
    "result": {
      "summary": "..."
    },
    "metadata": {
      "receipt_id": "...",
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

The canonical signed object is `receipt`. `runtime_metadata` is optional and unsigned. Verification, persistence, and downstream audit should use the canonical `receipt` object.

The SDK still normalizes older blended runtime responses for compatibility, but that normalization is legacy-only. The repo documents the v1.1.0 envelope as the single canonical public contract.
