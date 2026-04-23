# CommandLayer SDK

CommandLayer turns AI/runtime actions into verifiable receipts you can run and audit from one SDK.

```bash
npm install @commandlayer/sdk
```

```ts
import { commandlayer } from "@commandlayer/sdk";
const receipt = await commandlayer.run("summarize", {
  text: "Agent receipts prove what happened."
});
const result = await commandlayer.verify(receipt);
console.log(receipt);
console.log(result.valid ?? result.ok);
```

For advanced usage (custom clients, ENS/public key verification, and protocol details), see the docs below.

## What this repo now treats as canonical

- **Requests**: Commons requests are built around one explicit envelope: top-level `x402.verb`, `x402.version`, `actor`, and the verb body.
- **Responses**: the signed artifact is always `response.receipt`.
- **Unsigned runtime context**: optional execution details live in `response.runtime_metadata`.
- **Verification**: verification recomputes the receipt hash from the unsigned receipt, checks `metadata.receipt_id === metadata.proof.hash_sha256`, then verifies the Ed25519 signature over the UTF-8 hash string.
- **Verb semantics**: the verb is read from `receipt.x402.verb`.

This repo no longer presents legacy blended envelopes as the primary contract. Legacy normalization remains only to accept older runtime responses that inlined `trace` beside the receipt.

## Start here

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

Protocol-Commercial / x402 payment flows are intentionally separate from the Commons SDK surface in this repo. Commons examples and helpers below avoid payment metadata entirely; any retained `receipt.x402` handling is legacy / commercial-only compatibility, not the Commons happy path.

## Install

### TypeScript / JavaScript

```bash
npm install @commandlayer/sdk
```

### Python

```bash
pip install commandlayer
```

## Canonical receipt shape

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
      "receipt_id": "sha256-of-unsigned-receipt",
      "proof": {
        "alg": "ed25519-sha256",
        "canonical": "cl-stable-json-v1",
        "signer_id": "runtime.commandlayer.eth",
        "hash_sha256": "same-value-as-receipt_id",
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

## TypeScript quick path

```ts
import { createClient, verifyReceipt } from "@commandlayer/sdk";

const client = createClient({ actor: "my-app" });
const response = await client.summarize({
  content: "CommandLayer turns agent calls into signed receipts.",
  style: "bullet_points"
});

console.log(response.receipt.result?.summary);
console.log(response.runtime_metadata?.duration_ms);

const verification = await verifyReceipt(response.receipt, {
  publicKey: process.env.COMMANDLAYER_PUBLIC_KEY!
});

console.log(verification.ok);
```

## Python quick path

```python
from commandlayer import create_client, verify_receipt

client = create_client(actor="my-app")
response = client.summarize(
    content="CommandLayer turns agent calls into signed receipts.",
    style="bullet_points",
)

print(response["receipt"]["result"]["summary"])
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

The canonical signed object is `receipt`. `runtime_metadata` is optional and unsigned. Verification, persistence, and downstream audit should use the canonical `receipt` object.

### Commons

Use the client verb methods or the explicit request builder helpers:

- TypeScript: `buildCommonsRequest(verb, body, { actor })`
- Python: `build_commons_request(verb, body, actor=...)`

### Commercial

The repo does **not** claim first-class commercial runtime coverage, but both SDKs now isolate commercial request shaping behind explicit opt-in helpers instead of mixing it into Commons request construction:

- TypeScript: `buildCommercialRequest(...)`
- Python: `build_commercial_request(...)`

That commercial builder is intentionally separate from the Commons happy path.

## Verification

Verification reads exactly the current receipt contract:

1. take `response.receipt`,
2. remove `metadata.receipt_id` and the signed hash/signature fields,
3. canonicalize with `cl-stable-json-v1`,
4. recompute `sha256`,
5. require `metadata.receipt_id === metadata.proof.hash_sha256`,
6. verify the Ed25519 signature.

## Legacy handling retained

Only one legacy surface is retained in the main packages:

- `normalizeCommandResponse` / `normalize_command_response` still accept older blended runtime payloads that used a top-level `trace` field and convert them into `{ receipt, runtime_metadata }`.

Everything else is documented and typed against the current receipt contract.
