# CommandLayer TypeScript SDK

Current-line TypeScript SDK for reusable CommandLayer receipt flows.

## Scope

This package is SDK-only and focuses on:
- receipt generation helpers,
- canonicalization,
- SHA-256 hashing,
- Ed25519 signing + verification,
- ENS key-resolution helpers,
- agent-wrapping utilities.

For public paste-and-verify receipt verification, use VerifyAgent:
https://github.com/commandlayer/verifyagent

## Install

```bash
npm install @commandlayer/sdk
```

## Happy path

```ts
import { createClient, verifyReceipt } from "@commandlayer/sdk";

const client = createClient({ actor: "docs-example" });
const response = await client.summarize({
  content: "CommandLayer makes receipt verification explicit.",
  style: "bullet_points"
});

const verification = await verifyReceipt(response.receipt, {
  publicKey: "ed25519:BASE64_PUBLIC_KEY"
});

console.log(response.receipt.result?.summary);
console.log(verification.ok);
```

## Verification helpers

- `verifyReceipt(receipt, { publicKey })`
- `verifyReceipt(receipt, { ens: { name, rpcUrl } })`
- `extractReceiptVerb(receiptOrResponse)`
- `recomputeReceiptHashSha256(receiptOrResponse)`

## Contract semantics

- `response.receipt` is the signed canonical artifact.
- `response.runtime_metadata` is optional unsigned context.
- Verification recomputes the canonical SHA-256 hash and validates Ed25519 signature proof.
- `receipt.metadata.receipt_id` is compatibility metadata when present.

## Boundary notes

- VerifyAgent is external and not part of this package/repository runtime surface.
- Commercial hosted runtime, x402, and indexing/dashboard product surfaces are outside the SDK package scope.
