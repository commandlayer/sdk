# CommandLayer TypeScript SDK

Current-line TypeScript SDK for the CommandLayer Commons receipt contract (`1.1.0`).

## What is canonical

- `response.receipt` is the signed receipt.
- `response.runtime_metadata` is optional unsigned execution context.
- `receipt.metadata.receipt_id` is the receipt hash identifier and must match `receipt.metadata.proof.hash_sha256`.
- The verb lives at `receipt.x402.verb`.

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

console.log(response.receipt.metadata.receipt_id);
console.log(response.receipt.x402.verb);

const verification = await verifyReceipt(response.receipt, {
  publicKey: "ed25519:BASE64_PUBLIC_KEY"
});

console.log(verification.ok);
```

## Explicit request builders

```ts
import { buildCommonsRequest, buildCommercialRequest } from "@commandlayer/sdk";

const commons = buildCommonsRequest("summarize", {
  input: { content: "hello", summary_style: "bullet_points" },
  limits: { max_output_tokens: 400 }
}, { actor: "docs-example" });

const commercial = buildCommercialRequest("summarize", {
  input: { content: "hello" }
}, {
  actor: "docs-example",
  payment: { scheme: "x402", quote_id: "quote_123" }
});
```

The commercial builder is isolated on purpose; this package's first-class runtime client remains Commons-first.

## Verification helpers

- `verifyReceipt(receipt, { publicKey })`
- `verifyReceipt(receipt, { ens: { name, rpcUrl } })`
- `extractReceiptVerb(receiptOrResponse)`
- `recomputeReceiptHashSha256(receiptOrResponse)`

## Legacy support

`normalizeCommandResponse()` still accepts old blended payloads that put `trace` beside the receipt and rewrites them to `{ receipt, runtime_metadata }`. That is compatibility-only, not the recommended contract.
