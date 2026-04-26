# CommandLayer TypeScript SDK

Current-line TypeScript SDK for the CommandLayer Commons receipt contract (`1.1.0`).

## What is canonical

- `response.receipt` is the signed receipt.
- `response.runtime_metadata` is optional unsigned execution context.
- `receipt.metadata.proof.hash_sha256` is the signed/recomputed receipt proof hash.
- The canonical verb lives at `receipt.verb`; `receipt.x402.verb` is legacy / commercial fallback only.
- `receipt.metadata.receipt_id`, when present, should match the proof hash but is not required for verification `ok`.

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

console.log(response.receipt.result?.summary);
console.log(response.runtime_metadata?.duration_ms);

const verification = await verifyReceipt(response.receipt, {
  publicKey: "ed25519:BASE64_PUBLIC_KEY"
});

console.log(verification.ok);
```

## Return shape

Client methods return:

```json
{
  "receipt": {
    "status": "success",
    "verb": "summarize",
    "result": {},
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

`verifyReceipt()` accepts the canonical `receipt` object. The SDK also accepts a whole response envelope for legacy compatibility, but new integrations should pass `response.receipt` explicitly. Any `receipt.x402` block should be treated as legacy / commercial-only metadata rather than part of the Commons contract.

## Verification modes

### Offline

```ts
const result = await verifyReceipt(response.receipt, {
  publicKey: "ed25519:BASE64_PUBLIC_KEY"
});
```

### ENS-backed

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

```bash
cd typescript-sdk
npm ci
npm run typecheck
npm test
npm run test:integration
```

## Receipt verification semantics

- `receipt.verb` is the canonical verb field returned by the runtime.
- `receipt.metadata.receipt_id` is an identifier for the receipt instance.
- `receipt.metadata.proof.hash_sha256` is the SHA-256 hash over the unsigned canonical receipt payload.
- `verifyReceipt()` succeeds when the declared algorithm/canonicalization match, the recomputed payload hash matches `hash_sha256`, and the Ed25519 signature validates over that hash. Any `receipt_id_matches` output is compatibility/diagnostic metadata and is not required for `ok`.
- Legacy receipts that still place the verb under `receipt.x402.verb` continue to parse, but that path is fallback-only.
