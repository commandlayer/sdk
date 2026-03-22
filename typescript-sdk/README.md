# CommandLayer TypeScript SDK

Official TypeScript/JavaScript SDK for CommandLayer Commons v1.1.0.

Use this package to:
- call CommandLayer Commons verbs,
- receive the canonical signed `receipt`,
- capture optional unsigned `runtime_metadata` separately,
- verify receipts offline or through ENS, and
- reproduce calls from the CLI.

## Install

```bash
npm install @commandlayer/sdk
```

Supported runtime: Node.js 20+.

## Quick start

```ts
import { createClient, verifyReceipt } from "@commandlayer/sdk";

const client = createClient({ actor: "docs-example" });

const response = await client.summarize({
  content: "CommandLayer makes agent execution verifiable.",
  style: "bullet_points"
});

console.log(response.receipt.result?.summary);
console.log(response.receipt.verb);
console.log(response.receipt.metadata?.receipt_id);
console.log(response.runtime_metadata?.duration_ms);

const verification = await verifyReceipt(response.receipt, {
  publicKey: process.env.COMMANDLAYER_PUBLIC_KEY!
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
    "x402": {
      "version": "1.1.0"
    },
    "result": {},
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

`verifyReceipt()` accepts the canonical `receipt` object. The runtime-aligned receipt verb lives at `receipt.verb`; `receipt.x402.verb` is accepted only as a legacy fallback. `metadata.receipt_id` is a distinct receipt identifier, while `metadata.proof.hash_sha256` is the integrity hash that is recomputed and signature-verified. The retained `receipt.x402` block is Commons protocol metadata, not a primary SDK surface. The SDK also accepts a whole response envelope for legacy compatibility, but new integrations should pass `response.receipt` explicitly.

## Verification modes

### Offline

```ts
const result = await verifyReceipt(response.receipt, {
  publicKey: "ed25519:BASE64_PUBLIC_KEY"
});
```

### ENS-backed

```ts
const result = await verifyReceipt(response.receipt, {
  ens: {
    name: "summarizeagent.eth",
    rpcUrl: process.env.MAINNET_RPC_URL!
  }
});
```

The ENS flow resolves:
1. `cl.receipt.signer` on the agent ENS name,
2. `cl.sig.pub` on the signer ENS name,
3. `cl.sig.kid` on the signer ENS name.

## CLI

The package ships the `commandlayer` CLI.

```bash
commandlayer summarize --content "hello" --style bullet_points --json
commandlayer verify --file receipt.json --public-key "ed25519:BASE64_PUBLIC_KEY"
```

## Development

`npm test` is package-local and reproducible from this repo alone. The optional protocol integration lane remains available as `npm run test:integration`.

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
- `verifyReceipt()` succeeds when the declared algorithm/canonicalization match, the recomputed payload hash matches `hash_sha256`, and the Ed25519 signature validates over that hash.
- Legacy receipts that still place the verb under `receipt.x402.verb` continue to parse, but that path is fallback-only.
