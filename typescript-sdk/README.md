# CommandLayer TypeScript SDK

Official TypeScript/JavaScript SDK for CommandLayer Commons v1.1.0.

Use this package to:
- call CommandLayer Commons verbs,
- receive a canonical signed receipt,
- capture optional runtime metadata separately,
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
    "x402": {
      "verb": "summarize",
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

`verifyReceipt()` accepts the canonical `receipt` object. The SDK also accepts a whole response envelope for legacy compatibility, but new integrations should pass `response.receipt` explicitly.

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
3. `cl.sig.kid` on the signer ENS name,
4. `cl.sig.pub.<kid>` when verifying an older receipt after key rotation.

## CLI

The package ships the `commandlayer` CLI.

The CLI has two usage layers:
- verb-specific commands such as `summarize` and `analyze` for the fast/common paths,
- `call` for generic usage when you want to supply the raw JSON payload for any verb.

`commandlayer verify` accepts either a canonical receipt JSON object or a full response envelope with a top-level `receipt` field.

```bash
commandlayer summarize --content "hello" --style bullet_points --json
commandlayer verify --file receipt.json --public-key "ed25519:BASE64_PUBLIC_KEY"
```

## Development

```bash
cd typescript-sdk
npm ci
npm run typecheck
npm test
```
