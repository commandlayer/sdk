# CommandLayer SDK Quickstart

Goal: install the SDK, run one verb, inspect the receipt, verify it, and reproduce the call in under three minutes.

## 1. Install

### TypeScript / JavaScript

```bash
npm install @commandlayer/sdk
```

### Python

```bash
pip install commandlayer
```

### CLI

The CLI ships with the TypeScript/npm package only:

```bash
npm install -g @commandlayer/sdk
```

The Python SDK does not ship a CLI. Python users should use the TypeScript CLI or call the Python API directly.

## 2. Make your first call

### TypeScript

```ts
import { createClient } from "@commandlayer/sdk";

const client = createClient({ actor: "quickstart-ts" });

const response = await client.summarize({
  content: "CommandLayer makes agent execution verifiable.",
  style: "bullet_points"
});

console.log(response.receipt.result?.summary);
```

### Python

```python
from commandlayer import create_client

client = create_client(actor="quickstart-py")
response = client.summarize(
    content="CommandLayer makes agent execution verifiable.",
    style="bullet_points",
)

print(response["receipt"]["result"]["summary"])
```

## 3. Inspect the response

Both SDKs return the same shape:

```json
{
  "receipt": {
    "status": "success",
    "x402": { "verb": "summarize", "version": "1.1.0" },
    "result": { "summary": "..." },
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
    "duration_ms": 118
  }
}
```

Use `response.receipt` as the durable protocol artifact. `runtime_metadata` is optional execution context.

## 4. Verify the receipt

### TypeScript

```ts
import { verifyReceipt } from "@commandlayer/sdk";

const result = await verifyReceipt(response.receipt, {
  publicKey: "ed25519:BASE64_PUBLIC_KEY"
});

console.log(result.ok);
```

### Python

```python
from commandlayer import verify_receipt

result = verify_receipt(
    response["receipt"],
    public_key="ed25519:BASE64_PUBLIC_KEY",
)
print(result["ok"])
```

### ENS-backed verification

Use the same signer-discovery model in both SDKs:
- agent ENS TXT: `cl.receipt.signer`
- signer ENS TXT: `cl.sig.pub`
- signer ENS TXT: `cl.sig.kid`
- signer ENS TXT: `cl.sig.pub.<kid>` for older receipts after key rotation

## 5. Try the CLI

```bash
commandlayer summarize   --content "CommandLayer makes agent execution verifiable."   --style bullet_points   --json
```

Save the returned JSON and verify it:

```bash
commandlayer verify   --file receipt.json   --public-key "ed25519:BASE64_PUBLIC_KEY"
```

`commandlayer verify` accepts either a canonical receipt JSON object or a full response envelope with a top-level `receipt` field. New integrations should pass the canonical receipt explicitly.

## 6. What is stable today?

Stable in this repo:
- Protocol-Commons v1.1.0 verb surface,
- canonical signed receipt verification,
- ENS signer discovery helpers,
- TypeScript SDK `@commandlayer/sdk` v1.1.0,
- Python SDK `commandlayer` v1.1.0.

Not claimed as first-class SDK support here:
- Protocol-Commercial payment flows,
- runtime-specific orchestration metadata beyond the generic `runtime_metadata` envelope.

## Next steps

- More recipes: `EXAMPLES.md`
- Package docs: `typescript-sdk/README.md`, `python-sdk/README.md`
- Contributor workflow: `CONTRIBUTING.md`
- Maintainer notes: `MAINTAINER_GUIDE.md`
- Release flow: `RELEASE_GUIDE.md`
