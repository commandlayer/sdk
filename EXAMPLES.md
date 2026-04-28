# CommandLayer SDK Examples

Examples in this repository focus on reusable SDK behavior:
- receipt creation,
- canonicalization,
- SHA-256 hashing,
- Ed25519 signing/verification,
- ENS key-resolution helpers, and
- wrapping agent execution in CommandLayer receipts.

For public paste-and-verify receipt verification, use VerifyAgent:
https://github.com/commandlayer/verifyagent

## Architecture boundaries

- SDK repo: programmatic receipt tooling.
- VerifyAgent repo: external public verifier UI.
- Commercial API: hosted runtime, x402/paid flows, indexing, dashboards.

## 1. Canonical response envelope

```json
{
  "receipt": {
    "status": "success",
    "verb": "summarize",
    "result": {
      "summary": "..."
    },
    "metadata": {
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
    "trace_id": "trace_abc123",
    "duration_ms": 120,
    "provider": "runtime.commandlayer.org"
  }
}
```

## 2. TypeScript

```ts
import { createClient, extractReceiptVerb, verifyReceipt } from "@commandlayer/sdk";

const client = createClient({ actor: "examples-ts" });
const response = await client.summarize({
  content: "CommandLayer defines verifiable agent verbs.",
  style: "bullet_points"
});

console.log(extractReceiptVerb(response));
console.log(response.receipt.metadata.receipt_id);

const verified = await verifyReceipt(response.receipt, {
  publicKey: "ed25519:BASE64_PUBLIC_KEY"
});
console.log(verified.ok);
```

## 3. Python

```python
from commandlayer import create_client, verify_receipt
from commandlayer.verify import extract_receipt_verb

client = create_client(actor="examples-py")
response = client.summarize(
    content="CommandLayer defines verifiable agent verbs.",
    style="bullet_points",
)

print(extract_receipt_verb(response))
print(response["receipt"]["metadata"]["receipt_id"])
print(verify_receipt(response["receipt"], public_key="ed25519:BASE64_PUBLIC_KEY")["ok"])
```

## 4. Explicit request building

### Commons

```ts
import { buildCommonsRequest } from "@commandlayer/sdk";

const payload = buildCommonsRequest(
  "parse",
  {
    input: { content: '{"a":1}', content_type: "json", mode: "strict" },
    limits: { max_output_tokens: 300 }
  },
  { actor: "examples-ts" }
);
```

```python
from commandlayer import build_commons_request

payload = build_commons_request(
    "parse",
    {
        "input": {"content": '{"a":1}', "content_type": "json", "mode": "strict"},
        "limits": {"max_output_tokens": 300},
    },
    actor="examples-py",
)
```

### Commercial request shaping

Commercial request shaping is intentionally separate from Commons SDK examples in this repository.
