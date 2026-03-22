# CommandLayer SDK Examples

## Canonical response envelope

```json
{
  "receipt": {
    "status": "success",
    "x402": { "verb": "summarize", "version": "1.1.0" },
    "result": { "summary": "..." },
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
    "trace_id": "trace_abc123",
    "duration_ms": 120,
    "provider": "runtime.commandlayer.org"
  }
}
```

## TypeScript

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

## Python

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

## Explicit request building

### Commons

```ts
import { buildCommonsRequest } from "@commandlayer/sdk";

const payload = buildCommonsRequest("parse", {
  input: { content: '{"a":1}', content_type: "json", mode: "strict" },
  limits: { max_output_tokens: 300 }
}, { actor: "examples-ts" });
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

Commercial request shaping is intentionally separate from Commons examples. Use the dedicated `buildCommercialRequest` / `build_commercial_request` helper only if you are integrating a payment-aware flow outside this repo's first-class runtime client surface.
