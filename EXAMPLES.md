# CommandLayer SDK Examples

Canonical examples for the CommandLayer SDK repo. These examples keep the Commons v1.1.0 story receipt-first: `receipt` is signed, `runtime_metadata` is optional and unsigned, and Commons examples do not include payment metadata.

All examples in this file target:
- Protocol-Commons v1.1.0,
- canonical signed receipts returned as `response.receipt`, and
- optional execution context returned as `response.runtime_metadata`.

## 1. Canonical response envelope

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

```ts
const response = await client.clean({
  content: "   test@example.com  ",
  operations: ["trim", "redact_emails"]
});
```

### Convert

```ts
const response = await client.convert({
  content: '{"a":1}',
  from: "json",
  to: "csv"
});
```

### Describe

```ts
const response = await client.describe({
  subject: "receipt verification",
  audience: "general",
  detail: "medium"
});
```

### Explain

```ts
const response = await client.explain({
  subject: "receipt verification",
  audience: "novice",
  style: "step-by-step"
});
```

### Format

```ts
const response = await client.format({
  content: "a: 1\nb: 2",
  to: "table"
});
```

### Parse

```ts
const response = await client.parse({
  content: '{ "a": 1 }',
  contentType: "json",
  mode: "strict",
  schema: "invoice.summary.v1"
});
```

### Fetch

```ts
const response = await client.fetch({
  source: "https://example.com",
  include_metadata: true
});
```

## 3. Python examples

```python
from commandlayer import create_client

client = create_client(actor="examples-py")

summary = client.summarize(content="CommandLayer defines semantic agent verbs.", style="bullet_points")
analysis = client.analyze(content="Invoice total: $1200", goal="detect finance intent")
classification = client.classify(content="Contact support@example.com")
cleaned = client.clean(content="   test@example.com  ", operations=["trim", "redact_emails"])
converted = client.convert(content='{"a":1}', from_format="json", to_format="csv")
description = client.describe(subject="receipt verification")
explanation = client.explain(subject="receipt verification", style="step-by-step")
formatted = client.format(content="a: 1\nb: 2", to="table")
parsed = client.parse(content='{ "a": 1 }', content_type="json", mode="strict", schema="invoice.summary.v1")
fetched = client.fetch(source="https://example.com", include_metadata=True)
```

## 4. Verification examples

### TypeScript, explicit key

```ts
import { verifyReceipt } from "@commandlayer/sdk";

const result = await verifyReceipt(response.receipt, {
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
