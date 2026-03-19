# CommandLayer SDK Examples

Canonical examples for the CommandLayer SDK repo.

All examples in this file target:
- Protocol-Commons v1.1.0,
- canonical signed receipts returned as `response.receipt`, and
- optional execution context returned as `response.runtime_metadata`.

## 1. Canonical response envelope

```json
{
  "receipt": {
    "status": "success",
    "x402": {
      "verb": "summarize",
      "version": "1.1.0",
      "entry": "x402://summarizeagent.eth/summarize/v1.1.0"
    },
    "result": {
      "summary": "..."
    },
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
    "trace_id": "trace_abc123",
    "duration_ms": 120,
    "provider": "runtime.commandlayer.org"
  }
}
```

## 2. TypeScript examples

### Create client

```ts
import { createClient } from "@commandlayer/sdk";

const client = createClient({
  actor: "examples-ts",
  runtime: "https://runtime.commandlayer.org"
});
```

### Summarize

```ts
const response = await client.summarize({
  content: "CommandLayer defines semantic agent verbs.",
  style: "bullet_points"
});

console.log(response.receipt.result?.summary);
```

### Analyze

```ts
const response = await client.analyze({
  content: "Invoice total: $1200",
  goal: "detect finance intent"
});
```

### Classify

```ts
const response = await client.classify({
  content: "Contact support@example.com"
});
```

### Clean

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
  mode: "strict"
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
parsed = client.parse(content='{ "a": 1 }', content_type="json", mode="strict")
fetched = client.fetch(source="https://example.com", include_metadata=True)
```

## 4. Verification examples

### TypeScript, explicit key

```ts
import { verifyReceipt } from "@commandlayer/sdk";

const result = await verifyReceipt(response.receipt, {
  publicKey: "ed25519:BASE64_PUBLIC_KEY"
});
```

### Python, explicit key

```python
from commandlayer import verify_receipt

result = verify_receipt(response["receipt"], public_key="ed25519:BASE64_PUBLIC_KEY")
```

### ENS-backed verification

```ts
const result = await verifyReceipt(response.receipt, {
  ens: {
    name: "summarizeagent.eth",
    rpcUrl: process.env.MAINNET_RPC_URL!
  }
});
```

```python
result = verify_receipt(
    response["receipt"],
    ens={"name": "summarizeagent.eth", "rpcUrl": "https://mainnet.infura.io/v3/YOUR_KEY"},
)
```

## 5. CLI examples

### Summarize

```bash
commandlayer summarize \
  --content "CommandLayer defines semantic verbs." \
  --style bullet_points \
  --json
```

### Analyze

```bash
commandlayer analyze \
  --content "Invoice total: $500" \
  --goal "detect finance intent" \
  --json
```

### Verify a saved receipt

```bash
commandlayer verify \
  --file receipt.json \
  --public-key "ed25519:BASE64_PUBLIC_KEY"
```

## 6. Runtime override

### TypeScript

```ts
const client = createClient({
  actor: "override-example",
  runtime: "https://staging-runtime.commandlayer.org"
});
```

### Python

```python
client = create_client(
    actor="override-example",
    runtime="https://staging-runtime.commandlayer.org",
)
```

## 7. Persist the canonical receipt

```ts
import { writeFile } from "node:fs/promises";

await writeFile("receipt.json", JSON.stringify(response.receipt, null, 2));
```

```python
import json
from pathlib import Path

Path("receipt.json").write_text(json.dumps(response["receipt"], indent=2), encoding="utf-8")
```

## 8. Error handling

### TypeScript

```ts
import { CommandLayerError } from "@commandlayer/sdk";

try {
  await client.summarize({ content: "" });
} catch (error) {
  if (error instanceof CommandLayerError) {
    console.error(error.statusCode, error.message, error.details);
  }
}
```

### Python

```python
from commandlayer import CommandLayerError

try:
    client.summarize(content="")
except CommandLayerError as error:
    print(error.status_code, error, error.details)
```
