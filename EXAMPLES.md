# CommandLayer SDK Examples

Canonical examples for the CommandLayer SDK repo. These examples keep the Commons v1.1.0 story aligned with the active request and receipt contracts: requests are flat top-level protocol objects, `receipt` is signed, `runtime_metadata` is optional and unsigned, and the `x402` object only appears inside receipts as protocol metadata.

All examples in this file target:
- Protocol-Commons v1.1.0,
- flat request payloads shaped exactly like `schemas/v1.1.0/commons/<verb>/<verb>.request.schema.json`,
- canonical signed receipts returned as `response.receipt`, and
- optional execution context returned as `response.runtime_metadata`.

## 1. Canonical summarize request

```json
{
  "verb": "summarize",
  "version": "1.1.0",
  "input": "CommandLayer defines semantic agent verbs.",
  "mode": "brief"
}
```

## 2. Canonical response envelope

```json
{
  "receipt": {
    "status": "success",
    "x402": {
      "verb": "summarize",
      "version": "1.1.0"
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

## 3. TypeScript examples

### Create client

```ts
import { createClient } from "@commandlayer/sdk";

const client = createClient({
  runtime: "https://runtime.commandlayer.org"
});
```

### Summarize

```ts
const response = await client.summarize({
  input: "CommandLayer defines semantic agent verbs.",
  mode: "brief"
});

console.log(response.receipt.result?.summary);
```

### Analyze

```ts
const response = await client.analyze({
  input: "Invoice total: $1200",
  mode: "deep"
});
```

### Classify

```ts
const response = await client.classify({
  input: "Contact support@example.com",
  mode: "single"
});
```

### Clean

```ts
const response = await client.clean({
  input: "   test@example.com  ",
  mode: "sanitize"
});
```

### Convert

```ts
const response = await client.convert({
  input: '{"a":1}',
  mode: "structured"
});
```

### Describe

```ts
const response = await client.describe({
  input: "receipt verification",
  mode: "detailed"
});
```

### Explain

```ts
const response = await client.explain({
  input: "receipt verification",
  mode: "stepwise"
});
```

### Format

```ts
const response = await client.format({
  input: "a: 1\nb: 2",
  mode: "markdown"
});
```

### Parse

```ts
const response = await client.parse({
  input: '{ "a": 1 }',
  mode: "strict"
});
```

### Fetch

```ts
const response = await client.fetch({
  input: "https://example.com",
  mode: "html"
});
```
