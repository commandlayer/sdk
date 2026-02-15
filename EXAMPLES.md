# CommandLayer SDK — Examples (Spec-Ready)

This document provides canonical, implementation-aligned examples for:

- All Commons verbs
- Receipt structure
- Verification flows
- CLI usage
- cURL reproduction
- Multi-step orchestration
- Error handling

All examples target:

```
API Version: v1.0.0
Canonical Runtime: https://runtime.commandlayer.org
Schema Host: https://www.commandlayer.org
```

---

# 1. Receipt Structure (Canonical Reference)

Every successful SDK call returns a receipt shaped as:

```json
{
  "status": "success",
  "x402": {
    "verb": "summarize",
    "version": "1.0.0",
    "entry": "x402://summarizeagent.eth/summarize/v1.0.0"
  },
  "trace": {
    "trace_id": "trace_abc123",
    "parent_trace_id": null,
    "started_at": "2026-02-15T02:30:00.000Z",
    "completed_at": "2026-02-15T02:30:00.120Z",
    "duration_ms": 120,
    "provider": "runtime"
  },
  "result": { ... },
  "metadata": {
    "proof": {
      "alg": "ed25519-sha256",
      "canonical": "cl-stable-json-v1",
      "signer_id": "runtime.commandlayer.eth",
      "hash_sha256": "abc...",
      "signature_b64": "xyz..."
    },
    "receipt_id": "abc..."
  }
}
```

Verification requires:

- Canonical JSON reconstruction
- SHA-256 hash match
- Ed25519 signature verification

---

# 2. TypeScript SDK Examples

## 2.1 Create Client

```ts
import { createClient } from "@commandlayer/sdk";

const client = createClient({
  runtime: "https://runtime.commandlayer.org",
  verifyReceipts: false
});
```

---

## 2.2 Summarize

```ts
const receipt = await client.summarize({
  content: "CommandLayer defines semantic agent verbs.",
  style: "bullet_points"
});

console.log(receipt.result.summary);
```

Expected `result`:

```json
{
  "summary": "CommandLayer defines semantic agent verbs.",
  "format": "text",
  "compression_ratio": 1.0,
  "source_hash": "..."
}
```

---

## 2.3 Analyze

```ts
const receipt = await client.analyze({
  input: "Invoice total: $1200",
  goal: "detect finance intent"
});
```

Expected result:

```json
{
  "summary": "...",
  "insights": [...],
  "labels": ["finance"],
  "score": 0.25
}
```

---

## 2.4 Classify

```ts
const receipt = await client.classify({
  actor: "tenant_1",
  input: {
    content: "Contact support@example.com"
  }
});
```

Expected result:

```json
{
  "labels": ["contains_emails"],
  "scores": [0.5],
  "taxonomy": ["root", "contains_emails"]
}
```

---

## 2.5 Fetch

```ts
const receipt = await client.fetch({
  source: "https://example.com"
});
```

Expected result:

```json
{
  "items": [
    {
      "source": "https://example.com",
      "ok": true,
      "http_status": 200,
      "body_preview": "<!doctype html>...",
      "truncated": false
    }
  ]
}
```

---

## 2.6 Convert

```ts
const receipt = await client.convert({
  input: {
    content: "{\"a\":1}",
    source_format: "json",
    target_format: "csv"
  }
});
```

---

## 2.7 Explain

```ts
await client.explain({
  input: {
    subject: "Receipt verification",
    audience: "novice",
    style: "step-by-step"
  }
});
```

---

## 2.8 Parse

```ts
await client.parse({
  input: {
    content: "{ \"a\": 1 }",
    content_type: "json"
  }
});
```

---

## 2.9 Clean

```ts
await client.clean({
  input: {
    content: "   test@example.com  ",
    operations: ["trim", "redact_emails"]
  }
});
```

---

## 2.10 Format

```ts
await client.format({
  input: {
    content: "a: 1\nb: 2",
    target_style: "table"
  }
});
```

---

# 3. CLI Examples

## 3.1 Basic

```bash
commandlayer summarize \
  --content "CommandLayer defines semantic verbs." \
  --style bullet_points \
  --json
```

---

## 3.2 Pipe Input

```bash
cat file.txt | commandlayer summarize --stdin --json
```

---

## 3.3 Analyze

```bash
commandlayer analyze \
  --content "Invoice total: $500" \
  --dimensions sentiment
```

---

# 4. cURL Reproduction

Each receipt should include a `curl` block (if exposed by orchestration).

Example:

```bash
curl -X POST https://runtime.commandlayer.org/summarize/v1.0.0 \
  -H "Content-Type: application/json" \
  -d '{
    "x402": {
      "verb": "summarize",
      "version": "1.0.0"
    },
    "input": {
      "content": "Test text"
    }
  }'
```

---

# 5. Multi-Step Orchestration Example

## Flow: Fetch → Summarize → Explain

```ts
const step1 = await client.fetch({ source: "https://example.com" });

const step2 = await client.summarize({
  content: step1.result.items[0].body_preview
});

const step3 = await client.explain({
  input: {
    subject: "Example site summary",
    context: step2.result.summary
  }
});
```

Each step yields independent receipts.

---

# 6. Receipt Verification (Offline)

```ts
import { verifyReceipt } from "@commandlayer/sdk";

const ok = await verifyReceipt(receipt, {
  publicKey: "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
});

console.log(ok);
```

Verification steps:

1. Reconstruct unsigned receipt
2. Stable JSON stringify
3. SHA-256 hash
4. Compare with `metadata.proof.hash_sha256`
5. Verify Ed25519 signature

---

# 7. Receipt Verification (ENS)

```ts
await verifyReceipt(receipt, {
  ens: true,
  rpcUrl: "https://mainnet.infura.io/v3/..."
});
```

Resolution flow:

- Fetch ENS resolver
- Read `cl.receipt.pubkey_*`
- Convert to PEM if required
- Verify signature

---

# 8. Error Example

```json
{
  "status": "error",
  "x402": { "verb": "summarize", "version": "1.0.0" },
  "trace": {...},
  "error": {
    "code": "INTERNAL_ERROR",
    "message": "summarize.input.content required",
    "retryable": false
  },
  "metadata": { ... }
}
```

SDK should throw structured errors mirroring receipt shape.

---

# 9. Schema Validation Example

To validate receipt schema:

```ts
await verifyReceipt(receipt, {
  schema: true
});
```

If schema validator not warmed:

- SDK should either:
  - Compile schema
  - Or return controlled error

Never silently ignore invalid schema.

---

# 10. Deterministic Hash Example

Unsigned receipt canonicalization:

```ts
const unsigned = structuredClone(receipt);
unsigned.metadata.proof.hash_sha256 = "";
unsigned.metadata.proof.signature_b64 = "";
unsigned.metadata.receipt_id = "";

const canonical = stableStringify(unsigned);
const hash = sha256(canonical);
```

Hash must equal:

```
receipt.metadata.proof.hash_sha256
```

---

# 11. Definition of Spec Compliance

An SDK implementation is compliant if:

- All verbs map to `/verb/v1.0.0`
- Receipt canonicalization matches runtime
- Verification passes against runtime receipts
- Errors match receipt schema
- CLI and SDK produce identical receipt structures

---


