# Developer Experience (DX) — CommandLayer SDK

This document defines how developers should experience CommandLayer — from install to first receipt — and the principles guiding SDK design decisions.

The goal is simple:

> Zero friction to first successful, verifiable receipt.

---

# 1. Design Principles

## 1.1 Deterministic by Default

CommandLayer Commons verbs are:

- Strictly schema-defined
- Deterministic where possible
- Receipt-producing
- Cryptographically verifiable

Developers should never wonder:

- What shape is this request?
- What does this response contain?
- Can I verify this output later?

The SDK exists to eliminate ambiguity.

---

## 1.2 Receipts > Raw Responses

Every SDK method returns a **receipt object**, not just output.

Example:

```ts
const receipt = await client.summarize({
  content: "Long text...",
  style: "bullet_points"
});

console.log(receipt.result);
console.log(receipt.metadata.proof.hash_sha256);
```

Why?

Because CommandLayer is not just execution — it is **evidence**.

---

## 1.3 Verification Is First-Class

Verification should be:

- Available
- Simple
- Optional
- Explicit

Developers can:

- Verify using a provided public key (offline)
- Resolve signer pubkey from ENS (online)
- Skip verification entirely (if desired)

The SDK must not silently perform network verification without consent.

---

# 2. Installation Experience

## TypeScript

```bash
npm install @commandlayer/sdk
```

Basic usage:

```ts
import { createClient } from "@commandlayer/sdk";

const client = createClient({
  runtime: "https://runtime.commandlayer.org"
});
```

---

## Python

```bash
pip install commandlayer-sdk
```

Basic usage:

```python
from commandlayer import create_client

client = create_client(runtime="https://runtime.commandlayer.org")
```

---

# 3. First Successful Call

The "Hello World" of CommandLayer:

```ts
const receipt = await client.summarize({
  content: "CommandLayer standardizes agent verbs.",
  style: "bullet_points"
});

console.log(receipt.result.summary);
```

Expected:

- A valid structured result
- A signed receipt
- A verifiable hash

---

# 4. SDK API Philosophy

## 4.1 Flat, Verb-Based Methods

Each Commons verb is a top-level method:

```ts
client.summarize(...)
client.analyze(...)
client.classify(...)
client.fetch(...)
client.convert(...)
```

No nested namespaces. No magic proxies.

Clarity over cleverness.

---

## 4.2 No Hidden Global State

The client instance holds configuration:

```ts
const client = createClient({
  runtime: "...",
  actor: "...",
  verifyReceipts: true
});
```

No singleton.
No global mutation.

---

## 4.3 Explicit Runtime Selection

Default runtime:

```
https://runtime.commandlayer.org
```

But developers may override:

```ts
createClient({
  runtime: "https://my-runtime.internal"
});
```

The SDK should not hard-code execution endpoints.

---

# 5. Receipt Verification Model

CommandLayer receipts contain:

- Structured result
- Canonicalized hash
- Ed25519 signature
- Signer identity

Verification modes:

## 5.1 Local Public Key

```ts
verifyReceipt(receipt, {
  publicKey: "...pem..."
});
```

Works offline.

---

## 5.2 ENS Resolution

```ts
verifyReceipt(receipt, {
  ens: true,
  rpcUrl: "https://mainnet.infura.io/v3/..."
});
```

Resolves:

```
cl.receipt.pubkey_* TXT record
```

This anchors signer identity to ENS.

---

## 5.3 Hybrid (Recommended)

The SDK may:

1. Attempt ENS resolution
2. Fall back to provided public key
3. Fail clearly if neither is available

This provides:

- Decentralized trust anchor
- Operational resilience

---

# 6. CLI Developer Experience

The CLI mirrors SDK behavior.

Example:

```bash
commandlayer summarize \
  --content "Test text" \
  --style bullet_points \
  --json
```

CLI expectations:

- Always outputs valid JSON when `--json` is passed
- Human-readable output by default
- Never hides errors

The CLI is:

- A smoke test tool
- A reproducibility tool
- A receipt inspector

---

# 7. Error Handling Philosophy

Errors must be:

- Structured
- Predictable
- Transparent

SDK errors include:

```ts
{
  statusCode: 400,
  message: "summarize.input.content required",
  details: {...}
}
```

No silent failures.
No swallowed verification errors.

---

# 8. Local Development Flow

Recommended flow:

```bash
npm install
npm run build
node bin/cli.js summarize --content "test" --json
```

Definition of working local SDK:

- Build succeeds
- CLI returns receipt JSON
- No runtime crashes
- No syntax errors

---

# 9. Performance Considerations

The SDK must:

- Avoid schema compilation during hot paths
- Cache validators
- Avoid blocking verification by default
- Allow disabling receipt verification

Verification should not cause production latency spikes.

---

# 10. Backwards Compatibility

We follow SemVer:

- Patch → bug fixes
- Minor → new verbs/options
- Major → breaking changes

The SDK must not:

- Change receipt shapes silently
- Alter canonicalization rules
- Break verification logic without version bump

---

# 11. What Is Not SDK Responsibility

The SDK does NOT:

- Define new verbs
- Modify schemas
- Change receipt canonicalization rules
- Override runtime security policy
- Perform business logic

It is a transport + validation layer.

---

# 12. Definition of Excellent Developer Experience

A developer can:

1. Install SDK in under 60 seconds
2. Make a successful call in under 2 minutes
3. Verify a receipt in under 5 minutes
4. Understand the receipt structure without reading the runtime source

If any of those fail, DX needs improvement.

---

# 13. Long-Term Vision

CommandLayer SDKs should become:

- The standard client layer for agentic infrastructure
- The simplest way to produce verifiable execution artifacts
- A reference implementation of semantic API contracts

The SDK is not just a client.

It is the interface between:

- Intent
- Execution
- Evidence
- Trust

---

