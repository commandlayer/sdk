# CommandLayer TypeScript SDK

Semantic verbs. Typed schemas. Signed receipts.

This package provides the official TypeScript/JavaScript SDK for **CommandLayer Commons v1.0.0**.

Install → call a verb → receive a signed receipt → verify it.

---

## Overview

CommandLayer is the semantic verb layer for autonomous agents.

The SDK provides:

- Standardized Commons verbs (`summarize`, `analyze`, `fetch`, etc.)
- Strict JSON Schemas (requests + receipts)
- Cryptographically signed receipts (Ed25519 + SHA-256)
- Deterministic canonicalization (`cl-stable-json-v1`)
- Verification helpers (offline or ENS-based)
- CLI for reproducible local testing

---

## Installation

```bash
npm install @commandlayer/sdk
```

### Quickstart (TypeScript)
```
import { createClient } from "@commandlayer/sdk";

const client = createClient({
  actor: "my-app"
});

const receipt = await client.summarize({
  content: "CommandLayer turns agent actions into verifiable receipts.",
  style: "bullet_points"
});

console.log(receipt.result.summary);
console.log(receipt.metadata.receipt_id);
```
---

### Runtime Configuration

Default runtime:
```
https://runtime.commandlayer.org
```

Override if needed:
```
const client = createClient({
  actor: "my-app",
  runtime: "https://your-runtime.example",
  verifyReceipts: true
});
```

verifyReceipts should remain enabled in production.

---

### Receipt Structure

Every call returns a signed receipt:

```
{
  "status": "success",
  "x402": {
    "verb": "summarize",
    "version": "1.0.0",
    "entry": "x402://summarizeagent.eth/summarize/v1.0.0"
  },
  "trace": {
    "trace_id": "trace_ab12cd34",
    "duration_ms": 118
  },
  "result": {
    "summary": "..."
  },
  "metadata": {
    "receipt_id": "8f0a...",
    "proof": {
      "alg": "ed25519-sha256",
      "canonical": "cl-stable-json-v1",
      "signer_id": "runtime.commandlayer.eth",
      "hash_sha256": "...",
      "signature_b64": "..."
    }
  }
}
```

Receipt guarantees:

- Stable canonical hashing
- SHA-256 digest over unsigned receipt
- Ed25519 signature over the hash
- Deterministic validation across runtimes

---

### Verifying Receipts
 

**Option A — Offline (explicit public key)**

Fastest method. No RPC required.
```
import { verifyReceipt } from "@commandlayer/sdk";

const result = await verifyReceipt(receipt, {
  publicKey: "ed25519:7Vkkmt6R02Iltp/+i3D5mraZyvLjfuTSVB33KwfzQC8="
});

console.log(result.ok);
```
---

**Option B — ENS-based Verification**

Resolves the public key from ENS TXT records.

Required ENS records:

- `cl.receipt.pubkey_pem`
- `cl.receipt.signer_id`
- `cl.receipt.alg`
- 
Example:
```
import { verifyReceipt } from "@commandlayer/sdk";

const out = await verifyReceipt(receipt, {
  ens: {
    name: "runtime.commandlayer.eth",
    rpcUrl: process.env.ETH_RPC_URL!
  }
});

console.log(out.ok, out.values.pubkey_source);
```

ENS affects verification correctness — not build or publishing.

---

**Commons Verbs**

All verbs return signed receipts.
```
await client.summarize({ content, style: "bullet_points" });

await client.analyze({
  content,
  dimensions: ["sentiment", "tone"]
});

await client.classify({
  content,
  categories: ["support", "billing"]
});

await client.clean({
  content,
  operations: ["trim", "normalize_newlines"]
});

await client.convert({
  content,
  from: "json",
  to: "csv"
});

await client.describe({
  subject,
  detail_level: "medium"
});

await client.explain({
  subject,
  style: "step-by-step"
});

await client.format({
  content,
  to: "table"
});

await client.parse({
  content,
  content_type: "json"
});

await client.fetch({
  source: "https://example.com"
});
```

See `EXAMPLES.md` for full technical payloads.

### CLI

The SDK includes a CLI for local testing.

**Build First**
```
npm run build
```

Expected output:

- `dist/index.cjs`
- `dist/index.mjs`
- `dist/cli.cjs`
- `dist/index.d.ts`

**Run**
```
node dist/cli.cjs summarize --content "test" --style bullet_points --json
```

***Global Link (Optional)**
```
npm link
commandlayer --help
commandlayer summarize --content "test" --style bullet_points
```

To unlink:
```
npm unlink -g @commandlayer/sdk || true
```
### Windows esbuild EBUSY Fix

- If install fails with EBUSY:
- Run terminal as Administrator
- Temporarily disable Defender real-time protection
- Close processes locking `node_modules`
- Delete `node_modules`
- Retry `npm install`

If you see:
```
'tsup' is not recognized
```

`npm install` did not complete successfully.

---

### Local Development Workflow
```
sdk/
  typescript-sdk/
    src/
    dist/
```

Typical flow:
```
cd typescript-sdk
npm install
npm run build
npm run test:cli-smoke
node dist/cli.cjs summarize --content "test" --style bullet_points --json
```
---

### Publishing to npm (Optional)

Ensure `typescript-sdk/package.json` includes:

- name
- version
- main / module / exports → dist/*
- types → dist/index.d.ts
- bin → bin/cli.js
- files → dist/ and bin/

Then:
```
npm login
npm publish --access public
```
---

### Versioning

Use Semantic Versioning:

- Patch → bug fixes
- Minor → backward-compatible additions
- Major → breaking changes

Release flow:

Update `CHANGELOG.md`
`npm version patch|minor|major`
`npm run build`
CLI smoke test
Tag + push

Publish

### Definition of Done

You are deployed when:

- `npm install` succeeds cleanly
- `npm run build` produces `dist/`
- CLI returns valid receipt JSON
- CI reproduces the same steps on push

---
License

MIT

CommandLayer turns agent actions into verifiable infrastructure.

Ship APIs that can prove what they did.
