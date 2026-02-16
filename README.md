# CommandLayer SDK

**Semantic verbs. Structured schemas. Signed receipts.**

CommandLayer is the execution layer for autonomous agents that turns actions into verifiable infrastructure.

This SDK lets you:

- Call standardized agent verbs (`summarize`, `analyze`, `classify`, etc.)
- Receive structured, typed responses
- Get cryptographically signed receipts
- Verify execution integrity (hash + signature)
- Integrate x402-ready workflows

---

# What Makes CommandLayer Different?

Traditional APIs return data.

CommandLayer returns **evidence**.

Every call produces a signed receipt containing:

- Structured result
- Canonical hash
- Ed25519 signature
- Signer identity
- Trace metadata

This enables:

- Auditability
- Independent verification
- Cross-runtime interoperability
- Agent-to-agent trust

---

# Installation

## TypeScript / JavaScript

```bash
npm install @commandlayer/sdk
```

## Python

```bash
pip install commandlayer
```

---

# Quick Example (TypeScript)

```ts
import { createClient } from "@commandlayer/sdk";

const client = createClient({
  actor: "my-app"
});

const receipt = await client.summarize({
  content: "CommandLayer defines semantic verbs.",
  style: "bullet_points"
});

console.log(receipt.result.summary);
```

You receive a signed receipt — not just raw output.

---

# Available Verbs (Commons v1.0.0)

- `summarize`
- `analyze`
- `classify`
- `clean`
- `convert`
- `describe`
- `explain`
- `format`
- `parse`
- `fetch`

All verbs:

- Use strict JSON schemas
- Produce deterministic receipt envelopes
- Support receipt verification

---

# Receipt Structure (High-Level)

```json
{
  "status": "success",
  "x402": { "verb": "summarize", "version": "1.0.0" },
  "trace": { "trace_id": "...", "duration_ms": 112 },
  "result": { ... },
  "metadata": {
    "proof": {
      "alg": "ed25519-sha256",
      "hash_sha256": "...",
      "signature_b64": "...",
      "signer_id": "runtime.commandlayer.eth"
    },
    "receipt_id": "..."
  }
}
```

Receipts are:

- Canonicalized
- SHA-256 hashed
- Ed25519 signed

---

# Verification

The SDK supports:

### Offline Verification

```ts
verifyReceipt(receipt, {
  publicKey: "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
});
```

### ENS-Based Verification

```ts
verifyReceipt(receipt, {
  ens: {
    name: "runtime.commandlayer.eth",
    rpcUrl: "https://mainnet.infura.io/v3/..."
  }
});
```

ENS verification resolves signer material using this TXT record chain:

- Agent/issuer ENS name TXT `cl.receipt.signer` => signer ENS name
- Signer ENS name TXT `cl.sig.pub` and `cl.sig.kid` => Ed25519 public key metadata

To verify receipts issued by the runtime signer, set `ens.name` to the issuer/agent name that contains `cl.receipt.signer`. If using `runtime.commandlayer.eth` as the agent name, set `cl.receipt.signer` on `runtime.commandlayer.eth` to point to itself.

### Verification (Working Example)

```ts
import { createClient } from "@commandlayer/sdk";
import { verifyReceipt } from "@commandlayer/sdk";

const client = createClient({
  actor: "my-app",
  verifyReceipts: true,
  verify: {
    ens: {
      name: "runtime.commandlayer.eth",
      rpcUrl: process.env.MAINNET_RPC!
    }
  }
});

const receipt = await client.summarize({ content: "hello", style: "bullet_points" });
// if verifyReceipts true, client methods should throw or return verify result depending on your design
// also show direct call:
const vr = await verifyReceipt(receipt, {
  ens: { name: "runtime.commandlayer.eth", rpcUrl: process.env.MAINNET_RPC! }
});
console.log(vr.ok, vr.checks);
```

### ENS Setup

For `runtime.commandlayer.eth` as the signer identity:

- Existing TXT records on `runtime.commandlayer.eth`:
  - `cl.sig.kid = v1`
  - `cl.sig.pub = ed25519:CEHI9g4...`
- Add one additional TXT record on `runtime.commandlayer.eth`:
  - `cl.receipt.signer = runtime.commandlayer.eth`

This makes `runtime.commandlayer.eth` self-describing for ENS verification, so the SDK can resolve `cl.receipt.signer` and then fetch `cl.sig.pub`/`cl.sig.kid` from the same name.

Optional future pattern:

- If each issuer/agent ENS name (for example, `summarizeagent.eth`) should verify through its own lookup, add:
  - `cl.receipt.signer = runtime.commandlayer.eth`
  on each issuer/agent ENS name, while keeping signing keys only on `runtime.commandlayer.eth`.

---

# CLI

The SDK includes a CLI for testing and reproducibility.

```bash
commandlayer summarize \
  --content "Test text" \
  --style bullet_points
```

Pipe support:

```bash
cat file.txt | commandlayer summarize --stdin
```

---

# Runtime Compatibility

Default runtime:

```
https://runtime.commandlayer.org
```

Override if needed:

```ts
createClient({
  runtime: "https://your-runtime.example"
});
```

The SDK does not hard-code execution infrastructure.

---

# Architecture

CommandLayer separates:

1. **Semantic layer** (verbs + schemas)
2. **Execution layer** (runtime)
3. **Verification layer** (hash + signature)
4. **Discovery layer** (ENS / ERC-8004)

The SDK acts as the client transport and validation interface across these layers.

---

# Versioning

This SDK follows **Semantic Versioning**:

- Patch → bug fixes
- Minor → new verbs or backward-compatible changes
- Major → breaking changes

Commons schemas are versioned (`v1.0.0`) and stable.

---

# Developer Resources

- Quickstart → `QUICKSTART.md`
- Full Examples → `EXAMPLES.md`
- Deployment Guide → `DEPLOYMENT_GUIDE.md`
- Developer Architecture → `DEVELOPER_EXPERIENCE.md`
- Schemas → https://commandlayer.org/schemas
- Runtime Docs → https://commandlayer.org/runtime.html

---

# Philosophy

CommandLayer is not an AI model.

It is a **semantic contract layer**.

It standardizes:

- What an action means
- How it is executed
- How it is proven
- How it is verified

Receipts are not logs.

They are **cryptographic execution artifacts**.

---

# License

Commons SDK components are MIT licensed.

See `LICENSE` for details.

---

CommandLayer turns agent execution into verifiable infrastructure.

Build systems that can prove what they did.
