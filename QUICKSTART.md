# CommandLayer SDK Quickstart

Install. Call a verb. Get a signed receipt.

You can integrate CommandLayer in under 2 minutes.

---

## What is CommandLayer?

CommandLayer is the **semantic verb layer** for autonomous agents.

It provides:

- Standardized verbs (`summarize`, `analyze`, `classify`, etc.)
- Strict JSON request & receipt schemas
- Cryptographically signed receipts (Ed25519 + SHA-256)
- x402-compatible execution envelopes
- ERC-8004–aligned agent discovery

CommandLayer turns agent actions into **verifiable infrastructure**.

---

# 1️⃣ Install

## TypeScript / JavaScript

```bash
npm install @commandlayer/sdk
```

## Python

```bash
pip install commandlayer
```

---

# 2️⃣ Make Your First Call

## TypeScript

```ts
import { createClient } from "@commandlayer/sdk";

const client = createClient({
  actor: "my-app"
});

const receipt = await client.summarize({
  content: "CommandLayer makes agent actions structured and verifiable.",
  style: "bullet_points"
});

console.log(receipt.result.summary);
```

---

## Python

```python
from commandlayer import create_client

client = create_client(actor="my-app")

receipt = client.summarize(
    content="CommandLayer makes agent actions structured and verifiable.",
    style="bullet_points"
)

print(receipt.result["summary"])
```

---

## CLI

```bash
commandlayer summarize \
  --content "CommandLayer makes agent actions structured and verifiable." \
  --style bullet_points
```

---

# 3️⃣ What You Get Back

Every call returns a **signed receipt**, not just raw output.

```ts
receipt.status                 // "success"
receipt.metadata.receipt_id    // Deterministic receipt hash
receipt.trace.duration_ms      // Execution latency

receipt.result                 // Structured verb output

receipt.metadata.proof.hash_sha256
receipt.metadata.proof.signature_b64
receipt.metadata.proof.signer_id
receipt.metadata.proof.alg     // "ed25519-sha256"
```

Receipts are:

- Canonicalized
- Hashed (SHA-256)
- Signed (Ed25519)
- Verifiable independently

By default, the SDK verifies receipts automatically.

---

# 4️⃣ Available Verbs

The Commons SDK includes 10 verbs:

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

All verbs return structured, signed receipts.

---

# 5️⃣ Configuration

```ts
const client = createClient({
  actor: "my-production-app",
  runtime: "https://runtime.commandlayer.org", // default
  verifyReceipts: true                          // default
});
```

### Options

- `actor` — Identifier for your application or tenant
- `runtime` — Custom runtime base URL
- `verifyReceipts` — Enable/disable signature verification

---

# 6️⃣ Production Notes

- Always set a meaningful `actor`
- Keep `verifyReceipts` enabled in production
- Store `receipt_id` for audit trails
- Treat receipts as durable evidence, not logs

---

# 7️⃣ Verify a Receipt (Optional)

```ts
import { verifyReceipt } from "@commandlayer/sdk";

const ok = await verifyReceipt(receipt, {
  ens: true,
  rpcUrl: "https://mainnet.infura.io/v3/..."
});

console.log("Verified:", ok);
```

You can verify:

- With a provided public key (offline)
- By resolving signer pubkey from ENS
- Or disable verification entirely

---

# Next Steps

📖 Real-world usage → `EXAMPLES.md`  
🚀 Deployment & publishing → `DEPLOYMENT_GUIDE.md`  
🔍 SDK architecture → `DEVELOPER_EXPERIENCE.md`  
🌐 Full docs → https://commandlayer.org/docs.html  

---

CommandLayer turns agent execution into verifiable infrastructure.

You're ready to build.
