# CommandLayer SDK Quickstart

Install. Call a verb. Get a signed receipt.

You can integrate CommandLayer in under 2 minutes.

---

## What is CommandLayer?

CommandLayer is the **semantic verb layer** for autonomous agents.

It provides:

- Standardized verbs (`summarize`, `analyze`, `classify`, etc.)
- Typed request/response schemas
- Cryptographically signed receipts
- x402-ready payment compatibility
- ERC-8004 aligned agent discovery

---

# 1️⃣ Install

### TypeScript / JavaScript

```bash
npm install @commandlayer/sdk
```
Python
```
pip install commandlayer
```

---

# 2️⃣ Make Your First Call

## TypeScript

```
import { createClient } from '@commandlayer/sdk';

const client = createClient({ actor: 'my-app' });

const result = await client.summarize({
  content: "CommandLayer makes agent actions structured and verifiable.",
  style: 'bullet_points'
});

console.log(result.result.summary);
```

## Python

```
from commandlayer import create_client

client = create_client(actor="my-app")

result = client.summarize(
    content="CommandLayer makes agent actions structured and verifiable.",
    style="bullet_points"
)

print(result.result["summary"])
```

## CLI
```
commandlayer summarize \
  --content "CommandLayer makes agent actions structured and verifiable." \
  --style bullet_points
```

---


# 3️⃣ What You Get Back

Every call returns a signed receipt.
```
result.status                 // 'success'
result.metadata.receipt_id    // Unique receipt ID
result.metadata.timestamp     // Processing time

result.result                 // The actual verb output

result.metadata.proof.hash_sha256
result.metadata.proof.signature_ed25519
result.metadata.proof.signer_id
```
Receipts are signed using Ed25519 and verified automatically by the SDK.

---


# 4️⃣ Available Verbs

The Commons SDK includes 10 verbs:

-summarize
-analyze
-classify
-clean
-convert
-describe
-explain
-format
-parse
-fetch

All verbs return structured, signed receipts.

---


# 5️⃣ Configuration
```
const client = createClient({
  actor: 'my-production-app',
  runtime: 'https://runtime.commandlayer.org', // default
  verifyReceipts: true                         // default
});
```
---


# 6️⃣ Production Notes

-Always set a meaningful actor
-Keep verifyReceipts enabled in production
-Store receipt_id for audit trails

## Next Steps

📖 See real-world examples → EXAMPLES.md

🚀 Deployment & publishing → DEPLOYMENT_GUIDE.md

🔍 Deep developer comparison → DEVELOPER_EXPERIENCE.md

🌐 Full documentation → https://commandlayer.org/docs.html


CommandLayer turns agent actions into verifiable infrastructure.

You're ready to build.


