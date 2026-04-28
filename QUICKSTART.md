# CommandLayer SDK Quickstart

## What this quickstart covers

SDK-only receipt flow:
1. Install SDK
2. Wrap agent execution
3. Generate signed receipt
4. Verify with SDK locally or VerifyAgent publicly
5. Move to Commercial API for hosted/high-volume verification

For public paste-and-verify receipt verification, use VerifyAgent:
https://github.com/commandlayer/verifyagent

## 1. Install

```bash
npm install @commandlayer/sdk
pip install commandlayer
```

## 2. Wrap agent execution

### TypeScript

```ts
import { createClient } from "@commandlayer/sdk";

const client = createClient({ actor: "quickstart-ts" });
const response = await client.summarize({
  content: "CommandLayer makes agent execution verifiable.",
  style: "bullet_points"
});

console.log(response.receipt.result?.summary);
console.log(response.receipt.metadata.receipt_id);
```

### Python

```python
from commandlayer import create_client

client = create_client(actor="quickstart-py")
response = client.summarize(
    content="CommandLayer makes agent execution verifiable.",
    style="bullet_points",
)

print(response["receipt"]["result"]["summary"])
print(response["receipt"]["metadata"]["receipt_id"])
```

## 3. Verify locally with SDK

### TypeScript

```ts
import { verifyReceipt } from "@commandlayer/sdk";
await verifyReceipt(response.receipt, { publicKey: "ed25519:BASE64_PUBLIC_KEY" });
```

### Python

```python
from commandlayer import verify_receipt
verify_receipt(response["receipt"], public_key="ed25519:BASE64_PUBLIC_KEY")
```

## 4. Verification options

- Local SDK verification: canonicalization + SHA-256 + Ed25519 signature checks.
- ENS-based key resolution: resolve signer keys via ENS helpers.
- Public verification UI: use external VerifyAgent repository.

## 5. Commercial upgrade path

Use CommandLayer Commercial when you need hosted runtime integrations, paid API/x402 flows, or high-volume verification infrastructure.
