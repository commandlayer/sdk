# CommandLayer SDK Quickstart

## 1. Install

```bash
npm install @commandlayer/sdk
pip install commandlayer
```

## 2. Make one call

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

## 3. Verify the receipt

```ts
import { verifyReceipt } from "@commandlayer/sdk";
await verifyReceipt(response.receipt, { publicKey: "ed25519:BASE64_PUBLIC_KEY" });
```

```python
from commandlayer import verify_receipt
verify_receipt(response["receipt"], public_key="ed25519:BASE64_PUBLIC_KEY")
```

## 4. Remember the contract

- Persist `response.receipt`.
- Treat `response.runtime_metadata` as optional unsigned context.
- Treat `receipt.metadata.receipt_id` as the receipt hash identifier.
- Read the verb from `receipt.x402.verb`.
