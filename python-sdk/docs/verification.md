# Verification

The SDK verifies signed receipts using:

- canonical JSON: `cl-stable-json-v1`
- hash: `sha256` over unsigned receipt
- signature: `ed25519` over the hash string

## ENS key resolution flow

1. Resolve agent ENS TXT: `cl.receipt.signer`
2. Resolve signer ENS TXT: `cl.sig.pub`
3. Resolve signer ENS TXT: `cl.sig.kid`

Use `resolve_signer_key(name, rpc_url)` for direct key resolution.

## Programmatic verification

```python
from commandlayer import verify_receipt

result = verify_receipt(receipt, ens={"name": "summarizeagent.eth", "rpcUrl": "https://..."})
print(result["ok"])
```
