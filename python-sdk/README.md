# CommandLayer Python SDK

Current-line Python SDK for reusable CommandLayer receipt flows.

## Scope

This package is SDK-only and focuses on:
- receipt generation helpers,
- canonicalization,
- SHA-256 hashing,
- Ed25519 signing + verification,
- ENS key-resolution helpers,
- agent-wrapping utilities.

For public paste-and-verify receipt verification, use VerifyAgent:
https://github.com/commandlayer/verifyagent

## Install

```bash
pip install commandlayer
```

## Happy path

```python
from commandlayer import create_client, verify_receipt

client = create_client(actor="docs-example")
response = client.summarize(
    content="CommandLayer makes receipt verification explicit.",
    style="bullet_points",
)

verification = verify_receipt(
    response["receipt"],
    public_key="ed25519:BASE64_PUBLIC_KEY",
)
print(verification["ok"])
```

## Verification helpers

- `verify_receipt(receipt, public_key=...)`
- `verify_receipt(receipt, ens={"name": ..., "rpcUrl": ...})`
- `extract_receipt_verb(receipt_or_response)`
- `recompute_receipt_hash_sha256(receipt_or_response)`

## Boundary notes

- VerifyAgent is external and not part of this package/repository runtime surface.
- Commercial hosted runtime, x402, and indexing/dashboard product surfaces are outside the SDK package scope.
