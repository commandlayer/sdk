# CommandLayer Python SDK

Current-line Python SDK for the CommandLayer Commons receipt contract (`1.1.0`).

## Canonical contract

- `response["receipt"]` is the signed receipt.
- `response.get("runtime_metadata")` is optional unsigned runtime context.
- `response["receipt"]["metadata"]["receipt_id"]` is the receipt hash identifier.
- `response["receipt"]["x402"]["verb"]` is the canonical verb field.

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

print(response["receipt"]["metadata"]["receipt_id"])
print(response["receipt"]["x402"]["verb"])

verification = verify_receipt(
    response["receipt"],
    public_key="ed25519:BASE64_PUBLIC_KEY",
)
print(verification["ok"])
```

## Explicit request builders

```python
from commandlayer import build_commons_request, build_commercial_request

commons = build_commons_request(
    "summarize",
    {
        "input": {"content": "hello", "summary_style": "bullet_points"},
        "limits": {"max_output_tokens": 400},
    },
    actor="docs-example",
)

commercial = build_commercial_request(
    "summarize",
    {"input": {"content": "hello"}},
    actor="docs-example",
    payment={"scheme": "x402", "quote_id": "quote_123"},
)
```

Commercial request shaping is deliberately isolated from the Commons client happy path.

## Verification helpers

- `verify_receipt(receipt, public_key=...)`
- `verify_receipt(receipt, ens={"name": ..., "rpcUrl": ...})`
- `extract_receipt_verb(receipt_or_response)`
- `recompute_receipt_hash_sha256(receipt_or_response)`

## Legacy support

`normalize_command_response()` still accepts older blended payloads with top-level `trace` and rewrites them to the canonical envelope. That is compatibility-only.
