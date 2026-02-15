# CommandLayer Python SDK

Semantic verbs. Signed receipts. Deterministic verification.

Official Python SDK for **CommandLayer Commons v1.0.0**.

## Installation

```bash
pip install commandlayer
```

Python 3.10+ is supported.

---

## Quickstart

```python
from commandlayer import create_client

client = create_client(
    actor="my-app",
    runtime="https://runtime.commandlayer.org",  # optional
)

receipt = client.summarize(
    content="CommandLayer turns agent actions into verifiable receipts.",
    style="bullet_points",
)

print(receipt["status"])
print(receipt["metadata"]["receipt_id"])
```

> `verify_receipts` is **off by default** (matching TypeScript SDK behavior).

---

## Client Configuration

```python
client = create_client(
    runtime="https://runtime.commandlayer.org",
    actor="my-app",
    timeout_ms=30_000,
    verify_receipts=True,
    verify={
        "public_key": "ed25519:7Vkkmt6R02Iltp/+i3D5mraZyvLjfuTSVB33KwfzQC8=",
        # or ENS:
        # "ens": {"name": "runtime.commandlayer.eth", "rpcUrl": "https://..."}
    },
)
```

### Verification options
- `verify["public_key"]`: explicit Ed25519 pubkey (`ed25519:<base64>`, `<base64>`, `0x<hex>`, `<hex>`)
- `verify["ens"]`: `{ "name": str, "rpcUrl": str, "pubkeyTextKey"?: str }`

---

## Supported Verbs

All verbs return a signed receipt.

```python
client.summarize(content="...", style="bullet_points")
client.analyze(content="...", goal="extract key risks")
client.classify(content="...", max_labels=5)
client.clean(content="...", operations=["trim", "normalize_newlines"])
client.convert(content='{"a":1}', from_format="json", to_format="csv")
client.describe(subject="x402 receipt", detail="medium")
client.explain(subject="receipt verification", style="step-by-step")
client.format(content="a: 1\nb: 2", to="table")
client.parse(content='{"a":1}', content_type="json", mode="strict")
client.fetch(source="https://example.com", include_metadata=True)
```

---

## Receipt Verification API

```python
from commandlayer import verify_receipt

result = verify_receipt(
    receipt,
    public_key="ed25519:7Vkkmt6R02Iltp/+i3D5mraZyvLjfuTSVB33KwfzQC8=",
)

print(result["ok"])
print(result["checks"])
```

ENS-based verification:

```python
result = verify_receipt(
    receipt,
    ens={
        "name": "runtime.commandlayer.eth",
        "rpcUrl": "https://mainnet.infura.io/v3/YOUR_KEY",
        "pubkeyTextKey": "cl.pubkey",
    },
)
```

---

## Development

```bash
cd python-sdk
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
```
