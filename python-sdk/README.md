# CommandLayer Python SDK

Official Python SDK for CommandLayer Commons v1.1.0.

The Python package mirrors the TypeScript SDK's protocol model:
- client methods return `{ "receipt": ..., "runtime_metadata": ... }`,
- the signed `receipt` is the canonical verification payload,
- `runtime_metadata` is optional execution context, and
- verification can use an explicit Ed25519 key or ENS discovery.

Any `response["receipt"]["x402"]` block should be treated as legacy / commercial-only metadata rather than part of the Commons happy path in this repository.

## Install

```bash
pip install commandlayer
```

Supported Python versions: 3.10+.

## Quick start

```python
from commandlayer import create_client, verify_receipt

client = create_client(actor="docs-example")
response = client.summarize(
    content="CommandLayer makes agent execution verifiable.",
    style="bullet_points",
)

print(response["receipt"]["result"]["summary"])
print(response.get("runtime_metadata", {}).get("duration_ms"))

verification = verify_receipt(
    response["receipt"],
    public_key="ed25519:BASE64_PUBLIC_KEY",
)
print(verification["ok"])
```

## Verification

```python
result = verify_receipt(
    response["receipt"],
    ens={
        "name": "summarizeagent.eth",
        "rpcUrl": "https://mainnet.infura.io/v3/YOUR_KEY",
    },
)
```

## Development

```bash
cd python-sdk
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
ruff check .
mypy commandlayer
pytest
```
