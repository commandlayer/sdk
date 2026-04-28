# Getting Started

## Install

```bash
pip install commandlayer
```

## Developer flow

1. Install SDK
2. Wrap agent execution
3. Generate signed CommandLayer receipt
4. Verify locally with SDK or publicly with VerifyAgent
5. Upgrade to Commercial API for hosted/high-volume verification

For public paste-and-verify receipt verification, use VerifyAgent:
https://github.com/commandlayer/verifyagent

## First request

```python
from commandlayer import create_client

client = create_client(actor="my-app")
response = client.summarize(content="Hello world", style="bullet_points")
print(response["receipt"]["status"])
```

## Verify receipts in production

```python
from commandlayer import CommandLayerClient

client = CommandLayerClient(
    verify_receipts=True,
    verify={
        "ens": {
            "name": "summarizeagent.eth",
            "rpcUrl": "https://mainnet.infura.io/v3/YOUR_KEY",
        }
    },
)
```
