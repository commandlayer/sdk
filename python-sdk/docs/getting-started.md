# Getting Started

## Install

```bash
pip install commandlayer
```

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
