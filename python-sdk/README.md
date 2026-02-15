# CommandLayer Python SDK

Semantic verbs. Typed schemas. Signed receipts.

This package provides the official Python SDK for **CommandLayer Commons v1.0.0**.

Install → call a verb → receive a signed receipt → verify it.

---

## What is CommandLayer?

CommandLayer is the **semantic verb layer** for autonomous agents.

The SDK provides:

- Standardized Commons verbs (`summarize`, `analyze`, `fetch`, etc.)
- Strict JSON Schemas (requests + receipts)
- Cryptographically signed receipts (Ed25519 + SHA-256)
- Deterministic canonicalization (`cl-stable-json-v1`)
- Verification helpers (offline PEM or ENS-based)
- CLI-style patterns for reproducible testing

---

## Installation

```bash
pip install commandlayer
```

Python 3.10+ recommended.

---

## Quickstart
```
from commandlayer import create_client

client = create_client(
    actor="my-app",
    runtime="https://runtime.commandlayer.org",  # default
    verify_receipts=True,                        # default (recommended)
)

receipt = client.summarize(
    content="CommandLayer turns agent actions into verifiable receipts.",
    style="bullet_points",
)

print(receipt["status"])
print(receipt["result"]["summary"])
print(receipt["metadata"]["receipt_id"])
```
---

## Runtime configuration

Default runtime:

  - `https://runtime.commandlayer.org-

Override if needed:
```
from commandlayer import create_client

client = create_client(
    actor="my-app",
    runtime="https://your-runtime.example",
    verify_receipts=True,
    timeout_ms=30_000,
)
```
---

Keep `verify_receipts=True` in production.

---

## Receipt structure

Every call returns a signed receipt:
```
{
  "status": "success",
  "x402": {
    "verb": "summarize",
    "version": "1.0.0",
    "entry": "x402://summarizeagent.eth/summarize/v1.0.0"
  },
  "trace": {
    "trace_id": "trace_ab12cd34",
    "duration_ms": 118
  },
  "result": {
    "summary": "..."
  },
  "metadata": {
    "receipt_id": "8f0a...",
    "proof": {
      "alg": "ed25519-sha256",
      "canonical": "cl-stable-json-v1",
      "signer_id": "runtime.commandlayer.eth",
      "hash_sha256": "...",
      "signature_b64": "..."
    }
  }
}
```
Receipt guarantees:

- Stable canonical hashing over the unsigned receipt
- SHA-256 digest of canonical JSON
- Ed25519 signature over the hash
- Deterministic verification across runtimes

  ---
  
## Verifying receipts

**Option A — Offline verification (explicit public key PEM)**

Fastest method. No RPC required.
```
from commandlayer import verify_receipt

PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA7Vkkmt6R02Iltp/+i3D5mraZyvLjfuTSVB33KwfzQC8=
-----END PUBLIC KEY-----"""

out = verify_receipt(receipt, public_key_pem=PUBLIC_KEY_PEM)

print(out["ok"])
print(out["checks"])  # schema_valid (optional), hash_matches, signature_valid
```

**Option B — ENS-based verification**

Resolves the public key from ENS TXT records.

Required ENS records:

- `cl.receipt.pubkey_pem`
- `cl.receipt.signer_id`
- `cl.receipt.alg`

```
import os
from commandlayer import verify_receipt

out = verify_receipt(
    receipt,
    ens_name="runtime.commandlayer.eth",
    rpc_url=os.environ["ETH_RPC_URL"],
    ens_txt_key="cl.receipt.pubkey_pem",  # default
)

print(out["ok"])
print(out["values"]["pubkey_source"])  # "ens" when resolved
```

ENS affects verification correctness — not package build/publish.

---

## Commons verbs

All verbs return signed receipts.

**summarize**
```
receipt = client.summarize(
    content="Long text...",
    style="bullet_points",       # optional
    format="text",               # optional
    max_tokens=1000,             # optional
)
```

**analyze**
```
receipt = client.analyze(
    content="Data...",
    dimensions=["sentiment", "tone"],  # optional (runtime-dependent)
    max_tokens=1000,
)
```

**classify**
```
receipt = client.classify(
    content="Support message...",
    categories=["support", "billing"],  # optional (runtime-dependent)
    max_tokens=1000,
)
```

**clean**
```
receipt = client.clean(
    content=" a \r\n\r\n b ",
    operations=["trim", "normalize_newlines", "remove_empty_lines"],  # optional
    max_tokens=1000,
)
```
**convert**
```
receipt = client.convert(
    content='{"a":1,"b":2}',
    from_format="json",
    to_format="csv",
    max_tokens=1000,
)
```
**describe**
```
receipt = client.describe(
    subject="CommandLayer receipt",
    context="A receipt returned from the runtime...",
    detail_level="medium",   # brief|medium|detailed (runtime-dependent)
    audience="general",
    max_tokens=1000,
)
```
**explain**
```
receipt = client.explain(
    subject="x402 receipt verification",
    context="Explain what schema + hash + signature verification proves.",
    style="step-by-step",
    detail_level="medium",
    audience="general",
    max_tokens=1000,
)
```
**format**

```receipt = client.format(
    content="a: 1\nb: 2",
    target_style="table",  # runtime-dependent
    max_tokens=1000,
)
```
**parse**
```
receipt = client.parse(
    content='{"a":1}',
    content_type="json",     # json|yaml|text
    mode="strict",           # best_effort|strict
    target_schema=None,      # optional
    max_tokens=1000,
)
```
**fetch**
```
receipt = client.fetch(
    source="https://example.com",
    mode="text",              # text|html|json (runtime-dependent)
    query=None,
    include_metadata=False,
    max_tokens=1000,
)
```

## Local development

Typical workflow:

```
cd python-sdk
python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

pip install -U pip
pip install -e .
python -c "from commandlayer import create_client; print(create_client)"
```

Build a release:
```
pip install -U build twine
python -m build
```

Publish (optional):
```
twine upload dist/*
```
---

## Versioning + release discipline

Use SemVer:

- Patch: bug fixes (no API break)
- Minor: new verbs/options (backward compatible)
- Major: breaking changes

Release flow:

- Update `CHANGELOG.md`
- Bump version
- Build
- Smoke test a live call against runtime.commandlayer.org
- Publish

---

## Definition of Done

You’re “deployed” when:

- `pip install commandlayer` succeeds
- A verb call returns a valid receipt JSON
- Verification passes (offline or ENS-based)
- CI reproduces install + minimal smoke test

## License

MIT

CommandLayer turns agent actions into verifiable infrastructure.

Ship APIs that can prove what they did.








