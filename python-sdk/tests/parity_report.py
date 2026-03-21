from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any, cast

from commandlayer.verify import (
    parse_ed25519_pubkey,
    recompute_receipt_hash_sha256,
    resolve_signer_key,
    verify_receipt,
)

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "test_vectors"
MANIFEST = json.loads((VECTORS / "parity_manifest.json").read_text(encoding="utf-8"))
PUBLIC_KEY = f"ed25519:{(VECTORS / 'public_key_base64.txt').read_text(encoding='utf-8').strip()}"

ENS_FIXTURES: dict[str, dict[str, str]] = {
    "parseagent.eth": {"cl.receipt.signer": "runtime.commandlayer.eth"},
    "runtime.commandlayer.eth": {"cl.sig.pub": PUBLIC_KEY, "cl.sig.kid": "v1"},
    "invalidagent.eth": {},
    "malformed.eth": {"cl.receipt.signer": "malformed-signer.eth"},
    "malformed-signer.eth": {"cl.sig.pub": "ed25519:not-base64", "cl.sig.kid": "v1"},
}


class FakeResolver:
    def get_text(self, name: str, key: str) -> str | None:
        return ENS_FIXTURES.get(name, {}).get(key)


resolver = FakeResolver()


def load_fixture(name: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((VECTORS / name).read_text(encoding="utf-8")))


vector_results: list[dict[str, Any]] = []
for vector in MANIFEST["verification_vectors"]:
    receipt = load_fixture(vector["name"])
    verification = verify_receipt(receipt, public_key=PUBLIC_KEY)
    recomputed = recompute_receipt_hash_sha256(receipt)
    vector_results.append(
        {
            "name": vector["name"],
            "expected_ok": vector["expected_ok"],
            "ok": verification["ok"],
            "checks": verification["checks"],
            "values": verification["values"],
            "errors": verification["errors"],
            "recomputed_hash": recomputed["hash_sha256"],
        }
    )

ens_results: list[dict[str, Any]] = []
for case in MANIFEST["ens_resolution_cases"]:
    try:
        resolution = resolve_signer_key(case["name"], "https://rpc.example", resolver=resolver)
        signer_name = resolver.get_text(case["name"], "cl.receipt.signer")
        ens_results.append(
            {
                "name": case["name"],
                "ok": True,
                "algorithm": resolution.algorithm,
                "kid": resolution.kid,
                "signer_name": signer_name,
                "public_key_b64": base64.b64encode(resolution.raw_public_key_bytes).decode("utf-8"),
                "error": None,
            }
        )
    except Exception as exc:  # noqa: BLE001
        ens_results.append(
            {
                "name": case["name"],
                "ok": False,
                "algorithm": None,
                "kid": None,
                "signer_name": resolver.get_text(case["name"], "cl.receipt.signer"),
                "public_key_b64": None,
                "error": str(exc),
            }
        )

print(
    json.dumps(
        {
            "sdk": "python",
            "public_key_length": len(parse_ed25519_pubkey(PUBLIC_KEY)),
            "vector_results": vector_results,
            "ens_results": ens_results,
        },
        sort_keys=True,
        indent=2,
    )
)
