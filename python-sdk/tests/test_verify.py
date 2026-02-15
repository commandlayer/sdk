from __future__ import annotations

import base64

import pytest
from nacl.signing import SigningKey

from commandlayer.verify import (
    parse_ed25519_pubkey,
    recompute_receipt_hash_sha256,
    resolve_signer_key,
    verify_receipt,
)


class FakeResolver:
    def __init__(self, records: dict[tuple[str, str], str | None]):
        self.records = records

    def get_text(self, name: str, key: str) -> str | None:
        return self.records.get((name, key))


def _signed_receipt() -> tuple[dict[str, object], str]:
    receipt: dict[str, object] = {
        "status": "success",
        "x402": {
            "verb": "summarize",
            "version": "1.0.0",
            "entry": "x402://summarizeagent.eth/summarize/v1.0.0",
        },
        "metadata": {
            "proof": {
                "alg": "ed25519-sha256",
                "canonical": "cl-stable-json-v1",
                "signer_id": "runtime.commandlayer.eth",
            }
        },
    }

    key = SigningKey.generate()
    h = recompute_receipt_hash_sha256(receipt)["hash_sha256"]
    sig = key.sign(h.encode("utf-8")).signature
    pub_b64 = base64.b64encode(bytes(key.verify_key)).decode("utf-8")

    metadata = receipt["metadata"]
    assert isinstance(metadata, dict)
    proof = metadata["proof"]
    assert isinstance(proof, dict)
    proof["hash_sha256"] = h
    proof["signature_b64"] = base64.b64encode(sig).decode("utf-8")
    metadata["receipt_id"] = h

    return receipt, pub_b64


def test_parse_ed25519_pubkey_supports_base64_and_hex() -> None:
    _, pub_b64 = _signed_receipt()
    parsed = parse_ed25519_pubkey(f"ed25519:{pub_b64}")
    assert len(parsed) == 32

    hex_key = parsed.hex()
    assert parse_ed25519_pubkey(hex_key) == parsed
    assert parse_ed25519_pubkey(f"0x{hex_key}") == parsed


def test_resolve_signer_key_two_hop_lookup() -> None:
    _, pub_b64 = _signed_receipt()
    resolver = FakeResolver(
        {
            ("summarizeagent.eth", "cl.receipt.signer"): "runtime.commandlayer.eth",
            ("runtime.commandlayer.eth", "cl.sig.pub"): f"ed25519:{pub_b64}",
            ("runtime.commandlayer.eth", "cl.sig.kid"): "2026-01",
        }
    )

    out = resolve_signer_key("summarizeagent.eth", "https://rpc.example", resolver=resolver)
    assert out.algorithm == "ed25519"
    assert out.kid == "2026-01"
    assert base64.b64encode(out.raw_public_key_bytes).decode("utf-8") == pub_b64


def test_resolve_signer_key_missing_fields_are_clear() -> None:
    resolver = FakeResolver({})
    with pytest.raises(ValueError, match="cl.receipt.signer missing"):
        resolve_signer_key("agent.eth", "https://rpc.example", resolver=resolver)


def test_verify_receipt_with_explicit_and_ens_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    receipt, pub_b64 = _signed_receipt()

    explicit = verify_receipt(receipt, public_key=f"ed25519:{pub_b64}")
    assert explicit["ok"] is True
    assert explicit["checks"]["signature_valid"] is True

    class Resolved:
        algorithm = "ed25519"
        kid = "2026-01"
        raw_public_key_bytes = parse_ed25519_pubkey(f"ed25519:{pub_b64}")

    monkeypatch.setattr(
        "commandlayer.verify.resolve_signer_key", lambda *_args, **_kwargs: Resolved()
    )

    ens_out = verify_receipt(
        receipt,
        ens={"name": "summarizeagent.eth", "rpcUrl": "https://rpc.example"},
    )
    assert ens_out["ok"] is True
    assert ens_out["values"]["pubkey_source"] == "ens"


def test_verify_receipt_rejects_tampered_receipt() -> None:
    receipt, pub_b64 = _signed_receipt()
    receipt["status"] = "error"

    out = verify_receipt(receipt, public_key=f"ed25519:{pub_b64}")
    assert out["ok"] is False
    assert out["checks"]["hash_matches"] is False
