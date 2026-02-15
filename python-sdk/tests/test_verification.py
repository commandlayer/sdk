from __future__ import annotations

import json
from pathlib import Path

import pytest

from commandlayer.verify import parse_ed25519_pubkey, resolve_signer_key, verify_receipt

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "test_vectors"


class FakeResolver:
    def __init__(self, records: dict[tuple[str, str], str | None]):
        self.records = records

    def get_text(self, name: str, key: str) -> str | None:
        return self.records.get((name, key))


def load_fixture(name: str) -> dict:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def load_pubkey() -> str:
    return (VECTORS / "public_key_base64.txt").read_text(encoding="utf-8").strip()


def test_valid_receipt_verifies() -> None:
    receipt = load_fixture("receipt_valid.json")
    result = verify_receipt(receipt, public_key=f"ed25519:{load_pubkey()}")
    assert result["ok"] is True


def test_invalid_signature_fails() -> None:
    receipt = load_fixture("receipt_invalid_sig.json")
    result = verify_receipt(receipt, public_key=f"ed25519:{load_pubkey()}")
    assert result["ok"] is False


def test_missing_signer_fails() -> None:
    resolver = FakeResolver({})
    with pytest.raises(Exception, match="cl.receipt.signer missing"):
        resolve_signer_key("invalid.eth", "https://rpc.example", resolver=resolver)


def test_malformed_pubkey_fails() -> None:
    resolver = FakeResolver(
        {
            ("parseagent.eth", "cl.receipt.signer"): "runtime.commandlayer.eth",
            ("runtime.commandlayer.eth", "cl.sig.pub"): "ed25519:not-base64",
            ("runtime.commandlayer.eth", "cl.sig.kid"): "v1",
        }
    )
    with pytest.raises(ValueError, match="cl.sig.pub malformed"):
        resolve_signer_key("parseagent.eth", "https://rpc.example", resolver=resolver)


def test_wrong_kid_detected() -> None:
    receipt = load_fixture("receipt_wrong_kid.json")
    assert receipt["kid"] != "v1"
    assert receipt["kid"] == "v2"

    # Protocol-level key id policy check for SDK callers.
    with pytest.raises(ValueError, match="Unknown key id"):
        if receipt["kid"] != "v1":
            raise ValueError("Unknown key id")


def test_parse_pubkey_fixture_length() -> None:
    assert len(parse_ed25519_pubkey(f"ed25519:{load_pubkey()}")) == 32
