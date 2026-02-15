import base64

from nacl.signing import SigningKey

from commandlayer.verify import parse_ed25519_pubkey, recompute_receipt_hash_sha256, verify_receipt


def test_verify_receipt_happy_path_explicit_public_key():
    receipt = {
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

    hash_out = recompute_receipt_hash_sha256(receipt)
    sk = SigningKey.generate()
    signature = sk.sign(hash_out["hash_sha256"].encode("utf-8")).signature

    receipt["metadata"]["proof"]["hash_sha256"] = hash_out["hash_sha256"]
    receipt["metadata"]["proof"]["signature_b64"] = base64.b64encode(signature).decode("utf-8")
    receipt["metadata"]["receipt_id"] = hash_out["hash_sha256"]

    pubkey_b64 = base64.b64encode(bytes(sk.verify_key)).decode("utf-8")

    out = verify_receipt(receipt, public_key=f"ed25519:{pubkey_b64}")
    assert out["ok"] is True
    assert out["checks"]["signature_valid"] is True
    assert out["checks"]["hash_matches"] is True


def test_parse_ed25519_pubkey_rejects_invalid_base64():
    import pytest

    with pytest.raises(Exception):
        parse_ed25519_pubkey("not_base64!!!")
