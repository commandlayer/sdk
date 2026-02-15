import base64
import copy
import hashlib
import json
import re
from typing import Any, Literal

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from web3 import Web3

from .types import Receipt, VerifyResult


def canonicalize_stable_json_v1(value: Any) -> str:
    def encode(v: Any) -> str:
        if v is None:
            return "null"
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, str):
            return json.dumps(v, ensure_ascii=False)
        if isinstance(v, (int, float)):
            if isinstance(v, float):
                if v != v or v in (float("inf"), float("-inf")):
                    raise ValueError("canonicalize: non-finite number not allowed")
                if v == 0.0 and str(v).startswith("-"):
                    return "0"
            return format(v, "g") if isinstance(v, float) else str(v)
        if isinstance(v, list):
            return "[" + ",".join(encode(x) for x in v) + "]"
        if isinstance(v, dict):
            out = []
            for k in sorted(v.keys()):
                val = v[k]
                out.append(f"{json.dumps(str(k), ensure_ascii=False)}:{encode(val)}")
            return "{" + ",".join(out) + "}"
        raise ValueError(f"canonicalize: unsupported type {type(v).__name__}")

    return encode(value)


def sha256_hex_utf8(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def parse_ed25519_pubkey(text: str) -> bytes:
    s = str(text).strip()
    match = re.match(r"^ed25519\s*[:=]\s*(.+)$", s, re.IGNORECASE)
    candidate = (match.group(1) if match else s).strip()

    if re.match(r"^(0x)?[0-9a-fA-F]{64}$", candidate):
        h = candidate[2:] if candidate.startswith("0x") else candidate
        return bytes.fromhex(h)

    decoded = base64.b64decode(candidate, validate=True)
    if len(decoded) != 32:
        raise ValueError("invalid base64 ed25519 pubkey length (need 32 bytes)")
    return decoded


def verify_ed25519_signature_over_utf8_hash_string(hash_hex: str, signature_b64: str, pubkey32: bytes) -> bool:
    if len(pubkey32) != 32:
        raise ValueError("ed25519: pubkey must be 32 bytes")
    sig = base64.b64decode(signature_b64)
    if len(sig) != 64:
        raise ValueError("ed25519: signature must be 64 bytes")

    vk = VerifyKey(pubkey32)
    try:
        vk.verify(hash_hex.encode("utf-8"), sig)
        return True
    except BadSignatureError:
        return False


def resolve_ens_ed25519_pubkey(name: str, rpc_url: str, pubkey_text_key: str = "cl.pubkey") -> dict[str, Any]:
    if not rpc_url:
        return {"pubkey": None, "source": None, "error": "rpcUrl is required for ENS verification", "txt_key": pubkey_text_key}
    try:
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        if not w3.is_connected():
            return {"pubkey": None, "source": None, "error": "Unable to connect to RPC", "txt_key": pubkey_text_key}

        try:
            ens_module = w3.ens  # type: ignore[attr-defined]
            if ens_module is None:
                return {"pubkey": None, "source": None, "error": "ENS module not available", "txt_key": pubkey_text_key}
            txt = ens_module.get_text(name, pubkey_text_key)  # type: ignore[union-attr]
        except Exception as err:
            return {"pubkey": None, "source": None, "error": f"ENS TXT lookup failed: {err}", "txt_key": pubkey_text_key}

        if not txt:
            return {"pubkey": None, "source": None, "error": f"ENS TXT {pubkey_text_key} missing", "txt_key": pubkey_text_key}

        pubkey = parse_ed25519_pubkey(str(txt).strip())
        return {"pubkey": pubkey, "source": "ens", "txt_key": pubkey_text_key, "txt_value": txt}
    except Exception as err:
        return {"pubkey": None, "source": None, "error": str(err), "txt_key": pubkey_text_key}


def to_unsigned_receipt(receipt: Receipt) -> Receipt:
    if not isinstance(receipt, dict):
        raise ValueError("receipt must be an object")

    r = copy.deepcopy(receipt)

    metadata = r.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("receipt_id", None)

        proof = metadata.get("proof")
        if isinstance(proof, dict):
            unsigned_proof = {}
            for key in ("alg", "canonical", "signer_id"):
                if isinstance(proof.get(key), str):
                    unsigned_proof[key] = proof[key]
            metadata["proof"] = unsigned_proof

    r.pop("receipt_id", None)
    return r


def recompute_receipt_hash_sha256(receipt: Receipt) -> dict[str, str]:
    unsigned = to_unsigned_receipt(receipt)
    canonical = canonicalize_stable_json_v1(unsigned)
    hash_sha256 = sha256_hex_utf8(canonical)
    return {"canonical": canonical, "hash_sha256": hash_sha256}


def verify_receipt(receipt: Receipt, public_key: str | None = None, ens: dict[str, Any] | None = None) -> VerifyResult:
    try:
        proof = ((receipt.get("metadata") or {}).get("proof") or {}) if isinstance(receipt, dict) else {}

        claimed_hash = proof.get("hash_sha256") if isinstance(proof.get("hash_sha256"), str) else None
        signature_b64 = proof.get("signature_b64") if isinstance(proof.get("signature_b64"), str) else None
        alg = proof.get("alg") if isinstance(proof.get("alg"), str) else None
        canonical = proof.get("canonical") if isinstance(proof.get("canonical"), str) else None
        signer_id = proof.get("signer_id") if isinstance(proof.get("signer_id"), str) else None

        alg_matches = alg == "ed25519-sha256"
        canonical_matches = canonical == "cl-stable-json-v1"

        recomputed_hash = recompute_receipt_hash_sha256(receipt)["hash_sha256"]
        hash_matches = bool(claimed_hash and claimed_hash == recomputed_hash)

        metadata = receipt.get("metadata") if isinstance(receipt.get("metadata"), dict) else {}
        assert isinstance(metadata, dict)  # narrowing for mypy; always true given the guard above
        receipt_id = metadata.get("receipt_id") or receipt.get("receipt_id")
        receipt_id = receipt_id if isinstance(receipt_id, str) else None
        receipt_id_matches = bool(claimed_hash and receipt_id == claimed_hash)

        pubkey: bytes | None = None
        pubkey_source: Literal["explicit", "ens"] | None = None
        ens_error: str | None = None
        ens_txt_key: str | None = None

        if public_key:
            pubkey = parse_ed25519_pubkey(public_key)
            pubkey_source = "explicit"
        elif ens:
            ens_rpc_url = ens.get("rpcUrl") or ens.get("rpc_url") or ""
            res = resolve_ens_ed25519_pubkey(
                name=ens["name"],
                rpc_url=str(ens_rpc_url),
                pubkey_text_key=ens.get("pubkeyTextKey") or ens.get("pubkey_text_key") or "cl.pubkey",
            )
            ens_txt_key = res.get("txt_key")
            if not res.get("pubkey"):
                ens_error = res.get("error") or "ENS pubkey not found"
            else:
                pubkey = res["pubkey"]
                pubkey_source = "ens"

        signature_valid = False
        signature_error = None

        if not alg_matches:
            signature_error = f'proof.alg must be "ed25519-sha256" (got {alg})'
        elif not canonical_matches:
            signature_error = f'proof.canonical must be "cl-stable-json-v1" (got {canonical})'
        elif not claimed_hash or not signature_b64:
            signature_error = "missing proof.hash_sha256 or proof.signature_b64"
        elif not pubkey:
            signature_error = ens_error or "no public key available (provide public_key/publicKey or ens)"
        else:
            try:
                signature_valid = verify_ed25519_signature_over_utf8_hash_string(claimed_hash, signature_b64, pubkey)
            except Exception as err:
                signature_valid = False
                signature_error = str(err)

        ok = alg_matches and canonical_matches and hash_matches and receipt_id_matches and signature_valid

        return {
            "ok": ok,
            "checks": {
                "hash_matches": hash_matches,
                "signature_valid": signature_valid,
                "receipt_id_matches": receipt_id_matches,
                "alg_matches": alg_matches,
                "canonical_matches": canonical_matches,
            },
            "values": {
                "verb": (((receipt.get("x402") or {}).get("verb")) if isinstance(receipt, dict) else None),
                "signer_id": signer_id,
                "alg": alg,
                "canonical": canonical,
                "claimed_hash": claimed_hash,
                "recomputed_hash": recomputed_hash,
                "receipt_id": receipt_id,
                "pubkey_source": pubkey_source,
                "ens_txt_key": ens_txt_key,
            },
            "errors": {
                "signature_error": signature_error,
                "ens_error": ens_error,
                "verify_error": None,
            },
        }
    except Exception as err:
        return {
            "ok": False,
            "checks": {
                "hash_matches": False,
                "signature_valid": False,
                "receipt_id_matches": False,
                "alg_matches": False,
                "canonical_matches": False,
            },
            "values": {
                "verb": ((receipt.get("x402") or {}).get("verb")) if isinstance(receipt, dict) else None,
                "signer_id": ((((receipt.get("metadata") or {}).get("proof") or {}).get("signer_id")) if isinstance(receipt, dict) else None),
                "alg": ((((receipt.get("metadata") or {}).get("proof") or {}).get("alg")) if isinstance(receipt, dict) else None),
                "canonical": ((((receipt.get("metadata") or {}).get("proof") or {}).get("canonical")) if isinstance(receipt, dict) else None),
                "claimed_hash": ((((receipt.get("metadata") or {}).get("proof") or {}).get("hash_sha256")) if isinstance(receipt, dict) else None),
                "recomputed_hash": None,
                "receipt_id": (((receipt.get("metadata") or {}).get("receipt_id")) if isinstance(receipt, dict) else None),
                "pubkey_source": None,
                "ens_txt_key": None,
            },
            "errors": {
                "signature_error": None,
                "ens_error": None,
                "verify_error": str(err),
            },
        }
