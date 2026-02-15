from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from web3 import Web3

from .types import EnsVerifyOptions, Receipt, SignerKeyResolution, VerifyResult

_ED25519_PREFIX_RE = re.compile(r"^ed25519\s*[:=]\s*(.+)$", re.IGNORECASE)
_ED25519_HEX_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")


class EnsTextResolver(Protocol):
    def get_text(self, name: str, key: str) -> str | None: ...


class Web3EnsTextResolver:
    def __init__(self, rpc_url: str):
        self._w3 = Web3(Web3.HTTPProvider(rpc_url))

    def get_text(self, name: str, key: str) -> str | None:
        if not self._w3.is_connected():
            raise ValueError(f"Unable to connect to RPC: {self._w3.provider}")

        ens_module = self._w3.ens  # type: ignore[attr-defined]
        if ens_module is None:
            raise ValueError("ENS module is unavailable on this web3 instance")

        value = ens_module.get_text(name, key)  # type: ignore[union-attr]
        if value is None:
            return None

        text = str(value).strip()
        return text or None


def canonicalize_stable_json_v1(value: Any) -> str:
    def encode(v: Any) -> str:
        if v is None:
            return "null"

        value_type = type(v)

        if value_type is str:
            return json.dumps(v, ensure_ascii=False)
        if value_type is bool:
            return "true" if v else "false"

        if value_type in (int, float):
            if isinstance(v, float):
                if v != v or v in (float("inf"), float("-inf")):
                    raise ValueError("canonicalize: non-finite number not allowed")
                if v == 0.0 and str(v).startswith("-"):
                    return "0"
            return str(v)

        if value_type in (complex, bytes, bytearray):
            raise ValueError(f"canonicalize: unsupported type {value_type.__name__}")

        if isinstance(v, list):
            return "[" + ",".join(encode(item) for item in v) + "]"

        if isinstance(v, dict):
            out: list[str] = []
            for key in sorted(v.keys()):
                val = v[key]
                if val is ...:
                    raise ValueError(f'canonicalize: unsupported value for key "{key}"')
                out.append(f"{json.dumps(str(key), ensure_ascii=False)}:{encode(val)}")
            return "{" + ",".join(out) + "}"

        raise ValueError(f"canonicalize: unsupported type {value_type.__name__}")

    return encode(value)


def sha256_hex_utf8(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def parse_ed25519_pubkey(text: str) -> bytes:
    candidate = str(text).strip()
    match = _ED25519_PREFIX_RE.match(candidate)
    if match:
        candidate = match.group(1).strip()

    if _ED25519_HEX_RE.match(candidate):
        hex_part = candidate[2:] if candidate.startswith("0x") else candidate
        decoded = bytes.fromhex(hex_part)
        if len(decoded) != 32:
            raise ValueError("invalid ed25519 pubkey length")
        return decoded

    try:
        decoded = base64.b64decode(candidate, validate=True)
    except Exception as err:  # noqa: BLE001
        raise ValueError("invalid base64 in ed25519 pubkey") from err

    if len(decoded) != 32:
        raise ValueError("invalid base64 ed25519 pubkey length (need 32 bytes)")

    return decoded


def verify_ed25519_signature_over_utf8_hash_string(
    hash_hex: str,
    signature_b64: str,
    pubkey32: bytes,
) -> bool:
    if len(pubkey32) != 32:
        raise ValueError("ed25519: pubkey must be 32 bytes")

    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception as err:  # noqa: BLE001
        raise ValueError("ed25519: signature must be valid base64") from err

    if len(signature) != 64:
        raise ValueError("ed25519: signature must be 64 bytes")

    verify_key = VerifyKey(pubkey32)
    try:
        verify_key.verify(hash_hex.encode("utf-8"), signature)
        return True
    except BadSignatureError:
        return False


def resolve_signer_key(
    name: str,
    rpc_url: str,
    *,
    resolver: EnsTextResolver | None = None,
) -> SignerKeyResolution:
    if not rpc_url:
        raise ValueError("rpcUrl is required for ENS verification")

    txt_resolver = resolver or Web3EnsTextResolver(rpc_url)

    signer_name = txt_resolver.get_text(name, "cl.receipt.signer")
    if not signer_name:
        raise ValueError(f"ENS TXT cl.receipt.signer missing for agent ENS name: {name}")

    pub_key_text = txt_resolver.get_text(signer_name, "cl.sig.pub")
    if not pub_key_text:
        raise ValueError(f"ENS TXT cl.sig.pub missing for signer ENS name: {signer_name}")

    kid = txt_resolver.get_text(signer_name, "cl.sig.kid")
    if not kid:
        raise ValueError(f"ENS TXT cl.sig.kid missing for signer ENS name: {signer_name}")

    try:
        raw_public_key_bytes = parse_ed25519_pubkey(pub_key_text)
    except ValueError as err:
        raise ValueError(
            f"ENS TXT cl.sig.pub malformed for signer ENS name: {signer_name}. {err}"
        ) from err

    return SignerKeyResolution(
        algorithm="ed25519",
        kid=kid,
        raw_public_key_bytes=raw_public_key_bytes,
    )


def to_unsigned_receipt(receipt: Receipt) -> Receipt:
    if not isinstance(receipt, dict):
        raise ValueError("receipt must be an object")

    unsigned = copy.deepcopy(receipt)

    metadata = unsigned.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("receipt_id", None)

        proof = metadata.get("proof")
        if isinstance(proof, dict):
            unsigned_proof: dict[str, str] = {}
            for key in ("alg", "canonical", "signer_id"):
                value = proof.get(key)
                if isinstance(value, str):
                    unsigned_proof[key] = value
            metadata["proof"] = unsigned_proof

    unsigned.pop("receipt_id", None)
    return unsigned


def recompute_receipt_hash_sha256(receipt: Receipt) -> dict[str, str]:
    unsigned = to_unsigned_receipt(receipt)
    canonical = canonicalize_stable_json_v1(unsigned)
    return {"canonical": canonical, "hash_sha256": sha256_hex_utf8(canonical)}


def _extract_rpc_url(ens: EnsVerifyOptions) -> str:
    return str(ens.get("rpcUrl") or ens.get("rpc_url") or "")


def verify_receipt(
    receipt: Receipt,
    public_key: str | None = None,
    ens: EnsVerifyOptions | None = None,
) -> VerifyResult:
    try:
        proof = (
            ((receipt.get("metadata") or {}).get("proof") or {})
            if isinstance(receipt, dict)
            else {}
        )

        claimed_hash = (
            proof.get("hash_sha256") if isinstance(proof.get("hash_sha256"), str) else None
        )
        signature_b64 = (
            proof.get("signature_b64") if isinstance(proof.get("signature_b64"), str) else None
        )
        alg = proof.get("alg") if isinstance(proof.get("alg"), str) else None
        canonical = proof.get("canonical") if isinstance(proof.get("canonical"), str) else None
        signer_id = proof.get("signer_id") if isinstance(proof.get("signer_id"), str) else None

        alg_matches = alg == "ed25519-sha256"
        canonical_matches = canonical == "cl-stable-json-v1"

        recomputed_hash = recompute_receipt_hash_sha256(receipt)["hash_sha256"]
        hash_matches = bool(claimed_hash and claimed_hash == recomputed_hash)

        receipt_id_value: Any = None
        if isinstance(receipt, dict):
            metadata = receipt.get("metadata")
            if isinstance(metadata, dict):
                receipt_id_value = metadata.get("receipt_id")
            receipt_id_value = receipt_id_value or receipt.get("receipt_id")

        receipt_id = receipt_id_value if isinstance(receipt_id_value, str) else None
        receipt_id_matches = bool(claimed_hash and receipt_id == claimed_hash)

        pubkey: bytes | None = None
        pubkey_source: str | None = None
        ens_error: str | None = None
        ens_txt_key: str | None = None

        if public_key:
            pubkey = parse_ed25519_pubkey(public_key)
            pubkey_source = "explicit"
        elif ens:
            ens_txt_key = "cl.receipt.signer -> cl.sig.pub, cl.sig.kid"
            ens_name = ens.get("name")
            if not ens_name:
                ens_error = "ens.name is required"
            else:
                try:
                    signer_key = resolve_signer_key(ens_name, _extract_rpc_url(ens))
                    pubkey = signer_key.raw_public_key_bytes
                    pubkey_source = "ens"
                except Exception as err:  # noqa: BLE001
                    ens_error = str(err)

        signature_valid = False
        signature_error: str | None = None

        if not alg_matches:
            signature_error = f'proof.alg must be "ed25519-sha256" (got {alg})'
        elif not canonical_matches:
            signature_error = f'proof.canonical must be "cl-stable-json-v1" (got {canonical})'
        elif not claimed_hash or not signature_b64:
            signature_error = "missing proof.hash_sha256 or proof.signature_b64"
        elif not pubkey:
            signature_error = (
                ens_error or "no public key available (provide public_key/publicKey or ens)"
            )
        else:
            try:
                signature_valid = verify_ed25519_signature_over_utf8_hash_string(
                    claimed_hash,
                    signature_b64,
                    pubkey,
                )
            except Exception as err:  # noqa: BLE001
                signature_error = str(err)

        ok = (
            alg_matches
            and canonical_matches
            and hash_matches
            and receipt_id_matches
            and signature_valid
        )

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
                "verb": ((receipt.get("x402") or {}).get("verb"))
                if isinstance(receipt, dict)
                else None,
                "signer_id": signer_id,
                "alg": alg,
                "canonical": canonical,
                "claimed_hash": claimed_hash,
                "recomputed_hash": recomputed_hash,
                "receipt_id": receipt_id,
                "pubkey_source": pubkey_source,  # type: ignore[typeddict-item]
                "ens_txt_key": ens_txt_key,
            },
            "errors": {
                "signature_error": signature_error,
                "ens_error": ens_error,
                "verify_error": None,
            },
        }
    except Exception as err:  # noqa: BLE001
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
                "verb": ((receipt.get("x402") or {}).get("verb"))
                if isinstance(receipt, dict)
                else None,
                "signer_id": (
                    (((receipt.get("metadata") or {}).get("proof") or {}).get("signer_id"))
                    if isinstance(receipt, dict)
                    else None
                ),
                "alg": (
                    (((receipt.get("metadata") or {}).get("proof") or {}).get("alg"))
                    if isinstance(receipt, dict)
                    else None
                ),
                "canonical": (
                    (((receipt.get("metadata") or {}).get("proof") or {}).get("canonical"))
                    if isinstance(receipt, dict)
                    else None
                ),
                "claimed_hash": (
                    (((receipt.get("metadata") or {}).get("proof") or {}).get("hash_sha256"))
                    if isinstance(receipt, dict)
                    else None
                ),
                "recomputed_hash": None,
                "receipt_id": (
                    ((receipt.get("metadata") or {}).get("receipt_id"))
                    if isinstance(receipt, dict)
                    else None
                ),
                "pubkey_source": None,
                "ens_txt_key": None,
            },
            "errors": {
                "signature_error": None,
                "ens_error": None,
                "verify_error": str(err),
            },
        }
