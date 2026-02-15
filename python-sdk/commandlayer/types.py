from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, TypedDict

Receipt = dict[str, Any]


class EnsVerifyOptions(TypedDict, total=False):
    """ENS options for receipt verification."""

    name: str
    rpc_url: str
    rpcUrl: str


class VerifyOptions(TypedDict, total=False):
    """Verification options for client-side receipt checks."""

    public_key: str
    publicKey: str
    ens: EnsVerifyOptions


class VerifyChecks(TypedDict):
    hash_matches: bool
    signature_valid: bool
    receipt_id_matches: bool
    alg_matches: bool
    canonical_matches: bool


class VerifyValues(TypedDict):
    verb: str | None
    signer_id: str | None
    alg: str | None
    canonical: str | None
    claimed_hash: str | None
    recomputed_hash: str | None
    receipt_id: str | None
    pubkey_source: Literal["explicit", "ens"] | None
    ens_txt_key: str | None


class VerifyErrors(TypedDict):
    signature_error: str | None
    ens_error: str | None
    verify_error: str | None


class VerifyResult(TypedDict):
    ok: bool
    checks: VerifyChecks
    values: VerifyValues
    errors: VerifyErrors


@dataclass(frozen=True)
class SignerKeyResolution:
    algorithm: Literal["ed25519"]
    kid: str
    raw_public_key_bytes: bytes
