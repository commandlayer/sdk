from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, TypedDict

CanonicalReceipt = dict[str, Any]


class RuntimeMetadata(TypedDict, total=False):
    trace_id: str
    parent_trace_id: str | None
    started_at: str
    completed_at: str
    duration_ms: int
    provider: str
    runtime: str
    request_id: str


class CommandResponse(TypedDict, total=False):
    receipt: CanonicalReceipt
    runtime_metadata: RuntimeMetadata


class EnsVerifyOptions(TypedDict, total=False):
    name: str
    rpc_url: str
    rpcUrl: str


class VerifyOptions(TypedDict, total=False):
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
