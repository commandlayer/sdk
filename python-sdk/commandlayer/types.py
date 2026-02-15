from typing import Any, Literal, TypedDict


class VerifyChecks(TypedDict, total=False):
    hash_matches: bool
    signature_valid: bool
    receipt_id_matches: bool
    alg_matches: bool
    canonical_matches: bool


class VerifyValues(TypedDict, total=False):
    verb: str | None
    signer_id: str | None
    alg: str | None
    canonical: str | None
    claimed_hash: str | None
    recomputed_hash: str | None
    receipt_id: str | None
    pubkey_source: Literal["explicit", "ens"] | None
    ens_txt_key: str | None


class VerifyErrors(TypedDict, total=False):
    signature_error: str | None
    ens_error: str | None
    verify_error: str | None


class VerifyResult(TypedDict):
    ok: bool
    checks: VerifyChecks
    values: VerifyValues
    errors: VerifyErrors


Receipt = dict[str, Any]
