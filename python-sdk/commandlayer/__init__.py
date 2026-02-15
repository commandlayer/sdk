"""CommandLayer Python SDK."""

from .client import CommandLayerClient, create_client
from .errors import CommandLayerError
from .types import (
    EnsVerifyOptions,
    Receipt,
    SignerKeyResolution,
    VerifyOptions,
    VerifyResult,
)
from .verify import (
    canonicalize_stable_json_v1,
    parse_ed25519_pubkey,
    recompute_receipt_hash_sha256,
    resolve_signer_key,
    sha256_hex_utf8,
    verify_receipt,
)

__all__ = [
    "CommandLayerClient",
    "create_client",
    "CommandLayerError",
    "EnsVerifyOptions",
    "VerifyOptions",
    "SignerKeyResolution",
    "Receipt",
    "VerifyResult",
    "canonicalize_stable_json_v1",
    "sha256_hex_utf8",
    "parse_ed25519_pubkey",
    "recompute_receipt_hash_sha256",
    "resolve_signer_key",
    "verify_receipt",
]

__version__ = "1.0.0"
