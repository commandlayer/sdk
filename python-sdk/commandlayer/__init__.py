"""CommandLayer Python SDK."""

from .client import CommandLayerClient, create_client, normalize_command_response
from .errors import CommandLayerError
from .types import (
    CanonicalReceipt,
    CommandResponse,
    EnsVerifyOptions,
    RuntimeMetadata,
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
    "CanonicalReceipt",
    "CommandLayerClient",
    "CommandLayerError",
    "CommandResponse",
    "EnsVerifyOptions",
    "RuntimeMetadata",
    "VerifyOptions",
    "SignerKeyResolution",
    "VerifyResult",
    "canonicalize_stable_json_v1",
    "create_client",
    "normalize_command_response",
    "sha256_hex_utf8",
    "parse_ed25519_pubkey",
    "recompute_receipt_hash_sha256",
    "resolve_signer_key",
    "verify_receipt",
]

__version__ = "1.1.0"
