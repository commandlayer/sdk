# Verification

The SDK verification helper validates the current receipt contract directly.

For public paste-and-verify receipt verification, use VerifyAgent:
https://github.com/commandlayer/verifyagent

## Rules

1. Read the signed object from `receipt`.
2. Remove `metadata.receipt_id` and the signed hash/signature fields.
3. Canonicalize with `cl-stable-json-v1`.
4. Recompute `sha256`.
5. Compare the recomputed hash to `metadata.proof.hash_sha256`.
6. If `metadata.receipt_id` is present, treat equality to the proof hash as a compatibility / diagnostic check (not a hard requirement for `ok`).
7. Verify the Ed25519 signature over the UTF-8 hash string.

## Helpers

- `verify_receipt(receipt, public_key=...)`
- `verify_receipt(receipt, ens={"name": ..., "rpcUrl": ...})`
- `extract_receipt_verb(receipt_or_response)`
- `recompute_receipt_hash_sha256(receipt_or_response)`
