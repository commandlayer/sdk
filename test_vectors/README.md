# Test vectors

This directory contains shared receipt fixtures used by both SDKs and the parity check. The fixtures model the current Commons v1.1.0 receipt contract: `receipt` is canonical, `runtime_metadata` is unsigned, and the `x402` object is retained only as protocol metadata.

## Files

- `receipt_valid.json` — canonical valid receipt fixture.
- `receipt_valid_v1.json` — additional valid receipt fixture used for version compatibility checks.
- `receipt_invalid_sig.json` — receipt fixture with an invalid signature.
- `receipt_wrong_kid.json` — receipt fixture expected to fail verification after `kid` mutation changes the signed content.
- `receipt_malformed_pubkey.json` — receipt fixture paired with malformed ENS signer metadata scenarios.
- `public_key_base64.txt` — shared Ed25519 public key for explicit-key verification.
- `expected_hash.txt` — expected SHA-256 hash for canonical receipt hashing.
- `parity_manifest.json` — parity contract describing which fixtures must agree across SDKs.

## Parity validation

Run `node scripts/parity-check.mjs` from the repo root to verify that the TypeScript and Python SDKs:

- evaluate the same fixtures,
- recompute the same hashes,
- resolve signer identity consistently, and
- return the same verification pass/fail outcomes.
