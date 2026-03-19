# Test vectors

## Categories

- **Canonical receipts**: known-good signed receipts such as `receipt_valid.json`, `receipt_valid_v1.json`, and `receipt_valid_v2.json`.
- **ENS resolution cases**: fixtures and runtime tests that cover missing signer TXT records, malformed public keys, and key lookup by `kid`.
- **Invalid signature cases**: fixtures such as `receipt_invalid_sig.json` that keep the receipt payload intact but break the signature.
- **Key rotation cases**: `public_key_v1_base64.txt`, `public_key_v2_base64.txt`, `receipt_valid_v1.json`, `receipt_valid_v2.json`, `receipt_wrong_kid.json`, and `receipt_removed_kid.json`.
- **Envelope vs receipt tests**: verification tests that pass both a canonical receipt and an envelope with top-level `receipt`.

## Naming rules

- Receipt fixtures are named for the behavior they test.
- ENS-specific malformed cases use `ens_...` prefixes instead of pretending the receipt itself is malformed.
- Rotation fixtures must include real key material and distinct signatures for each `kid`.
