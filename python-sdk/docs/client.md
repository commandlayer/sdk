# Client API

## Constructor

`CommandLayerClient(runtime, actor, timeout_ms, headers, retries, verify_receipts, verify)`

## Current contract rules

- Client methods return `{ "receipt": ..., "runtime_metadata": ... }`.
- `receipt` is the signed artifact.
- `runtime_metadata` is optional and unsigned.
- `receipt.metadata.receipt_id` is the receipt hash identifier.
- `receipt.x402.verb` is the canonical verb field.

## Request construction

Use verb helpers for the normal Commons path. For low-level request shaping, use:

- `build_commons_request(verb, body, actor=...)`
- `build_commercial_request(verb, body, actor=..., payment=...)`

The commercial builder is isolated from the Commons client happy path on purpose.
