# Client API

## Constructor

`CommandLayerClient(runtime, actor, timeout_ms, headers, retries, verify_receipts, verify)`

- `runtime`: Base runtime URL.
- `actor`: Default actor ID used in requests.
- `timeout_ms`: Request timeout.
- `headers`: Additional request headers.
- `retries`: Retry count for transport/timeout errors.
- `verify_receipts`: If true, verify every returned receipt.
- `verify`: Verification options (`public_key` / `ens`).

## Verbs

- `summarize`
- `analyze`
- `classify`
- `clean`
- `convert`
- `describe`
- `explain`
- `format`
- `parse`
- `fetch`

## Generic invoke

Use `client.call(verb, payload)` for full control.
