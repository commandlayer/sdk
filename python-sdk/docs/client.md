# Client API

## Constructor

`CommandLayerClient(runtime, actor, timeout_ms, headers, retries, verify_receipts, verify)`

- `runtime`: Runtime base URL. Defaults to `https://runtime.commandlayer.org`.
- `actor`: Actor ID attached to requests.
- `timeout_ms`: Request timeout in milliseconds.
- `headers`: Additional headers.
- `retries`: Retry count for transport and timeout failures.
- `verify_receipts`: Verify every returned canonical receipt before returning.
- `verify`: Verification options (`public_key`/`publicKey` or `ens`).

## Return shape

Every verb method returns:

```python
{
  "receipt": {...},
  "runtime_metadata": {...},  # optional
}
```

`receipt` is the canonical signed payload. `runtime_metadata` is execution context and is not part of the signed receipt hash.

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
