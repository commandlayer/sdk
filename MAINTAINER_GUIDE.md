# Maintainer Guide

This document is for maintainers changing SDK internals, fixtures, CI, or release mechanics. It is not for application developers using the SDK in their own projects; use `README.md`, `QUICKSTART.md`, or the package READMEs instead.

## Product rules this repo now enforces

1. **One receipt truth**: the signed canonical payload is `receipt`.
2. **Runtime metadata stays separate**: execution context lives in optional `runtime_metadata` and is not part of the receipt hash.
3. **One version story**: both published SDK packages track CommandLayer Commons v1.1.0 and are versioned at `1.1.0` in this repo.
4. **Compatibility is explicit**: SDK clients normalize older blended runtime responses, but docs only teach the current envelope.

## Repo structure

- `typescript-sdk/`: npm package, CLI, JS verification helpers.
- `python-sdk/`: PyPI package and Python verification helpers.
- `test_vectors/`: shared receipt fixtures used across SDKs.
- `runtime/tests/`: cross-SDK protocol checks run against the built TypeScript package.
- root docs: public landing page, quickstart, examples, contributor guide, versioning policy, and release guide.

## Shared protocol model

### Canonical receipt

The signed payload includes:
- `status`,
- `x402` verb metadata,
- `result` or `error`,
- `metadata.receipt_id`, and
- `metadata.proof` with `alg`, `canonical`, `signer_id`, `hash_sha256`, and `signature_b64`.

### Runtime metadata

Unsigned context can include:
- `trace_id`,
- timing fields,
- runtime provider metadata,
- request IDs.

Clients normalize runtime responses into:

```json
{
  "receipt": { "...": "canonical signed receipt" },
  "runtime_metadata": { "...": "optional unsigned context" }
}
```

## SDK parity expectations

The TypeScript and Python SDKs should stay aligned on:
- method names,
- request body shaping,
- default runtime URL,
- receipt verification semantics,
- ENS resolution flow,
- major error messages where practical,
- shared test vectors.

If one SDK intentionally diverges, document it in that package README and in release notes.

## Verification rules

Both SDKs use the same verification contract:
1. strip `receipt_id` and the signed hash/signature fields from the receipt,
2. canonicalize with `cl-stable-json-v1`,
3. recompute `sha256`,
4. compare against `metadata.proof.hash_sha256`,
5. verify the Ed25519 signature over the UTF-8 hash string,
6. resolve signer keys via ENS when an explicit key is not provided,
7. when a receipt carries `kid`, prefer the matching `cl.sig.pub.<kid>` record so older receipts still verify after key rotation.

## CLI rules

The npm package owns the only supported `commandlayer` CLI. The Python package does not ship a CLI.

The CLI should remain:
- installable with `npm install -g @commandlayer/sdk`,
- aligned with SDK examples,
- useful for CI smoke tests,
- capable of verifying saved receipts or full response envelopes.

## Test execution and ordering

`runtime/tests` import `typescript-sdk/dist/index.cjs`, so a fresh clone must build the TypeScript SDK before running runtime tests.

Use the root scripts to avoid hidden ordering requirements:

```bash
npm install
npm run test:full
```

`npm run test:full` runs the TypeScript install/build/tests, then the runtime tests against the built output.

## Maintenance checklist

When protocol versions change:
1. update package versions and protocol constants,
2. update root docs and per-package READMEs,
3. regenerate or update shared fixtures,
4. run both SDK test suites plus `runtime/tests`,
5. confirm release automation and `RELEASE_GUIDE.md` still match reality.
