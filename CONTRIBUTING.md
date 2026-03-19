# Contributing

## Repo structure

- `typescript-sdk/` — npm package, CLI, and runtime-facing verification code.
- `python-sdk/` — PyPI package and Python verification code.
- `runtime/tests/` — cross-SDK tests that execute against `typescript-sdk/dist`.
- `test_vectors/` — shared fixtures for receipts, ENS cases, malformed inputs, and rotation cases.
- root docs — public usage docs plus maintainer/release policy docs.

## Install dependencies

```bash
npm install
cd python-sdk && pip install -e '.[dev]'
```

## Run TypeScript tests

```bash
npm run build
npm run test
```

## Run Python tests

```bash
cd python-sdk
pytest
```

## Run runtime tests without guessing about build order

```bash
npm run test:full
```

## `test_vectors/`

`test_vectors/` contains shared canonical receipts, ENS resolution cases, invalid signature cases, key rotation cases, and envelope-vs-receipt coverage used by both SDKs and the runtime tests.

## Pull requests

- keep changes scoped to the task,
- update shared docs and fixtures when behavior changes,
- run the relevant test commands before opening the PR,
- describe user-visible behavior changes and release impact clearly.

## Release rules

Release process and publish requirements live in `RELEASE_GUIDE.md`.
