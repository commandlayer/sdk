# Deployment and Release Guide

This repo publishes two SDK packages from one protocol-aligned codebase:
- npm: `@commandlayer/sdk`
- PyPI: `commandlayer`

Current release line:
- SDK package version: `1.1.0`
- Supported protocol line: Protocol-Commons v1.1.0
- ENS / Agent-Card alignment: v1.1.0 signer-discovery flow

## 1. Preconditions

Before cutting a release:
- confirm both SDK packages are on the same version,
- confirm docs reference the same protocol version and receipt model,
- confirm shared test vectors still represent the current signed receipt truth and do not reintroduce x402-first positioning,
- decide whether the release is docs-only or publishable.

## 2. Local quality gates

### TypeScript SDK

```bash
cd typescript-sdk
npm ci
npm run typecheck
npm test
```

### Python SDK

```bash
cd python-sdk
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
ruff check .
mypy commandlayer
pytest
```

## 3. Packaging checks

### npm package

```bash
cd typescript-sdk
npm pack --dry-run
```

Verify that the tarball includes:
- `dist/index.cjs`
- `dist/index.mjs`
- `dist/index.d.ts`
- `dist/cli.cjs`
- `README.md`

### PyPI package

```bash
cd python-sdk
python -m build
python -m twine check dist/*
```

## 4. Publish flow

### npm

```bash
cd typescript-sdk
npm publish --access public
```

### PyPI

```bash
cd python-sdk
python -m build
python -m twine upload dist/*
```

## 5. Git and release metadata

Release steps:
1. merge the release branch,
2. create a git tag matching the SDK version, for example `sdk-v1.1.0`,
3. publish npm,
4. publish PyPI,
5. create GitHub release notes summarizing protocol line, SDK changes, and any migration notes.

Release notes should call out:
- supported protocol version,
- receipt model changes,
- verification API changes,
- runtime compatibility notes,
- any explicit legacy compatibility retained.

## 6. commandlayer.org coordination

If the public docs site references installation or verification examples, update it in the same release window so that:
- package versions match,
- receipt examples match the repo,
- verification examples use the same API shapes,
- CLI examples are reproducible.

## 7. CI expectations

CI should stay green for:
- TypeScript typecheck/build/package-local tests,
- Python lint/typecheck/tests,
- optional cross-SDK runtime fixture checks.

Do not publish if any of those lanes are red.
