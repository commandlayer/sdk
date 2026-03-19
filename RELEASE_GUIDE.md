# Release Guide

This document is for maintainers publishing SDK releases and operating release automation. It is not for developers using the SDK in applications; use `README.md`, `QUICKSTART.md`, or `CONTRIBUTING.md` for local development and integration work.

This repo publishes two SDK packages from one protocol-aligned codebase:
- npm: `@commandlayer/sdk`
- PyPI: `commandlayer`

Current release line:
- SDK package version: `1.1.0`
- Supported protocol line: Protocol-Commons v1.1.0
- ENS / Agent-Card alignment: v1.1.0 signer-discovery flow

## 1. Release trigger

Releases are enforced by `.github/workflows/release.yml`. Publish from a signed tag or GitHub release; do not bypass the workflow with manual package uploads.

## 2. Preconditions

Before cutting a release:
- confirm both SDK packages are on the same version,
- confirm docs reference the same protocol version and receipt model,
- confirm shared test vectors still represent the current signed receipt truth,
- confirm npm and PyPI publish credentials are configured in GitHub Actions secrets.

## 3. Local quality gates

### Root scripts

```bash
npm install
npm run build
npm run test
npm run test:full
```

### Python SDK

```bash
cd python-sdk
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
python -m build
python -m twine check dist/*
pytest
```

## 4. Packaging checks

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

## 5. Automated publish flow

The release workflow must complete all of the following before publish succeeds:
1. install dependencies,
2. typecheck, build, and test the TypeScript SDK,
3. run the runtime protocol tests against built TypeScript output,
4. lint/typecheck/test the Python SDK,
5. build both packages,
6. validate artifacts,
7. publish to npm,
8. publish to PyPI.

Any failure blocks the release.

## 6. Git and release metadata

Release steps:
1. merge the release-ready changes,
2. create a git tag matching the SDK version, for example `sdk-v1.1.0`, or publish a GitHub release for that tag,
3. let GitHub Actions run the enforced release workflow,
4. verify the npm and PyPI publishes succeeded,
5. publish GitHub release notes summarizing protocol line, SDK changes, and migration notes.

Release notes should call out:
- supported protocol version,
- receipt model changes,
- verification API changes,
- runtime compatibility notes,
- any explicit legacy compatibility retained.

## 7. commandlayer.org coordination

If the public docs site references installation or verification examples, update it in the same release window so that:
- package versions match,
- receipt examples match the repo,
- verification examples use the same API shapes,
- CLI examples are reproducible.
