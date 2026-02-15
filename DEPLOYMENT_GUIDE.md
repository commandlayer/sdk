# CommandLayer SDK — Deployment Guide

This repo ships **client SDKs + a CLI**. “Deploy” here means: build artifacts, run smoke tests, and (optionally) publish packages.

Repo layout (current intent):
- `typescript-sdk/` → npm package + CLI (`commandlayer`)
- `python-sdk/` → PyPI package + CLI (optional)
- `GsCommand/` → optional wrapper / legacy tooling (only if you’re using it)

---

## 0) Prereqs (do this first)

### Node / npm (TypeScript SDK)
- Node: **LTS recommended** (Node 20.x is the safe default).
  - Your logs show Node **22.20.0**. It can work, but if Windows native deps act up (esbuild), use Node 20 LTS.
- npm: comes with Node.
- Git: installed.

### Python (Python SDK)
- Python 3.10+ recommended.
- `pip`, `venv`.

### Windows-specific notes (your exact errors)
You hit:
- `EBUSY` on `esbuild.exe` during install
- `'tsup' is not recognized`

That combination usually means:
1) `npm install` didn’t complete, so dev deps (tsup) never installed.
2) Windows locked a file in `node_modules` (Defender, indexing, or a stale node process).

**Fix path (Windows):**
- Close any running node processes using the repo (VSCode terminals too).
- Add your repo folder to Windows Defender exclusions (at least `typescript-sdk/node_modules`).
- Then clean and reinstall (see section 2).

---

## 1) Environment variables (only if needed)

Most SDK work doesn’t require env vars. You only need them if you’re calling a live runtime or verifying receipts.

Common:
- `COMMANDLAYER_RUNTIME_BASE_URL=https://runtime.commandlayer.org`
- `COMMANDLAYER_VERIFY_URL=https://runtime.commandlayer.org/verify` (or your Vercel proxy `/api/verify-receipt`)

If you’re doing ENS-based pubkey verification server-side:
- `ETH_RPC_URL=...`
- `VERIFIER_ENS_NAME=runtime.commandlayer.eth`
- `ENS_PUBKEY_TEXT_KEY=cl.receipt.pubkey_pem` *(match your ENS TXT key exactly)*

> SDK build itself does **not** depend on ENS TXT records. ENS only matters for runtime receipt verification logic.

---

## 2) TypeScript SDK — Build + smoke test

### A) Clean install (recommended when Windows breaks)
From repo root:
```bash
cd typescript-sdk

# hard clean
rmdir /s /q node_modules 2>nul || true
del package-lock.json 2>nul || true

# clear npm cache (optional but helps)
npm cache verify

# install
npm install

## If esbuild still throws EBUSY

- Run the terminal as **Administrator**
- Temporarily disable real-time protection or add Windows Defender exclusions
- Retry:

```bash
npm install
```

---

## B) Build

```bash
npm run build
```

### Expected output

- `dist/index.js` (CJS + ESM depending on config)
- `dist/index.d.ts` (types)

If you see:

```
'tsup' is not recognized
```

That means `npm install` did not finish.  
Re-run the clean install process until dependencies install successfully.

---

## C) CLI smoke test (local)

Your CLI is intended to import from `dist/`.

```bash
node bin/cli.js summarize --content "test" --style bullet_points --json
```

### If CLI fails with syntax errors

- Ensure `bin/cli.js` is valid JS (no stray template string quoting bugs)
- Ensure it requires:

```js
require("../dist/index.js")
```

And that `dist/` exists after build.

---

## D) Optional: link CLI globally for local testing

Inside `typescript-sdk/`:

```bash
npm link
commandlayer --help
commandlayer summarize --content "test" --style bullet_points
```

### To unlink

```bash
npm unlink -g @commandlayer/sdk || true
```

---

# 3) TypeScript SDK — Publish to npm (optional)

You have two sane approaches.

---

## Option 1: Publish from `typescript-sdk/` as its own package

Best if `typescript-sdk` is a standalone npm package directory.

### Checklist

`typescript-sdk/package.json` must include:

- `"name": "@commandlayer/sdk"` (or your chosen scope)
- `"version": "x.y.z"`
- `"main"` and/or `"exports"` pointing at `dist/*`
- `"types"` pointing at `dist/index.d.ts`
- `"bin"` pointing at `bin/cli.js` (if publishing CLI)
- `"files"` field including:
  - `dist/`
  - `bin/`

### Publish

```bash
npm login
npm publish --access public
```

---

## Option 2: Root publishes multiple packages (monorepo)

Only do this if you’ve set up workspaces + a release tool.

Common tools:

- npm workspaces + changesets
- pnpm + changesets
- lerna (less preferred)

If you’re not already using these, don’t introduce them yet.

---

# 4) Python SDK — Build + publish (optional)

## A) Setup venv and install

```bash
cd python-sdk
python -m venv .venv
```

Windows:

```bash
.venv\Scripts\activate
```

macOS / Linux:

```bash
source .venv/bin/activate
```

Then:

```bash
pip install -U pip build twine
pip install -e .
```

---

## B) Build

```bash
python -m build
```

---

## C) Publish

```bash
twine upload dist/*
```

---

# 5) GitHub Actions (recommended)

Minimal CI for `typescript-sdk/` should:

- install
- build
- run CLI smoke test

### Example workflow  
`.github/workflows/typescript-sdk.yml`

```yaml
name: typescript-sdk

on:
  push:
    branches: [ main ]
  pull_request:

jobs:
  build:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: typescript-sdk
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
          cache: "npm"
          cache-dependency-path: typescript-sdk/package-lock.json
      - run: npm ci
      - run: npm run build
      - run: node bin/cli.js summarize --content "test" --style bullet_points --json
```

If you want publish-on-tag later, add a separate job gated on Git tags.

---

# 6) Versioning + release discipline

Use **SemVer**:

- Patch → bug fixes (no API break)
- Minor → new verbs / options (backward compatible)
- Major → breaking API changes

### Recommended release steps

1. Update `CHANGELOG.md`
2. Bump version:

```bash
npm version patch
# or
npm version minor
# or
npm version major
```

3. Build
4. Smoke test CLI
5. Tag + push
6. Publish

---

# 7) ENS TXT records — do they affect SDK deployment?

No. Not for building or publishing.

They affect:

- Runtime receipt verification (“resolve pubkey from ENS”)
- Cross-verification tooling

If your SDK includes a `verifyReceipt()` helper that can:

- Verify with an explicit pubkey (offline)
- OR resolve pubkey from ENS (requires RPC)

Then ENS records affect verification correctness — not build or release.

### Your current ENS records

```
cl.receipt.pubkey_pem = PEM (escaped newlines)
cl.receipt.signer_id = runtime.commandlayer.eth
cl.receipt.alg = ed25519
```

That’s the correct structure for “ENS as pubkey directory.”

---

# 8) Known pitfalls (save yourself time)

## Windows esbuild EBUSY

Symptoms:
- Install fails

Fix:
- Add Defender exclusion
- Close processes holding `node_modules`
- Delete `node_modules` and reinstall

---

## CLI shebang on Windows

```bash
#!/usr/bin/env node
```

This is fine. Windows ignores it; npm shim handles execution.

Ensure `package.json` includes:

```json
"bin": {
  "commandlayer": "bin/cli.js"
}
```

---

## Don’t run CLI before build

CLI requires:

```
../dist/index.js
```

Always build first.

---

# 9) “Definition of Done” for SDK deployment

You’re deployed when:

- `npm install` succeeds cleanly
- `npm run build` produces `dist/`
- `node bin/cli.js summarize ...` returns receipt JSON without crashing
- CI runs the same steps on push/PR

---

If you want, paste your `typescript-sdk/package.json` and I’ll rewrite it so `dist/` and `bin/` publish cleanly and the CLI installs as `commandlayer` without hacks.

