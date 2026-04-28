# CommandLayer SDK

Official SDK repository for reusable CommandLayer receipt tooling.

## Scope of this repository

This repository is SDK-only. It focuses on:

- creating receipts,
- canonicalizing receipts,
- hashing receipts (SHA-256),
- signing receipts (Ed25519),
- verifying receipts (Ed25519 + receipt proof hash),
- ENS signer-resolution helpers, and
- utilities/examples for wrapping agent execution with CommandLayer receipts.

It does **not** contain the VerifyAgent product UI/demo app.

For public paste-and-verify receipt verification, use VerifyAgent:
https://github.com/commandlayer/verifyagent

## Architecture boundaries

- **CommandLayer SDK (this repo)**: local/developer receipt generation and verification building blocks.
- **VerifyAgent**: external public verifier (Commons/MIT) for paste-and-verify workflows.
- **CommandLayer Commercial**: hosted runtime, paid API, x402 flows, indexing, and dashboards.
- **Agent Cards**: identity/capability metadata used by agents and signer discovery.

## Developer flow

1. Install SDK.
2. Wrap agent execution.
3. Generate signed CommandLayer receipt.
4. Verify locally with SDK or publicly with VerifyAgent.
5. Upgrade to Commercial API for hosted/high-volume verification.

## Quick Start

```bash
npm install @commandlayer/sdk
```

```js
import { commandlayer } from "@commandlayer/sdk";

const receipt = await commandlayer.run("summarize", {
  text: "Agent receipts prove what happened."
});

const result = await commandlayer.verify(receipt);
console.log(result.valid);
```

## Start here

- Quickstart → `QUICKSTART.md`
- Full usage → `EXAMPLES.md`
- TypeScript package docs → `typescript-sdk/README.md`
- Python package docs → `python-sdk/README.md`
- Test vectors → `test_vectors/README.md`
- Changelog → `CHANGELOG.md`
