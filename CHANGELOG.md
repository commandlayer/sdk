# Changelog

## [Unreleased]

- Separated VerifyAgent into its own public Commons/MIT repository. The SDK now focuses on receipt generation, canonicalization, hashing, signing, verification, ENS helpers, and agent-wrapping utilities. Public paste-and-verify UI is handled externally by VerifyAgent.

For public paste-and-verify receipt verification, use VerifyAgent:
https://github.com/commandlayer/verifyagent

## [1.1.0] - 2026-03-19

CommandLayer SDKs now align on the Commons-first Protocol-Commons v1.1.0 surface. This release replaces the mixed 1.0.0-era documentation and response assumptions with a single canonical receipt model shared by the TypeScript SDK, Python SDK, fixtures, and verification flow.

### What changed from 1.0.0
- Standardized on the canonical `{ receipt, runtime_metadata? }` wrapper and receipt-first verification flow across both SDKs.
- Aligned TypeScript and Python behavior, fixtures, and parity checks around the same v1.1.0 receipt hashing and verification semantics.
- Added TypeScript CLI support for the current Commons surface.

### Removed
- x402-first positioning from Commons-facing surfaces and release documentation. Commons is no longer presented as an x402-first product surface in this repo.
- Ambiguous blended response/documentation paths that implied multiple concurrent canonical envelopes.

### Breaking changes
- Consumers should treat the v1.1.0 wrapper and receipt shape as the only canonical public contract documented by this repository.
- Verification guidance now assumes the canonical receipt payload and current signer-discovery flow; integrations built around older mixed envelopes and payment-blended Commons payloads should update.

### Non-breaking improvements
- Improved cross-SDK parity coverage for hashing, signature verification, and signer resolution behavior.
- Clearer release alignment: Protocol-Commons v1.1.0 is the supported line for this repository and its published SDK packages.

### Known limitations / scope
- This repository is Commons-first and does not claim first-class commercial or x402 runtime coverage.
- The SDKs may still normalize some older blended runtime responses for compatibility, but those compatibility paths are not the canonical contract.
