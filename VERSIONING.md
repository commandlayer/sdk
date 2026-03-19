# Versioning Policy

## SemVer rules

This repo uses semantic versioning for both published SDK packages.

- **Major**: breaking API changes, breaking CLI behavior, breaking verification semantics, removal of documented compatibility behavior, or a required migration for supported integrations.
- **Minor**: new backwards-compatible SDK APIs, new CLI commands or flags, new protocol features that do not break existing integrations, or additive verification capabilities such as new resolver lookup paths.
- **Patch**: bug fixes, fixture corrections, documentation corrections, build fixes, and internal changes that do not change documented behavior.

## What counts as breaking

The following are breaking unless explicitly documented otherwise:
- removing or renaming public exports,
- changing request or response shapes returned by public SDK methods,
- changing receipt verification success or failure rules for existing valid receipts,
- removing CLI commands, flags, or output fields that users are told to depend on,
- dropping a supported Node.js or Python runtime version,
- changing normalization behavior in a way that breaks existing callers.

## SDK version vs protocol version

The SDK version is not the protocol version.

- Protocol compatibility is documented release-by-release in `README.md` and release notes.
- SDK minor or patch releases may still target the same protocol line.
- A protocol change that forces integration changes is treated as an SDK breaking change and requires a major SDK release.

## Minor vs patch guidance

Use a **minor** release when behavior expands but existing integrations keep working.

Use a **patch** release when correcting bugs, tightening docs, fixing fixtures, or repairing release/test discipline without changing documented public behavior.

## Legacy normalization policy

Legacy blended response normalization is compatibility-only.

- The canonical current contract is the response envelope with top-level `receipt` and optional `runtime_metadata`.
- Legacy normalization exists to avoid breaking older runtime payloads immediately.
- It is not a long-term guarantee that every historical response shape will remain supported forever.
- If legacy normalization is removed, that removal is a breaking change and requires a major release.
