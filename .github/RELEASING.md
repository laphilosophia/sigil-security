# Releasing

This document is the practical release checklist for the current Sigil repository state.

## Current Package Maturity

Release posture is intentionally split:

- `@sigil-security/core`: production-candidate
- `@sigil-security/policy`: production-candidate
- `@sigil-security/runtime`: production-candidate
- `@sigil-security/client`: experimental
- `@sigil-security/ops`: experimental

That means a normal release can publish all packages, while `client` and `ops` continue to use their `experimental` npm tag until a later promotion decision.

## Pre-Release Checklist

Run these locally before cutting a release:

```bash
pnpm build
pnpm lint
pnpm typecheck
pnpm test
pnpm test:coverage
pnpm test:bench
node scripts/cross-runtime/core-smoke.mjs
```

Release should wait for:

- CI green on the Node matrix
- cross-runtime workflow green
- coverage thresholds satisfied
- any release-facing docs changes merged

## Changesets Flow

The repo uses Changesets for versioning.

Common flow:

1. Add or update a changeset for the packages affected by the release.
2. Merge to `main`.
3. Let the release workflow create or update the release PR.
4. Merge the release PR when versions and changelog output look correct.
5. The workflow publishes on `main`.

Relevant config:

- [Changesets config](../.changeset/config.json)
- [Release workflow](../.github/workflows/release.yml)

## Experimental Packages

`client` and `ops` currently publish with the `experimental` npm tag.

Promote them only when:

- package README and usage docs are stable enough for external users
- hosted CI evidence is consistently green
- release messaging is updated across root docs and package metadata
- the team is comfortable supporting the public API as non-experimental

## Recommended Release Notes Shape

For the next release, keep notes grouped like this:

- hardening and validation evidence
- runtime and adapter coverage improvements
- CI and release workflow improvements
- documentation and onboarding updates
- explicit note that `client` and `ops` remain experimental unless promotion is part of that release
