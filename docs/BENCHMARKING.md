# Benchmarking

This repository currently exposes a focused benchmark harness for `@sigil-security/core`.

## Run

```bash
pnpm run test:bench
```

or directly:

```bash
pnpm run test:bench:core
```

## Current Scope

The first benchmark pass intentionally measures only the cryptographic hot path:

- base64url encode / decode
- HMAC sign / verify
- HKDF key derivation (warm cache and cold derivation reference)
- token generation
- token validation
- one-shot token validation
- action hashing

## Performance Targets

These targets come from Phase 6 in `docs/IMPLEMENTATION_PLAN.md`:

- Token generation: `< 100µs`
- Token validation: `< 50µs`
- HMAC sign/verify: `< 30µs`
- HKDF key derivation: `< 50µs`
- One-shot validation: `< 80µs`
- base64url encode/decode: `< 5µs`

## Current Baseline

Measured locally with `pnpm run test:bench` on the current Node 18+ toolchain:

| Operation | Target | Baseline | Status |
| --------- | ------ | -------- | ------ |
| Token generation | `< 100µs` | `66.4µs` | Meets target |
| Token validation | `< 50µs` | `37.7µs` | Meets target |
| HMAC sign | `< 30µs` | `24.8µs` | Meets target |
| HMAC verify | `< 30µs` | `24.0µs` | Meets target |
| HKDF key derivation (warm cache) | `< 50µs` | `0.8µs` | Meets target |
| HKDF key derivation (cold reference) | `reference` | `115.8µs` | Above target |
| One-shot validation | `< 80µs` | `70.2µs` | Meets target |
| base64url encode | `< 5µs` | `1.9µs` | Meets target |
| base64url decode | `< 5µs` | `3.5µs` | Meets target |

## Notes

- The harness is designed to keep setup work out of the benchmark loop.
- The current baseline is intentionally a single-machine reference point, not a release gate by itself.
- HKDF now has two useful readings: warm cached derivation reflects steady-state reuse, while the cold reference captures first-derivation cost.
- The provider now caches imported HKDF base key material and previously derived `(master, salt, info)` HMAC keys to remove repeated setup overhead from steady-state paths.
- Cold HKDF derivation remains above the original `< 50µs` aspirational target and should stay on the perf follow-up list if cold-start latency matters for a deployment.
- `client` and `ops` benchmarks are intentionally deferred to follow-up PRs so the initial benchmark surface stays small and reviewable.
