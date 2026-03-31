# Sigil-Security — Copilot Workspace Instructions

## Project Identity

Sigil-Security is a **stateless cryptographic request authenticity primitive** — NOT a CSRF middleware, NOT a framework, NOT an auth system. Every implementation decision must preserve this identity. Valid Request := `Integrity AND Context AND Freshness AND Provenance`.

## Monorepo Layout

```
packages/
  core/     → @sigil-security/core      (crypto primitive, stateless, pure — ZERO runtime deps)
  policy/   → @sigil-security/policy    (validation policies: Fetch Metadata, Origin, context binding)
  runtime/  → @sigil-security/runtime   (framework adapters: Express, Fastify, Elysia, native Fetch)
  ops/      → @sigil-security/ops       (telemetry & monitoring, optional)
  client/   → @sigil-security/client    (browser SDK: refresh, multi-tab sync, leader election)
```

## Layer Dependency Direction (one-way, strictly enforced)

```
client → runtime → policy → core
                   ops ───→ runtime
```

`core` has ZERO dependencies on any other sigil package. Higher layers depend on lower, never the reverse.

## Core Hard Boundaries

`core` MUST NOT: accept HTTP objects (`Request`, `Response`, `req`, `res`, `ctx`), import any framework, perform I/O (network, FS, DB), log or emit metrics, manage token lifecycle, contain policy logic, or access `process.env`.

## Crypto Stack (fixed — no substitutions outside CryptoProvider)

- **Key derivation:** HKDF-SHA256 via `crypto.subtle.deriveKey`
- **MAC:** HMAC-SHA256 via `crypto.subtle.sign/verify` — full 256-bit, no truncation
- **Nonce:** 128-bit via `crypto.getRandomValues(new Uint8Array(16))`
- **Encoding:** base64url (RFC 4648), no padding
- **Default API:** WebCrypto — ZERO external crypto deps

## Token Structure (constant-length, fixed offsets)

| Token    | Layout                                                              | Size      |
| -------- | ------------------------------------------------------------------- | --------- |
| Standard | `base64url(kid[1] \| nonce[16] \| ts[8] \| ctx[32] \| mac[32])`     | 89 bytes  |
| One-shot | `base64url(nonce[16] \| ts[8] \| action[32] \| ctx[32] \| mac[32])` | 120 bytes |

`ctx` is always 32 bytes. Token length never varies.

## Security Invariants (always enforce)

- ALL validation steps must complete — no early return on failure (Deterministic Failure Model)
- NEVER use `===`/`!==` to compare MACs or tokens — use `crypto.subtle.verify` or `timingSafeEqual`
- NEVER log token content (nonce, mac) — only metadata (kid, timestamp, action label)
- NEVER differentiate error types to the client — single message: `"CSRF validation failed"`
- NEVER use `Math.random()` for security purposes

## TypeScript Standards

- `strict: true` in all tsconfig files
- No `any` — use `unknown` + type narrowing at system boundaries
- Result pattern over exceptions for validation: `{ valid: true } | { valid: false; reason: string }`
- Explicit return types on all exported functions
- `readonly` on immutable properties, `as const` for literal constants

## Spec References

Before implementing or reviewing architectural decisions, consult:

- `docs/BOUNDARY_SPECIFICATION.md` — normative core boundaries
- `docs/SPECIFICATION.md` — token model, validation layers, lifecycle
- `docs/OPERATIONS.md` — telemetry metrics, incident response
- `docs/MODEL_GENERALIZATION.md` — extended security model

## Build & Test

```bash
pnpm install          # install dependencies
pnpm build            # build all packages
pnpm test             # run all tests (vitest)
pnpm -F @sigil-security/core test   # test a single package
```

Test files mirror source: `src/token.ts` → `__tests__/token.test.ts`. Use `vitest`, not jest. Benchmark target: token validation < 50µs.

## On-Demand Skills

- `/sigil-boundary-check` — audit a file or package for layer boundary violations
- `/sigil-security-audit` — audit crypto/security implementation compliance
- `/sigil-code-review` — TypeScript code quality review (SOLID, KISS, naming, tests)
