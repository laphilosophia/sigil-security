# Contributing to Sigil-Security

Thank you for your interest in contributing to Sigil-Security. This document provides guidelines to ensure contributions maintain the project's architectural integrity and security standards.

---

## Before You Start

**Read these documents in order:**

1. **[Boundary Specification](./docs/BOUNDARY_SPECIFICATION.md)** — Defines what `sigil-core` MUST and MUST NOT do. This is non-negotiable.
2. **[Technical Specification](./docs/SPECIFICATION.md)** — Token model, validation layers, and lifecycle semantics.
3. **[Crypto Analysis](./docs/CRYPTO_ANALYSIS.md)** — Cryptographic decisions and their rationale.

---

## Architectural Rules

Sigil has strict layer boundaries. Violations will be rejected in review.

### sigil-core (Cryptographic Primitive)

- Pure functions only — deterministic, no side-effects (except ephemeral nonce cache)
- NEVER accepts HTTP request/response objects
- NEVER imports from policy, runtime, ops, or client packages
- NEVER performs I/O (network, filesystem, database)
- NEVER includes logging, metrics, or telemetry
- All crypto operations go through `CryptoProvider` interface

### Layer Dependencies (one-way only)

```
client → runtime → policy → core
                    ops → runtime
```

Reverse dependencies are forbidden.

---

## Code Standards

- **TypeScript strict mode** — no `any` on exported APIs
- **Explicit return types** on all exported functions
- **Result pattern** over exceptions for validation (`{ valid: true } | { valid: false, reason }`)
- **Constant-time** — all validation steps complete, no early returns, single failure path
- **Constant-length tokens** — `ctx` is always 32 bytes, token size never varies
- **Domain-separated keys** — CSRF, one-shot, and internal tokens use different HKDF derivation paths

---

## Security Requirements

- NEVER use `Math.random()` for security purposes
- NEVER use string comparison (`===`) for MAC/token comparison
- NEVER log token content (nonce, mac) — only metadata (kid, timestamp)
- NEVER differentiate error types to the client — single message: `"CSRF validation failed"`
- NEVER add external crypto dependencies — WebCrypto only (via CryptoProvider)

---

## Development

```bash
# Install dependencies
pnpm install

# Run tests
pnpm test

# Run linting
pnpm lint

# Build all packages
pnpm build
```

---

## Pull Request Process

1. **One concern per PR** — don't mix features, fixes, and refactors.
2. **Tests required** — every exported function must have unit tests.
3. **Security tests** — if touching crypto or validation, include replay/fuzzing/boundary tests.
4. **Benchmark** — if touching core, verify validation stays under 50µs target.
5. **No new dependencies** in `sigil-core` — it must remain zero-dependency.
6. **Reference the specification** — cite the relevant section from SPECIFICATION.md or BOUNDARY_SPECIFICATION.md in your PR description.

---

## Reporting Security Issues

Do **not** open a public issue for security vulnerabilities. Instead, email the maintainers directly. Details will be provided in a SECURITY.md file.

---
