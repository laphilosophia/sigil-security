# Sigil-Security

**Stateless Cryptographic Request Intent Verification Primitive**

Sigil is a high-integrity, stateless, multi-layered request authenticity library designed for modern web environments. It goes beyond traditional CSRF defense — Sigil provides **cryptographic proof of request intent** by verifying integrity, context, freshness, and provenance of every state-changing request.

Unlike session-based middlewares, Sigil leverages modern browser security signals and cryptographic proofs to guarantee request authenticity across distributed runtimes with zero shared state.

---

## Key Features

- **Stateless by Design:** No session store, Redis, or sticky sessions. Perfect for Serverless and Edge runtimes.
- **Multi-Layered Defense:** Combines Fetch Metadata, Strict Origin validation, and Cryptographic Tokens.
- **Professional Crypto:** HKDF-SHA256 key hierarchy with domain separation, constant-length tokens, and timing-attack-resilient validation via WebCrypto.
- **CryptoProvider Abstraction:** Swappable crypto backend — WebCrypto by default, extensible to KMS/HSM for enterprise.
- **Zero-Downtime Rotation:** Native key rotation with versioned keyring and domain-separated derivation.
- **One-Shot Tokens:** Single-use, action-bound tokens for high-assurance endpoints (payments, account deletion).
- **Runtime Agnostic:** Identical behavior across Node.js (≥18), Bun, Deno, and Edge runtimes.

---

## Packages

Sigil is a monorepo with strict architectural layer separation:

| Package                   | Scope                   | Description                                                                                         |
| ------------------------- | ----------------------- | --------------------------------------------------------------------------------------------------- |
| `@sigil-security/core`    | Cryptographic Primitive | Token generation/validation, HMAC, HKDF, constant-time ops, one-shot tokens. **Zero dependencies.** |
| `@sigil-security/policy`  | Validation Policies     | Fetch Metadata, Origin/Referer, context binding, risk tiers, Browser/API mode detection.            |
| `@sigil-security/runtime` | Framework Adapters      | Express, Fastify, Elysia, native fetch middleware.                                                   |
| `@sigil-security/ops`     | Telemetry (Optional)    | Experimental observability wrapper with pluggable metrics, anomaly detection, and structured logs.  |
| `@sigil-security/client`  | Browser SDK             | Experimental browser SDK with silent refresh, multi-tab sync, leader election, and fetch helpers.   |

**Dependency direction (one-way only):** `client → runtime → policy → core`

---

## Security Model

Sigil defines request validity as:

```
Valid Request := Integrity ∧ Context ∧ Freshness ∧ Provenance
```

| Dimension      | Mechanism                                         |
| -------------- | ------------------------------------------------- |
| **Integrity**  | HMAC-SHA256 verification                          |
| **Context**    | Context binding (session/user/origin hash)        |
| **Freshness**  | TTL + nonce + optional one-shot replay prevention |
| **Provenance** | Origin header + Fetch Metadata policy signals     |

This model naturally covers: CSRF, replay protection, request forgery, action-level security, stateless authenticity, request provenance, intent verification, incident visibility, key compromise resilience, and client diversity.

---

## Documentation

| Document                                                   | Audience                      | Description                                                                        |
| ---------------------------------------------------------- | ----------------------------- | ---------------------------------------------------------------------------------- |
| [Boundary Specification](./docs/BOUNDARY_SPECIFICATION.md) | Core contributors, architects | What the core primitive MUST and MUST NOT do. **Read first.**                      |
| [Technical Specification](./docs/SPECIFICATION.md)         | Developers, implementers      | Token model, validation layers, lifecycle, one-shot tokens.                        |
| [Operations Manual](./docs/OPERATIONS.md)                  | SRE, security teams           | Metric taxonomy, anomaly detection, incident response runbook.                     |
| [Model Generalization](./docs/MODEL_GENERALIZATION.md)     | Architects, product           | Extended security model beyond CSRF — request intent verification.                 |
| [Crypto Analysis](./docs/CRYPTO_ANALYSIS.md)               | Core contributors             | WebCrypto evaluation, limitations, domain separation, abstraction layer rationale. |
| [Documentation Index](./docs/README.md)                    | Everyone                      | Quick-start guide and navigation map.                                              |

---

## Why Sigil?

Traditional CSRF protection relies on server-side state, which introduces latency, synchronization issues in multi-tab SPAs, and horizontal scaling bottlenecks.

**Sigil shifts from "session tracking" to "cryptographic intent verification":**

- Leverages `Sec-Fetch-Site` to block cross-site requests at the edge.
- Uses context-bound, constant-length tokens to prevent exfiltration reuse and length oracles.
- Provides a deterministic failure model — no timing leaks, no error oracles, single failure path.
- Domain-separated key hierarchy closes cross-protocol attack surfaces.

---

## Requirements

- **Node.js ≥ 18** (WebCrypto API)
- **Bun** (any version)
- **Deno** (any version)

---

## Project Status

**Status:** Active implementation  
**Current Reality:** `core`, `policy`, and `runtime` are implemented and verified locally; `client` and `ops` are implemented but still marked experimental; Phase 6 hardening and release alignment remain open.

**Architecture:**

- Monorepo with pnpm workspaces
- TypeScript strict mode
- ESM + CJS dual output via tsup
- vitest for unit and integration testing
- GitHub Actions CI
- Oak and Hono runtime adapters intentionally remain disabled pending separate security remediation

---

## License

Apache 2.0

---

**A Cryptographic Primitive for the Professional Security Ecosystem.**
