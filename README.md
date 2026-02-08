# Sigil-Security

**Cryptographic Request Authenticity Primitive**

Sigil is a high-integrity, stateless, and multi-layered CSRF defense library designed for modern web environments. Unlike traditional session-based middlewares, Sigil leverages modern browser security signals and cryptographic proofs to guarantee request authenticity across distributed runtimes.

---

## Key Features

- **Stateless by Design:** No session store, Redis, or sticky sessions required. Perfect for Serverless and Edge runtimes.
- **Multi-Layered Defense:** Combines Fetch Metadata, Strict Origin validation, and Cryptographic Tokens.
- **Professional Crypto:** Built on HKDF-SHA256 and WebCrypto for timing-attack-resilient validation.
- **Zero-Downtime Rotation:** Native support for key rotation and versioned credentials.
- **One-Shot Tokens:** Optional single-use tokens for high-assurance endpoints (e.g., payments, account deletion).
- **Runtime Agnostic:** Works identical across Node.js, Bun, and Deno.

---

## Documentation

The project documentation is organized into four core normative files:

### 1. [Boundary Specification](./docs/BOUNDARY_SPECIFICATION.md)

The formal definition of what the core primitive MUST and MUST NOT do. Essential for core contributors and architects to ensure the library remains a "security primitive" and not a bloated framework.

### 2. [Technical Specification](./docs/SPECIFICATION.md)

Comprehensive details on the token model, cryptographic parameters, multi-layered validation logic, and the One-Shot token primitive.

### 3. [Operations Manual](./docs/OPERATIONS.md)

Guidance for SRE and Security teams. Includes a Metric Taxonomy for monitoring, baseline establishment, and a production-ready Incident Response Runbook.

### 4. [Documentation Index](./docs/README.md)

A quick-start guide and detailed navigation map for the entire documentation suite.

---

## Why Sigil?

Traditional CSRF protection often relies on server-side state, which introduces latency, synchronization issues in multi-tab SPAs, and horizontally scaling bottlenecks.

**Sigil solves this by shifting from "session tracking" to "cryptographic intent verification":**

- It leverages `Sec-Fetch-Site` to block cross-site requests at the edge.
- It uses context-bound tokens to prevent token exfiltration reuse.
- It provides a deterministic failure model to prevent timing side-channels.

---

## Project Status

**Status:** Production-Ready Specifications
**Stage:** Phase 7 (Operational Security) Complete — implementation ready to begin.

**Next Milestone:** Core Library Implementation (WebCrypto Integration).

---

## License

[Add License Type Here, e.g., MIT / Apache 2.0]

---

**Built with Precision for the Professional Security Ecosystem.**
