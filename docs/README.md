# Sigil-Security Documentation

**Project:** Stateless Cryptographic Request Intent Verification Primitive
**Status:** Implemented monorepo, hardening and release alignment in progress
**Total Documentation:** ~3500 lines (6 files)

---

## Documentation Structure

### 1. [`BOUNDARY_SPECIFICATION.md`](./BOUNDARY_SPECIFICATION.md) - Core Boundary Specification

**Scope:** Core behavioral boundaries (normative)

**Critical Rules:**

- **Core MUST do:** Cryptographic primitives, stateless validation, pure functions
- **Core MUST NOT do:** Lifecycle management, state orchestration, policy enforcement, runtime coupling, operational behavior
- **Only permitted state:** Ephemeral replay cache (TTL-bounded, optional)
- **Architectural layer contract:** `sigil-core` (crypto primitive) → `sigil-policy` (validation) → `sigil-runtime` (adapters) → `sigil-ops` (telemetry)

**Final Identity:** Cryptographic Request Authenticity Primitive (not CSRF middleware)

**Audience:** Core contributors, architects (MUST READ before implementation)

---

### 2. [`SPECIFICATION.md`](./SPECIFICATION.md) - Technical Specification

**Scope:** Architectural design, token model, lifecycle, one-shot primitive

**Contents:**

- **Part I: Core Specification**
  - Threat model
  - Architectural design (Core, Policy Engine, Adapters, Crypto)
  - Token model (kid, nonce, ts, ctx, mac)
  - Cryptographic parameters (HKDF-SHA256, 128-bit nonce)
  - Validation layers (Fetch Metadata, Origin, Token, Context)
  - Side-channel protection (timing, early reject, error oracle)
  - Risk tier model (low/medium/high assurance)
  - Key management and rotation
  - Browser vs API mode

- **Part II: Token Lifecycle**
  - Per-session model (20min TTL)
  - Silent refresh (last 25% window)
  - Multi-tab synchronization (BroadcastChannel + leader election)
  - Grace window (60s overlap)
  - Logout semantics (kid bump, revocation filter)

- **Part III: One-Shot Token Primitive**
  - Replay-impossible token (nonce cache)
  - Action binding
  - High-assurance endpoints
  - Performance (~80µs overhead)

**Audience:** Developers, implementers, architects

---

### 3. [`OPERATIONS.md`](./OPERATIONS.md) - Operations Manual

**Scope:** Monitoring, telemetry, incident response

**Contents:**

- **Part I: Monitoring & Telemetry**
  - Metric taxonomy (security, crypto, performance, anomaly)
  - Baseline establishment
  - Anomaly detection thresholds
  - Critical alerts (P0-P3)
  - Dashboards (security, operational)
  - SIEM integration

- **Part II: Incident Response**
  - Key compromise (signing key vs master secret)
  - Token forgery suspicion
  - Clock skew incident
  - One-shot replay attack
  - Validation spike
  - Escalation matrix
  - Communication templates

**Audience:** Security team, SRE, oncall engineers

---

### 4. [`MODEL_GENERALIZATION.md`](./MODEL_GENERALIZATION.md) - Model Generalization

**Scope:** Extended security model beyond CSRF

**Contents:**

- Security problem space naturally covered by the existing primitive
- 10 security domains: CSRF, replay, forgery, provenance, action-level, stateless authenticity, intent ambiguity, incident visibility, key resilience, client diversity
- Request validity formula: `Integrity ∧ Context ∧ Freshness ∧ Provenance`
- Architectural scope guard (what Sigil must NOT evolve into)

**Final Identity:** Stateless Cryptographic Request Intent Verification Primitive

**Audience:** Architects, product stakeholders

---

### 5. [`CRYPTO_ANALYSIS.md`](./CRYPTO_ANALYSIS.md) - Cryptographic Backend Analysis

**Scope:** WebCrypto evaluation and crypto architecture decisions

**Contents:**

- WebCrypto strengths (constant-time, cross-runtime, key isolation, RNG quality)
- WebCrypto limitations (no streaming, no zeroization, no direct KMS/HSM)
- Adopted improvements: key hierarchy with domain separation, constant-length tokens, CryptoProvider abstraction
- WebCrypto vs Node crypto comparison

**Audience:** Core contributors, security reviewers

---

### 6. [`SECURITY_ADVISORIES.md`](./SECURITY_ADVISORIES.md) - Dependency Advisories

**Scope:** Third-party CVEs, Sigil exposure, and temporary adapter support decisions

**Audience:** Security reviewers, maintainers

---

### 7. [`README.md`](./README.md) - This Document

**Scope:** Documentation index, quick start, project status

---

## Quick Start

### For New Readers

1. **Overview:** This README
2. **Technical Details:** [`SPECIFICATION.md`](./SPECIFICATION.md) - Part I
3. **Lifecycle Semantics:** [`SPECIFICATION.md`](./SPECIFICATION.md) - Part II
4. **Operational Requirements:** [`OPERATIONS.md`](./OPERATIONS.md)

### For Core Contributors (Implementation)

1. **READ FIRST:** [`BOUNDARY_SPECIFICATION.md`](./BOUNDARY_SPECIFICATION.md) - Core boundaries
2. [`CRYPTO_ANALYSIS.md`](./CRYPTO_ANALYSIS.md) - Crypto decisions and CryptoProvider
3. [`SPECIFICATION.md`](./SPECIFICATION.md) - Part I (Core Specification)
4. [`SPECIFICATION.md`](./SPECIFICATION.md) - Part II (Token Lifecycle)

### For Developers

1. [`SPECIFICATION.md`](./SPECIFICATION.md) - All sections
2. [`OPERATIONS.md`](./OPERATIONS.md) - Part I (Monitoring)

### For Security/SRE

1. [`OPERATIONS.md`](./OPERATIONS.md) - Part I (Monitoring)
2. [`OPERATIONS.md`](./OPERATIONS.md) - Part II (Incident Response)
3. [`SPECIFICATION.md`](./SPECIFICATION.md) - Part III (One-Shot Token)

### For Architects

1. [`BOUNDARY_SPECIFICATION.md`](./BOUNDARY_SPECIFICATION.md) - Core identity
2. [`MODEL_GENERALIZATION.md`](./MODEL_GENERALIZATION.md) - Extended security model
3. [`SPECIFICATION.md`](./SPECIFICATION.md) - Part I (Core)

---

## Project Status

### Completed Phases

- **Phase 0-3:** Infrastructure, core, policy, and runtime are implemented in the repo and validated by local lint, test, build, and typecheck runs.
- **Phase 4-5:** `client` and `ops` now have implementation code and tests, but remain explicitly experimental until the hardening and release criteria are closed.
- **Documentation foundation:** Specifications, boundary rules, operations guidance, and security advisories are present and aligned to the architecture.

### Current Phase

**Phase 6-7 Closing Work**

1. Security hardening evidence — fuzzing, malformed token coverage, benchmark baselines, and wider runtime validation.
2. Release alignment — experimental messaging for `client` and `ops`, package maturity review, and documentation accuracy.
3. Optional package maturation — move `client` and `ops` from experimental to GA only after hardening criteria are met.
4. Model Generalization — coverage validation, extended use cases, and formal docs.

---

## Critical Decisions

### Why Stateless?

**CAP theorem, latency, cost, failure domain**

- Session store I/O (~1ms) vs CPU-bound HMAC (~50µs)
- Natural horizontal scaling
- Edge/serverless deployment

**Trade-off:** No instant revocation (TTL expiry required)

### Why Per-Session Token?

**Overhead vs security balance**

- Per-request → high overhead
- Per-session → low overhead, silent refresh

**Trade-off:** Replay window = TTL (20min)

### Why Optional One-Shot Token?

**Selective usage (high-assurance only)**

- Requires bounded cache (~1MB)
- Minimal overhead (~80µs)
- Multi-use sufficient for most endpoints

**Trade-off:** Complexity vs absolute replay prevention

---

## Architectural Evolution

**Previous:** CSRF middleware → Token validation → Feature
**Current:** Request intent verification → Cryptographic proof of intent → Infrastructure primitive

---

## Documentation Metrics

- **Total Lines:** ~3500
- **File Count:** 6
- **Coverage:** Specification + Operations + Boundaries + Model Generalization + Crypto Analysis
- **Status:** Production-ready

---

**Last Updated:** 2026-02-08
**Version:** 1.1
