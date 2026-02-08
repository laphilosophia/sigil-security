# Sigil-Security Documentation

**Project:** Stateless CSRF Defense Library
**Status:** Production-Ready
**Total Documentation:** ~3000 lines (4 files)

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

### 4. [`README.md`](./README.md) - This Document

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
2. [`SPECIFICATION.md`](./SPECIFICATION.md) - Part I (Core Specification)
3. [`SPECIFICATION.md`](./SPECIFICATION.md) - Part II (Token Lifecycle)

### For Developers

1. [`SPECIFICATION.md`](./SPECIFICATION.md) - All sections
2. [`OPERATIONS.md`](./OPERATIONS.md) - Part I (Monitoring)

### For Security/SRE

1. [`OPERATIONS.md`](./OPERATIONS.md) - Part I (Monitoring)
2. [`OPERATIONS.md`](./OPERATIONS.md) - Part II (Incident Response)
3. [`SPECIFICATION.md`](./SPECIFICATION.md) - Part III (One-Shot Token)

### For Architects

1. [`BOUNDARY_SPECIFICATION.md`](./BOUNDARY_SPECIFICATION.md) - Core identity
2. [`SPECIFICATION.md`](./SPECIFICATION.md) - Part I (Core)

---

## Project Status

### Completed Phases

- **Phase 1-5:** Cryptographic foundation
  - Token format stabilized
  - HKDF-SHA256 key derivation
  - Side-channel protection
  - Risk tier model
  - Browser vs API mode

- **Phase 7:** Operational security
  - Token lifecycle specification
  - One-shot token primitive
  - Monitoring and telemetry architecture
  - Incident response runbook

### Next Phase

**Implementation** (10-14 weeks)

1. Core Library (2-3 weeks)
2. Policy Engine (1-2 weeks)
3. Adapters (2-3 weeks)
4. Client SDK (1-2 weeks)
5. Advanced Features (2-3 weeks)
6. Documentation & Release (1 week)

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
**Current:** Request authenticity framework → Cryptographic proof of intent → Infrastructure component

---

## Documentation Metrics

- **Total Lines:** ~3000
- **File Count:** 4 (hybrid approach)
- **Coverage:** Specification + Operations + Boundaries
- **Status:** Production-ready

---

**Last Updated:** 2026-02-08
**Version:** 1.0
