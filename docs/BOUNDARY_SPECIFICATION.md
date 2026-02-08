# Sigil — Core Boundary Specification

**Status:** Normative
**Scope:** `sigil-core` behavioral boundaries
**Purpose:** Ensure the library remains a security primitive

---

## 1. System Definition

`sigil-core` is a **stateless cryptographic request authenticity primitive.**
Under no circumstances does it manage the request lifecycle, session state, client state, or application flow.

The role of the Core is:

- Cryptographic validation
- Context binding
- Replay control (optional)
- Deterministic validation
- Constant-time security

The Core is a **security mechanism, not a policy engine.**

---

## 2. Core MUST do (Allowed Surface)

The Core is restricted to the following behaviors:

### 2.1 Cryptographic Primitives

- Token generation
- Token validation
- HMAC verification
- HKDF key derivation
- Constant-time comparisons
- Deterministic failure paths

### 2.2 Stateless Validation

- TTL (Time-to-Live) checks
- Context binding validation
- Optional replay detection (bounded, non-persistent)

### 2.3 Pure Function Model

Core functions must be:

- Deterministic
- Side-effect free (excluding ephemeral replay cache)
- I/O independent
- Runtime agnostic
- Framework agnostic

---

## 3. Core MUST NOT do (Hard Prohibitions)

The following behaviors **must never** be added to the Core:

### 3.1 Lifecycle Management PROHIBITED

The Core does not:

- Perform token refreshes
- Manage token rotation
- Handle session management
- Contain logout semantics
- Perform client synchronization
- Coordinate multiple tabs
- Utilize BroadcastChannel or storage events

### 3.2 State Orchestration PROHIBITED

The Core does not:

- Use a session store
- Manage distributed state
- Include persistence
- Maintain revocation lists (excluding ephemeral replay cache)
- Carry global state

### 3.3 Policy Enforcement PROHIBITED

The Core does not:

- Understand CSRF policies
- Process browser headers
- Perform Origin or Fetch Metadata validation
- Understand HTTP semantics
- Distinguish between client types
- Understand request transport mechanisms

These responsibilities belong to the **Policy Layer.**

### 3.4 Runtime Coupling PROHIBITED

The Core does not:

- Integrate with Express, Hono, Oak, or other frameworks
- Accept HTTP request objects
- Understand its environment
- Include a configuration store
- Include a logger
- Include metrics collection

### 3.5 Operational Behavior PROHIBITED

The Core does not:

- Perform monitoring
- Generate telemetry data
- Implement rate limiting
- Generate alerts
- Include incident handling logic

---

## 4. Only Permitted State

The Core may only maintain an **ephemeral replay cache.**

Boundaries:

- TTL-bounded
- Memory-bounded
- Non-distributed
- Optional
- Fail-open allowed
- No persistence

This cache is an **optimization, not a security guarantee.**

---

## 5. Policy Layer Responsibilities

The following fall outside the scope of the Core:

- CSRF presets
- Browser vs. API mode logic
- Fetch Metadata validation
- Origin validation
- Token transport mechanisms
- Lifecycle orchestration
- Refresh logic
- Logout behavior
- Telemetry generation
- Distributed replay detection
- Rate limiting
- General observability
- Deployment logic

These behaviors must reside in separate packages.

---

## 6. Architectural Layer Contract

```
sigil-core      → cryptographic primitive (stateless, pure)
sigil-policy    → validation policies (CSRF, API, Browser)
sigil-runtime   → framework adapters
sigil-ops       → telemetry & monitoring (optional)
sigil-extended  → distributed / advanced features (optional)
```

The Core is designed to operate independently and has no dependencies on higher layers.

---

## 7. Design Violation Criteria

The following scenarios constitute a **boundary violation:**

- The Core accepts a request object.
- The Core manages refreshes.
- The Core maintains distributed state.
- The Core has knowledge of client behavior.
- The Core contains policy logic.
- The Core has dependencies on configuration or runtime environments.
- The Core performs I/O operations.
- The Core includes observability features.

Such violations transform the project into a **framework** rather than a primitive.

---

## 8. Expansion Rules

When evaluating new features:

If the feature is a:

- Cryptographic primitive
- Stateless validation mechanism
- Replay detection variation
- Side-channel mitigation

→ It may be added to the **Core.**

If the feature involves:

- Behavioral orchestration → **Policy Layer**
- State management → **Extended Layer**
- Deployment logic → **Runtime Layer**
- Observability → **Operations Layer**
- Client behavior → **Policy Layer**

→ It remains outside the Core.

---

## 9. Core Design Principles

The Core must maintain the following:

- Minimal surface area
- Deterministic behavior
- Constant-time security
- Runtime independence
- Framework independence
- Stateless validation
- Cryptographic integrity

Loss of these principles results in the Core losing its architectural identity.

---

## 10. Final Architectural Identity

`sigil-core` is:

- NOT a CSRF middleware
- NOT a framework
- NOT an authentication system
- NOT a session management system

`sigil-core` is a:

**Cryptographic Request Authenticity Primitive.**

---
