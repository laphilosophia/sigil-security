# Sigil — Model Generalization

**Status:** Normative
**Scope:** Security capabilities beyond CSRF
**Identity:** Cryptographic Proof of Request Intent
**Model:** Stateless • Deterministic • Context-Bound • Replay-Aware

Technical and operational foundation:

---

# 1. Purpose

This specification defines how the Sigil primitive extends beyond CSRF into a broader **request authenticity and intent verification model**.

This document:

- Does **not** introduce new features
- Does **not** expand the core primitive
- Does **not** define a framework

It formally describes the **security problem space naturally covered by the existing primitive.**

---

# 2. Scope Boundary

Sigil **DOES:**

- Cryptographically verify request integrity
- Verify contextual correctness of a request
- Constrain and observe replay behavior
- Produce measurable request intent signals

Sigil **DOES NOT:**

- Perform authentication
- Perform authorization
- Manage sessions
- Filter traffic
- Provide rate limiting
- Act as a WAF
- Implement identity or access control

---

# 3. Core Concept

**Request Intent = Integrity ∧ Context ∧ Freshness ∧ Provenance**

Sigil verifies:

- Integrity → HMAC verification
- Context → Context binding
- Freshness → TTL / nonce / replay model
- Provenance → Policy signals (Origin / Fetch Metadata)

This produces:

**Cryptographic Proof of Request Intent**

---

# 4. Security Problems Addressed

## 4.1 Cross-Site Request Forgery (CSRF)

**Problem:** Cross-site authenticated requests executed without user intent.
**Mechanism:** Context-bound token + Origin + Fetch Metadata validation.
**Result:** Forged cross-site requests are rejected deterministically.
**Operational Signal:** origin mismatch, cross-site block.

---

## 4.2 Replay and Idempotency Exploitation

**Problem:** Valid requests reused or replayed, causing silent damage.
**Mechanism:** TTL + nonce + optional one-shot tokens.
**Result:** Replay constrained or prevented on critical endpoints.
**Operational Signal:** replay attempts, nonce reuse.

---

## 4.3 Forged / Spoofed Requests

**Problem:** Requests appear authenticated but originate from invalid or manipulated context.
**Mechanism:** Context binding + MAC verification.
**Result:** Context-invalid or forged requests are rejected.
**Operational Signal:** context mismatch, invalid MAC.

---

## 4.4 Request Provenance Ambiguity

**Problem:** Systems cannot reliably determine where a request originated.
**Mechanism:** Combined validation of Origin, Fetch Metadata, and context binding.
**Result:** Request provenance becomes measurable and distinguishable.
**Operational Signal:** origin mismatch, missing metadata.

---

## 4.5 Action-Level Security

**Problem:** Critical operations remain weakly protected despite valid sessions.
**Mechanism:** One-shot token + action binding + fail-closed policy.
**Result:** Non-replayable, action-bound verification for high-assurance operations.
**Operational Signal:** action mismatch, replay detection.

---

## 4.6 Stateless Request Authenticity

**Problem:** Session-bound security does not scale cleanly across distributed systems.
**Mechanism:** Stateless cryptographic validation + HKDF key derivation + key rotation.
**Result:** Horizontal scalability and edge compatibility without shared state.
**Operational Signal:** key rotation, cryptographic failures.

---

## 4.7 Intent Ambiguity

**Problem:** Authentication proves identity but not intent.
**Mechanism:** Context-bound verification + deterministic failure model.
**Result:** Distinction between authenticated identity and valid intent.
**Operational Signal:** classified validation failures, anomaly metrics.

---

## 4.8 Incident Visibility and Forensics

**Problem:** Insufficient signal during security incidents.
**Mechanism:** Deterministic validation + structured telemetry.
**Result:** Replay, forgery, provenance, and context failures become observable and classifiable.
**Operational Signal:** anomaly detection, validation spikes, crypto anomalies.

---

## 4.9 Key Compromise Resilience

**Problem:** Safe and continuous operation during key compromise or rotation.
**Mechanism:** HKDF key hierarchy + `kid` + keyring model.
**Result:** Normal rotation and emergency compromise are separated; continuity preserved.
**Operational Signal:** key rotation events, key failures.

---

## 4.10 Client Diversity

**Problem:** Browser, API, mobile, and service clients exhibit different trust signals.
**Mechanism:** Mode separation (Browser vs API) + canonical token transport + optional context binding.
**Result:** Consistent request authenticity across heterogeneous clients.
**Operational Signal:** mode distribution, metadata presence.

---

# 5. Generalization of the Security Model

Sigil naturally covers the following security domains:

| Domain                    | Covered by Sigil |
| ------------------------- | ---------------- |
| CSRF                      | Yes              |
| Replay protection         | Yes              |
| Request forgery           | Yes              |
| Action-level security     | Yes              |
| Internal API authenticity | Yes              |
| Webhook integrity         | Yes              |
| Stateless intent proof    | Yes              |
| Request provenance        | Yes              |

This is not feature expansion.
It is the **natural application surface of the same primitive.**

---

# 6. Architectural Scope Guard

Sigil MUST NOT evolve into:

- Authentication system
- Identity or access management
- Session manager
- Rate limiter
- Traffic filter / WAF
- General security framework

Sigil’s sole responsibility:

**Cryptographically verify request intent.**

---

# 7. Security Model Definition

Sigil defines request validity as:

```
Valid Request :=
  Integrity Verified
  AND Context Valid
  AND Freshness Valid
  AND Provenance Acceptable
```

Failure in any dimension produces:

- Deterministic rejection
- Uniform failure response
- Structured security signal

---

# 8. Architectural Identity

Sigil is:

- Not a CSRF middleware
- Not a framework
- Not an authentication system

Sigil is:

**A Stateless Cryptographic Request Intent Verification Primitive**

---

If needed, this can be extended next into:

- Formal Security Model (mathematical / adversarial)
- Product Positioning Spec
- Enterprise Capability Mapping
- Sigil vs Traditional Security Model Comparison
