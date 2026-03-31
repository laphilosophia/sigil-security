---
name: sigil-security-audit
description: 'Audit Sigil-Security crypto and security implementation for compliance. Use when implementing or reviewing token generation, MAC verification, key derivation, nonce cache, constant-time comparison, or any cryptographic operation. Keywords: crypto audit, timing attack, side-channel, HMAC, HKDF, constant-time, nonce, token structure, key management, forbidden patterns, security review, cryptographic compliance.'
argument-hint: "file or feature to audit (e.g. 'packages/core/src/token.ts' or 'one-shot token implementation')"
---

# Sigil Security Audit

Audits cryptographic implementations against the fixed security invariants defined in `docs/SPECIFICATION.md` and the Cursor security rules. Targets side-channel leaks, timing oracles, forbidden patterns, and incorrect token structure.

## When to Use

- Implementing or modifying any file in `packages/core/src/`
- Adding a new token type or validation step
- Reviewing key derivation or HMAC logic changes
- Auditing a PR that touches crypto, nonce cache, or key manager
- Investigating a potential security regression

## Audit Checklist

### 1. Crypto Stack Compliance

- [ ] HMAC uses **HMAC-SHA256** via `crypto.subtle.sign/verify` — no truncation, full 256-bit
- [ ] Key derivation uses **HKDF-SHA256** via `crypto.subtle.deriveKey` / `crypto.subtle.deriveBits`
- [ ] Nonce generation uses `crypto.getRandomValues(new Uint8Array(16))` — 128-bit
- [ ] Encoding is **base64url, no padding** (RFC 4648)
- [ ] All crypto goes through `CryptoProvider` interface — no direct `crypto.subtle` calls in business logic
- [ ] Zero external crypto dependencies in `core`

### 2. Constant-Time / Timing Safety

- [ ] MAC and token comparisons use `crypto.subtle.verify` or `timingSafeEqual` — NEVER `===` or `!==`
- [ ] Validation logic **does NOT early-return on failure** (Deterministic Failure Model)
- [ ] All validation branches complete — accumulate with `valid &= step` pattern
- [ ] Token length is **never checked with early rejection** before full validation

### 3. Token Structure Integrity

Standard token: `base64url(kid[1] | nonce[16] | ts[8] | ctx[32] | mac[32])` = **89 bytes**
One-shot token: `base64url(nonce[16] | ts[8] | action[32] | ctx[32] | mac[32])` = **120 bytes**

- [ ] Token length is constant — no variable-size fields
- [ ] `ctx` is always 32 bytes (use `SHA-256(0x00)` zero-pad when no context binding)
- [ ] Parsing uses **fixed byte offsets** — no length-based branching
- [ ] Action labels in one-shot tokens are fixed-width (zero-padded to 32 bytes)

### 4. Key Management

- [ ] Keyring holds max 3 keys (active + 2 previous) **per domain**
- [ ] Token generation always uses the **active key**
- [ ] Validation tries **all keys in keyring** (matched by `kid`)
- [ ] HKDF info strings enforce domain separation:
  - CSRF: `"csrf-signing-key-" + kid`
  - One-shot: `"oneshot-signing-key-" + kid`
  - Internal: `"internal-signing-key-" + kid`
- [ ] A CSRF-derived key cannot be used to validate a one-shot token

### 5. Nonce Cache

- [ ] In-memory LRU + TTL only (max 10k entries, 5min TTL)
- [ ] `used` flag set via **atomic compare-and-swap** (prevent race conditions)
- [ ] Cache failure is **fail-open** — does NOT block valid requests if cache unavailable
- [ ] No external storage (Redis, DB) referenced in `core`

### 6. Logging & Error Exposure

- [ ] Token content (nonce, mac raw bytes) is **never logged**
- [ ] Only metadata is logged: `kid`, timestamp, action label
- [ ] Client-facing error messages are unified: `"CSRF validation failed"` — no differentiation
- [ ] Internal `reason` field never leaks to HTTP response body

### 7. Forbidden Patterns

Flag any occurrence of:

- [ ] `Math.random()` for any security purpose
- [ ] `===` / `!==` comparing MAC bytes or full token strings
- [ ] `JSON.stringify` for token serialization (use binary `Uint8Array` ops)
- [ ] `eval()`, `new Function()`, dynamic code execution
- [ ] Secrets in source code, comments, or test fixtures
- [ ] `any` type on security-critical function signatures

## Report Format

For each finding:

```
FINDING [SEVERITY: CRITICAL|HIGH|MEDIUM]
File: <path>
Line: <n>
Category: <timing / token-structure / key-mgmt / logging / forbidden>
Issue: <description>
Fix: <concrete remediation>
```

If everything passes: `SECURITY AUDIT PASSED — no crypto or security violations detected.`

## Procedure

1. Read the target file(s)
2. Work through each checklist section — mark as ✅ PASS or ❌ FAIL
3. For each FAIL, record a finding with severity and fix
4. Output the checklist summary and all findings grouped by severity
5. If CRITICAL findings exist, recommend blocking the change

## References

- [SPECIFICATION.md](../../../docs/SPECIFICATION.md) — token model, validation layers, lifecycle
- [BOUNDARY_SPECIFICATION.md](../../../docs/BOUNDARY_SPECIFICATION.md) — core surface constraints
- [CRYPTO_ANALYSIS.md](../../../docs/CRYPTO_ANALYSIS.md) — cryptographic design rationale
- [SECURITY_ADVISORIES.md](../../../docs/SECURITY_ADVISORIES.md) — known issues and mitigations
