# Sigil-Security: Technical Specification

**Version:** 1.0
**Status:** Production-Ready
**Scope:** Stateless CSRF Defense Library

---

**Table of Contents:**

- [Part I: Core Specification](#part-i-core-specification)
- [Part II: Token Lifecycle](#part-ii-token-lifecycle)
- [Part III: One-Shot Token Primitive](#part-iii-one-shot-token-primitive)

---

# Part I: Core Specification

This document serves as the reference specification for a stateless, cryptographically verifiable, multi-layered CSRF defense library designed for modern browser behavior and multiple runtime targets. It covers application architecture, security model, validation layers, cryptographic preferences, threat model, research references, and development plan.

---

## 1. Purpose and Scope

The purpose of this project is to produce a CSRF protection library that eliminates the limitations of classical stateful CSRF middleware approaches by using modern browser security signals as the primary validation source, while remaining stateless and cryptographically verifiable. The goal is to provide a framework-agnostic security layer capable of running the same core validation logic across Node.js, Bun, and Deno runtimes.

This library is not merely middleware that generates and validates tokens. Modern CSRF defense is a combination of token + browser signals + request context validation. Therefore, the design is based on the principle of multi-layered validation.

---

## 2. Threat Model

### Protected Threats

- Cross-site authenticated requests (classic CSRF)
- Automatic browser requests carrying cookies
- SameSite bypass scenarios (redirect chains, top-level navigation)
- Token replay (limited within time window)
- Token exfiltration followed by out-of-context usage

### Unprotected Threats

- XSS (CSRF defense does not prevent XSS; if XSS exists, CSRF can be broken)
- Man-in-the-Middle (non-TLS traffic)
- Compromised client environment
- Clickjacking (requires separate defense)
- Same-origin logic bugs

These boundaries must be clearly stated in documentation.

---

## 3. Architectural Design

The core validation logic consists of pure functions and is runtime-agnostic. The adapter layer translates HTTP abstractions according to the framework.

### Layers

1. **Core (runtime-agnostic)**
   - Token encode/decode, HMAC validation, time window, context validation

2. **Policy Engine**
   - Fetch Metadata, Origin/Referer, Method, Content-Type, Same-site relationship

3. **Adapters**
   - Express, Fastify, Hono, Oak, Elysia, native fetch

4. **Crypto Layer**
   - WebCrypto (Node 18+, Bun, Deno). No native dependencies.

The stateless design eliminates the need for session stores, Redis, or sticky sessions.

---

## 4. Token Model

### 4.1 Token Structure

Token structure:

```
base64url(
  kid | nonce | ts | ctx | mac
)
```

Fields:

- **kid**: Key ID (8-bit, for key rotation)
- **nonce**: 128-bit random value (crypto.getRandomValues)
- **ts**: unix timestamp (int64, big-endian)
- **ctx**: binding data (optional, SHA-256 hash)
- **mac**: HMAC-SHA256(derived_key, kid|nonce|ts|ctx)

### 4.2 Cryptographic Parameters (Fixed)

**Entropy:**

- Nonce: 128-bit (16 bytes) — crypto.getRandomValues
- Minimum entropy: 2^128 (collision resistance)

**MAC:**

- HMAC-SHA256 (256-bit output)
- **No MAC truncation** (timing oracle risk)
- Full 256-bit MAC used

**Encoding:**

- base64url (RFC 4648)
- **No padding** (canonical form)
- Max token length: ~120 characters

**Key Derivation:**

- HKDF-SHA256 (RFC 5869)
- Master secret → versioned signing keys
- Key ID (kid) used for key rotation

### 4.3 Token Properties

- No server-side storage (stateless)
- Even if token is stolen, cannot be used out of context (context binding)
- TTL limits replay window (**design boundary, not vulnerability**)
- Constant-time validation (timing attack protection)
- Deterministic failure path (error oracle protection)

### 4.4 Token Replay Model

**Important:** Token replay is an **unavoidable design boundary** in stateless + TTL models, not a vulnerability.

Replay protection:

- TTL window (recommended: 10-30 minutes)
- Context binding (session/user/origin)
- Origin validation (prevents cross-site replay)

Requirements for replay attack:

- Valid token (exfiltration)
- Valid cookie (session)
- Valid origin (same-site)

At this point, the attack is not CSRF but **token exfiltration** (XSS).

---

## 5. Validation Layers

Token alone is not considered sufficient. Multi-layered policy is enforced.

### 5.1 Fetch Metadata

`Sec-Fetch-Site`:

- same-origin / same-site → allow
- cross-site → reject (state-changing request)

This is a low-cost and powerful filter in modern browsers.

**Support:**

- Chrome 76+
- Firefox 90+
- Edge 79+
- Safari 16.4+ (partial)

**Legacy Browser Behavior:**

**Risk Assessment:** Browser share without Fetch Metadata in modern web is **low but non-zero**.

**Fallback Strategy:**

#### Degraded Mode (Recommended)

- No Fetch Metadata → degrade to Origin + Token validation
- Origin/Referer + Token mandatory
- Log warning (legacy browser detected)

#### Strict Mode (High-Security)

- No Fetch Metadata → reject
- Modern browser mandatory
- User-Agent whitelist optional

**Configuration:**

```javascript
{
  legacyBrowserMode: 'degraded' | 'strict',
  requireFetchMetadata: false // for degraded mode
}
```

Reference: W3C Fetch Metadata Request Headers

---

### 5.2 Origin / Referer

- If Origin header exists, strict match
- Otherwise, Referer fallback
- Cross-origin mismatch → reject

Reference: RFC 6454 (Origin)

---

### 5.3 SameSite Policy

Default:

- `SameSite=Lax`
- `Secure` mandatory
- `Strict` optional

The CSRF package does not generate cookies; however, validation policy is exposed.

Reference: RFC 6265bis

---

### 5.4 HTTP Method Protection

Protected:

- POST
- PUT
- PATCH
- DELETE

GET is not protected by default.

---

### 5.5 Content-Type Restriction

Allowed:

- application/json
- application/x-www-form-urlencoded
- multipart/form-data

Others may be rejected or left optional.

---

### 5.6 Token Validation

Steps:

1. Token parse
2. Time window check
3. HMAC validation
4. Context validation (optional)

### 5.7 Side-Channel Protection

**Critical:** Timing attack is not the only side-channel.

#### Timing Attack

- **Constant-time HMAC validation** mandatory
- Crypto API must use native constant-time
- Use crypto.timingSafeEqual instead of string comparison

#### Early Reject Leakage

- Token parse failed → do NOT reject immediately
- TTL expired → do NOT reject immediately
- All validation steps must complete
- **Single failure path** (every error same response time)

#### Error Type Oracle

- "Invalid token" vs "Expired token" vs "Invalid signature" → **NOT DIFFERENTIATED**
- Single error message: "CSRF validation failed"
- Error details logged but not sent to client

#### Token Length Oracle

- Token length validation → constant-time
- Short token → normalized with padding
- Length leak → token format inference risk

#### Branch Prediction Leak

- Conditional branch → timing variation
- Crypto operations → branch-free implementation
- Modern CPU speculative execution risk (rare but exists)

### 5.8 Deterministic Failure Model

**Single Failure Path Principle:**

```
validate(token):
  valid = true

  # Parse (constant-time)
  parsed = parse(token)
  valid &= parsed.success

  # TTL check (constant-time)
  ttl_valid = check_ttl(parsed.ts)
  valid &= ttl_valid

  # HMAC verify (constant-time)
  mac_valid = verify_mac(parsed)
  valid &= mac_valid

  # Context check (constant-time)
  ctx_valid = verify_context(parsed.ctx)
  valid &= ctx_valid

  # Single exit point
  if valid:
    return SUCCESS
  else:
    return FAILURE  # Same response time
```

**Advantages:**

- No timing leak
- No error oracle
- Minimal branch prediction leak

---

## 6. Context Binding

### 6.1 Basic Concept

Optional security enhancement:

- session id hash
- user id hash
- origin hash
- deployment salt
- per-form nonce

Default is disabled because misconfiguration can produce false negatives.

### 6.2 Risk Tier Model

**Critical:** Context binding should not be applied with the same strictness for every endpoint.

#### Low Assurance (Relaxed Binding)

- **Endpoint type:** Read-only, non-destructive
- **Binding:** Optional or soft-fail
- **Example:** Profile viewing, list queries

#### Medium Assurance (Standard Binding)

- **Endpoint type:** State-changing but reversible
- **Binding:** Session ID hash (soft-fail with grace period)
- **Example:** Profile update, settings change

#### High Assurance (Strict Binding)

- **Endpoint type:** Financial, destructive, irreversible
- **Binding:** Session + User + Origin hash (fail-closed)
- **Example:** Money transfer, account deletion, permission change

### 6.3 Soft-Fail vs Fail-Closed

**Soft-Fail (Medium Assurance):**

- Context mismatch → log warning + allow
- Grace period: 5 minutes (session rotation tolerance)
- Telemetry measures false-negative rate

**Fail-Closed (High Assurance):**

- Context mismatch → reject + audit log
- No grace period
- Security > usability

### 6.4 False-Negative Mitigation

- 5-minute grace period after session rotation
- Multi-device login detection (user agent fingerprint)
- Telemetry: context mismatch rate < 1% target

---

## 7. Key Management and Rotation

### 7.1 Key Derivation

**Master Secret → Signing Keys:**

```
HKDF-SHA256(
  master_secret,
  salt = "sigil-csrf-v1",
  info = "signing-key-" + kid
)
```

**Advantages:**

- Versioned keys (via kid)
- Master secret leak → only rotation required
- Derived key usage instead of raw secret

### 7.2 Key Rotation Strategy

**Keyring Model:**

- Active key (kid = current)
- Previous keys (kid = current-1, current-2, ...)
- Max keyring size: 3 (active + 2 previous)

**Rotation Frequency:**

- **Recommended:** 7 days (weekly)
- **Minimum:** 1 day (daily, high-security)
- **Maximum:** 30 days (monthly, low-risk)

**Rotation Procedure:**

1. New key derived (kid++)
2. Old active key → previous keys
3. Token generation with new key
4. Token validation with entire keyring
5. Oldest key dropped (keyring size limit)

**Zero-Downtime Rotation:**

- TTL + keyring overlap ensures zero-downtime
- Example: TTL=30min, rotation=7days → 30min overlap sufficient

### 7.3 Key Compromise Scenarios

**Scenario 1: Signing Key Leak (kid-specific)**

- Impact: Attacker can generate valid tokens with that kid
- Mitigation: Emergency rotation (invalidate kid)
- Blast radius: Only tokens with that kid

**Scenario 2: Master Secret Leak**

- Impact: All derived keys compromised
- Mitigation: Master secret rotation + invalidate all kids
- Blast radius: All active tokens invalid

**Critical Distinction:** Key rotation (normal) vs key compromise (emergency)

---

## 8. Runtime Compatibility and Client Diversity

### 8.1 Runtime Support

Single crypto API: **WebCrypto**

Support:

- Node ≥18
- Bun
- Deno
- Edge runtimes (Cloudflare Workers, Vercel Edge)

Non-stream-consuming validation; serverless compatible.

### 8.2 Browser vs API Mode

**Critical:** Documentation was written entirely with browser assumptions. In reality, non-browser clients exist.

#### Browser Mode (Default)

- **Client:** Modern browser
- **Validation:** Full multi-layer (Fetch Metadata + Origin + Token)
- **Fetch Metadata:** Enforce
- **Origin/Referer:** Enforce

#### API Mode (Non-Browser)

- **Client:** Mobile app, CLI, internal service, curl, bot
- **Validation:** Token-only (no Fetch Metadata)
- **Fetch Metadata:** Skip (header absent)
- **Origin/Referer:** Optional (skip if trusted client)

#### Mode Detection

**Automatic:**

- `Sec-Fetch-Site` header present → Browser Mode
- `Sec-Fetch-Site` header absent → API Mode

**Manual:**

- `X-Client-Type: api` header → Force API Mode
- Configuration: `allowApiMode: true/false`

#### API Mode Security

In API Mode, no Fetch Metadata but:

- Token validation mandatory
- Context binding recommended (API key hash)
- Rate limiting mandatory
- IP whitelist optional

### 8.3 Token Transport Canonicalization

**Critical:** Token transport channel ambiguity produces bugs.

#### Transport Precedence (Strict Order)

1. **Custom Header** (recommended): `X-CSRF-Token`
2. **Request Body** (JSON): `{ "csrf_token": "..." }`
3. **Request Body** (form): `csrf_token=...`
4. **Query Parameter** (deprecated, insecure): `?csrf_token=...`

**Precedence Rule:**

- First valid token found is used
- Multiple tokens → first match wins
- Duplicate header → first value

#### Ambiguity Handling

**Multiple Token Conflict:**

- Header + Body different tokens → header takes precedence
- Body JSON + Form → JSON takes precedence
- Log warning (suspicious behavior)

**Duplicate Header:**

- First value used
- Audit log (potential attack)

**Content-Type Mismatch:**

- `Content-Type: application/json` but form data → reject
- `Content-Type: application/x-www-form-urlencoded` but JSON → reject

**Missing Token:**

- State-changing method (POST/PUT/PATCH/DELETE) → reject
- GET → allow (but log if suspicious)

### 8.4 Fetch Metadata Edge-Cases

**Same-Site but Cross-Origin (Subdomain):**

- `Sec-Fetch-Site: same-site`
- `Origin: https://api.example.com`
- `Referer: https://app.example.com`
- **Decision:** Allow (same-site) but log (cross-origin)

**Service Worker Initiated Request:**

- Service worker → `Sec-Fetch-Site` may vary
- **Decision:** Fallback to Origin/Referer validation

**Browser Extension Initiated Request:**

- Extension → `Sec-Fetch-Site: none` or missing
- **Decision:** Reject (untrusted origin)

**Preflight-less Credentialed Request:**

- Simple request (GET/POST form) → no preflight
- **Decision:** Fetch Metadata + Token mandatory

### 8.5 Non-Browser Client Examples

**Mobile App:**

- Native HTTP client (URLSession, OkHttp)
- No Fetch Metadata
- API Mode + Token + API key hash

**CLI Tool:**

- curl, wget
- No Fetch Metadata
- API Mode + Token + user authentication

**Internal Service:**

- Server-to-server
- No Fetch Metadata
- API Mode + Token + service authentication

**Bot/Scraper:**

- Headless browser or HTTP client
- Fetch Metadata present/absent (depends)
- Browser Mode (headless) or API Mode (HTTP client)

---

## 9. Security Notes

1. If XSS exists, CSRF is broken.
2. Token is not secret; it only validates integrity.
3. SameSite alone is not sufficient.
4. Origin check must not be disabled.
5. Fetch Metadata bypass should not be assumed impossible (legacy browser).
6. Clock skew tolerance must be applied.
7. Token TTL should be kept short (10-30 min).
8. Constant-time MAC validation is mandatory.
9. Token must not be logged.
10. Token must not be transported in URL parameters.

---

## 10. Testing Strategy

- Cross-origin POST simulation
- SameSite bypass edge-cases
- Key rotation
- Clock skew
- Malformed token fuzzing
- Replay testing
- Constant-time side-channel measurement
- High concurrency stateless validation

---

## 11. Performance Target

- O(1) validation
- No I/O
- No storage
- Token validation < 50µs
- Minimal memory footprint

---

## 12. Development Plan

Phase 1 — Core

- Token encode/decode
- HMAC validation
- TTL
- Context binding

Phase 2 — Policy Engine

- Fetch Metadata
- Origin/Referer
- Method / Content-Type

Phase 3 — Adapters

- Express
- Fastify
- Hono
- Oak
- Elysia
- Native fetch

Phase 4 — Security Hardening

- Constant-time
- Fuzzing
- Key rotation
- Side-channel testing

Phase 5 — Docs & Threat Model

- Misuse scenarios
- Security boundaries
- Deployment guidance

---

## 13. Research References / Citations

CSRF and modern defense:

- Barth, Jackson, Mitchell — Robust Defenses for CSRF (Stanford)
- OWASP CSRF Prevention Cheat Sheet
- RFC 6454 — The Origin Header
- RFC 6265bis — Cookies: HTTP State Management Mechanism
- W3C Fetch Metadata Request Headers
- Google Web Fundamentals — SameSite Cookies Explained
- Chrome Security — Defense in Depth for CSRF
- Mozilla Web Security Guidelines

Token & cryptography:

- NIST SP 800-107 — HMAC Security
- RFC 2104 — HMAC
- RFC 4648 — Base64url
- OWASP Cryptographic Storage Cheat Sheet

Side-channel & constant-time:

- Kocher — Timing Attacks
- OWASP Side Channel Attack Guidance

Stateless security models:

- JWT BCP — RFC 8725 (token misuse and binding issues)
- Macaroons — Context-bound token approach

---

## 14. Validity and Security Argument

This model, compared to classic synchronizer token approach:

- Requires no storage
- Horizontally scalable
- Edge/serverless compatible
- Uses modern browser signals
- Limits out-of-context usage even if token is stolen
- Narrows replay surface with time window
- Implements defense-in-depth

Security relies on the combination of layers, not a single mechanism.

---

## 15. Open Research Areas

- Legacy browser behavior without Fetch Metadata
- Token binding vs session binding accuracy rate
- SameSite bypass variations
- HTTP/3 and service worker effects
- Browser privacy partitioning impact
- WebView behaviors
- Cross-origin iframe + credential mode edge-cases

Real-world testing is recommended for these areas.

---

This document provides the technical foundation and reference framework for a modern, stateless, cryptographic, and multi-layered CSRF defense library in the context of web security. During development, the threat model and policy assumptions should be revalidated.

---

# Part II: Token Lifecycle Specification

**Version:** 1.0
**Status:** Formal Specification
**Target:** SPA + Multi-Tab + Rotation

---

## 1. Overview

The token lifecycle is the **most fragile component** of CSRF protection. This specification defines the semantics for token generation, refresh, synchronization, and invalidation.

### Design Principles

1. **Per-Session Token** (not per-request)
2. **Lazy Rotation** (not proactive)
3. **Hard Expiry** (not sliding TTL)
4. **Multi-Tab Sync** (via BroadcastChannel / storage events)
5. **Silent Refresh** (requires no user interaction)

---

## 2. Generation Model

### 2.1 Token Generation Timing

**Per-Session Model (Recommended):**

```
Session Start → Generate Token
Token Expiry → Silent Refresh
Session End → Token Discard
```

**Alternative (Per-Request):**

- New token for every request → high overhead
- **Reason for Rejection:** Unnecessary complexity for a stateless model.

### 2.2 Generation Trigger

**Initial Generation:**

- Upon session creation (login, anonymous session)
- When token is missing or expired

**Refresh Generation:**

- During the final 25% of TTL (e.g., last 5 minutes of a 20-minute TTL)
- Client-initiated (background fetch)
- Server-initiated (via response header: `X-CSRF-Token-Refresh: true`)

### 2.3 Generation Endpoint

**Dedicated Endpoint (Recommended):**

```
GET /api/csrf/token
Response: { "token": "...", "expiresAt": 1234567890 }
```

**Inline Generation (Alternative):**

- `X-CSRF-Token` header in every response
- **Trade-off:** Overhead vs convenience.

---

## 3. Refresh Strategy

### 3.1 Refresh Window

**Parameters:**

```javascript
{
  tokenTTL: 20 * 60 * 1000,        // 20 minutes
  refreshWindow: 0.25,              // Final 25% (5 minutes)
  refreshInterval: 60 * 1000,       // 1-minute check
  graceWindow: 60 * 1000            // 60-second overlap
}
```

**Refresh Logic:**

```javascript
function shouldRefresh(token) {
  const now = Date.now()
  const expiresAt = token.expiresAt
  const ttl = expiresAt - token.issuedAt
  const remaining = expiresAt - now

  // Refresh window = final 25%
  return remaining < ttl * 0.25
}
```

### 3.2 Silent Refresh

**Client-Side Implementation:**

```javascript
// Background refresh (no user interaction required)
async function silentRefresh() {
  try {
    const response = await fetch('/api/csrf/token', {
      credentials: 'same-origin',
    })
    const { token, expiresAt } = await response.json()

    // Persist to storage (for multi-tab sync)
    localStorage.setItem('csrf_token', token)
    localStorage.setItem('csrf_expires_at', expiresAt)

    // Notify other tabs via BroadcastChannel
    broadcastChannel.postMessage({ type: 'token_refresh', token, expiresAt })
  } catch (error) {
    // Fallback: 403 on next request → force refresh
  }
}

// Periodic check
setInterval(() => {
  const token = getCurrentToken()
  if (shouldRefresh(token)) {
    silentRefresh()
  }
}, 60 * 1000) // Check every 1 minute
```

### 3.3 Grace Window

**Problem:** An old token might still be in use during a refresh (in-flight request).

**Solution:** 60-second grace window.

```javascript
// Server-side validation
function validateToken(token) {
  const parsed = parseToken(token)
  const now = Date.now()

  // Hard expiry check
  if (now > parsed.expiresAt) {
    // Grace window check
    if (now - parsed.expiresAt < GRACE_WINDOW) {
      // Log warning but allow request
      logger.warn('Token in grace window', { kid: parsed.kid })
      return { valid: true, inGraceWindow: true }
    }
    return { valid: false, reason: 'expired' }
  }

  return { valid: true }
}
```

---

## 4. Multi-Tab Synchronization

### 4.1 Problem

A user may have multiple tabs open simultaneously:

- Tab A performs a token refresh.
- Tab B continues using the old token → results in a 403 error.

### 4.2 Solution: BroadcastChannel + Storage

**BroadcastChannel (Modern):**

```javascript
const channel = new BroadcastChannel('csrf_sync')

// Notify after token refresh
channel.postMessage({
  type: 'token_refresh',
  token,
  expiresAt,
})

// Listen in other tabs
channel.onmessage = (event) => {
  if (event.data.type === 'token_refresh') {
    updateLocalToken(event.data.token, event.data.expiresAt)
  }
}
```

**Storage Event (Fallback):**

```javascript
// Listen for localStorage changes
window.addEventListener('storage', (event) => {
  if (event.key === 'csrf_token') {
    updateLocalToken(event.newValue)
  }
})
```

### 4.3 Race Condition Protection

**Problem:** What if two tabs attempt to refresh simultaneously?

**Solution:** Leader election via Web Locks.

```javascript
// Only one tab performs the refresh
const isLeader = await navigator.locks.request(
  'csrf_refresh_lock',
  { ifAvailable: true },
  async (lock) => {
    if (lock) {
      await silentRefresh()
      return true
    }
    return false
  },
)
```

---

## 5. Token Invalidation

### 5.1 Logout Semantics

**Stateless Model → No Instant Revocation**

**Accepted Behavior:**

```
Logout → Delete cookie
Token → Remains valid until TTL expiry (max 20min)
Risk: Low (CSRF requires valid session cookie)
```

**Managing Expectations:**

- Explicitly state this behavior in documentation.
- Include in Security FAQ.
- Use short TTL (e.g., 10min) for high-security environments.

### 5.2 Optional: Kid Bump (Mini-Rotation)

**For immediate invalidation after logout:**

```javascript
// Logout endpoint
POST /api/auth/logout
Response: {
  success: true,
  csrfKidBump: true  // Hint client to fetch new token
}

// Server-side logic
function logout(sessionId) {
  // Clear session
  deleteSession(sessionId);

  // Trigger kid bump (optional)
  if (config.csrfKidBumpOnLogout) {
    rotateKey(); // increment kid
  }
}
```

**Trade-off:**

- ✅ Immediate invalidation
- ❌ Affects all users (kid is global)

### 5.3 Optional: Revocation Filter

**For high-security environments:**

```javascript
// Bloom filter / LRU cache
const revokedTokens = new LRUCache({
  max: 10000,
  ttl: 20 * 60 * 1000, // Matches token TTL
})

// Logout
function logout(sessionId) {
  const sessionHash = hash(sessionId)
  revokedTokens.set(sessionHash, true)
}

// Validation
function validateToken(token, sessionId) {
  const sessionHash = hash(sessionId)
  if (revokedTokens.has(sessionHash)) {
    return { valid: false, reason: 'revoked' }
  }
  // Proceed with normal validation
}
```

**Properties:**

- Memory-bounded (via TTL)
- Tolerates occasional false positives
- Preserves stateless core

---

## 6. Error Handling

### 6.1 Token Expired

**Client-Side:**

```javascript
// 403 response indicates token expiry
if (response.status === 403) {
  const newToken = await refreshToken()
  // Retry the request
  return fetch(url, {
    ...options,
    headers: { 'X-CSRF-Token': newToken },
  })
}
```

**Server-Side:**

```javascript
// Expired token → return 403 with a refresh hint
return {
  status: 403,
  body: { error: 'CSRF validation failed' },
  headers: { 'X-CSRF-Token-Expired': 'true' },
}
```

### 6.2 Token Refresh Failure

**Fallback:**

```javascript
// Failed refresh → force logout
if (!(await refreshToken())) {
  // Session might be invalid
  forceLogout()
  redirectToLogin()
}
```

---

## 7. Implementation Checklist

### Server-Side

- [ ] Token generation endpoint (`GET /api/csrf/token`)
- [ ] TTL parameters (20min default)
- [ ] Grace window validation (60s)
- [ ] Kid bump on logout (optional)
- [ ] Revocation filter (optional)

### Client-Side

- [ ] Silent refresh logic
- [ ] Refresh window check (final 25%)
- [ ] Multi-tab sync (BroadcastChannel + storage)
- [ ] Leader election (to prevent race conditions)
- [ ] Error handling (403 retry logic)
- [ ] Logout token cleanup

### Testing

- [ ] Token expiry edge-cases
- [ ] Multi-tab race conditions
- [ ] Grace window overlap
- [ ] Refresh failure fallback
- [ ] Logout invalidation (kid bump)

---

## 8. Configuration Reference

```javascript
{
  // Token TTL
  tokenTTL: 20 * 60 * 1000,           // 20 minutes (default)

  // Refresh window (final 25%)
  refreshWindow: 0.25,

  // Refresh check interval
  refreshInterval: 60 * 1000,         // 1 minute

  // Grace window (overlap)
  graceWindow: 60 * 1000,             // 60 seconds

  // Logout behavior
  kidBumpOnLogout: false,             // Key rotation on logout
  useRevocationFilter: false,         // Bloom filter / LRU

  // Multi-tab sync
  useBroadcastChannel: true,          // Modern browsers
  useStorageEvent: true,              // Fallback

  // Endpoints
  tokenEndpoint: '/api/csrf/token',
  refreshEndpoint: '/api/csrf/token'  // Usually the same
}
```

---

## 9. Security Considerations

### 9.1 Refresh Endpoint Security

**Critical:** Should the refresh endpoint be protected against CSRF?

**Answer:** No, because:

- It is a GET request (non-state-changing).
- Limits to same-origin only.
- Relies on cookie-based authentication.

### 9.2 Token Storage

**localStorage vs sessionStorage:**

- **localStorage:** Necessary for multi-tab synchronization.
- **sessionStorage:** Tab-isolated, no synchronization.

**XSS Risk:**

- Storing in localStorage makes it accessible via XSS.
- **Mitigation:** Implement robust CSP and XSS prevention (external to this library).

### 9.3 Clock Skew

**Client-Server Time Synchronization:**

- Client-side TTL checks may differ from server-side logic.
- **Mitigation:** Use server timestamps (do not rely solely on client clock).

```javascript
// Utilize server timestamp
const serverTime = response.headers.get('Date')
const expiresAt = new Date(serverTime).getTime() + tokenTTL
```

---

## 10. Conclusion

This specification defines the necessary semantics for a **production-grade token lifecycle**:

✅ **Per-session model** (low overhead)
✅ **Silent refresh** (no UX impact)
✅ **Multi-tab sync** (protected against race conditions)
✅ **Grace window** (protection for in-flight requests)
✅ **Logout semantics** (expectation management)

**Next Step:** One-shot token primitive for high-assurance endpoints.

---

# Part III: One-Shot Token Specification

**Version:** 1.0
**Status:** Formal Specification
**Target:** High-Assurance Request Authenticity

---

## 1. Motivation

Multi-use CSRF tokens are sufficient for most scenarios. However, for **high-risk endpoints**, the replay window is unacceptable:

- Fund transfers
- Account deletions
- Permission changes
- Signature operations
- Critical configuration changes

For these endpoints, a **one-shot token** is required: **single-use, relay impossible**.

---

## 2. Design Principles

1. **Single-Use:** Token can be used exactly once.
2. **Bounded Cache:** Preserves stateless core (small TTL-bounded cache).
3. **Selective:** Used only on high-assurance endpoints.
4. **Backward Compatible:** Works alongside normal CSRF tokens.

---

## 3. Token Format

### 3.1 Structure

```
one_shot_token = base64url(
  nonce | ts | action | ctx | mac
)
```

**Fields:**

- **nonce:** 128-bit (crypto.getRandomValues) — **unique identifier**
- **ts:** unix timestamp (int64)
- **action:** endpoint identifier hash (SHA-256)
- **ctx:** context binding (session/user/origin hash)
- **mac:** HMAC-SHA256(secret, nonce|ts|action|ctx)

### 3.2 Action Binding

**Critical:** The token must be bound to a specific action.

```javascript
// Action identifier
const action = hash('POST:/api/account/delete')

// Token generation
const token = generateOneShotToken({
  action,
  sessionId,
  userId,
})
```

**Advantage:** The token cannot be used for any other endpoint (prevents cross-action replay).

---

## 4. Generation

### 4.1 Generation Endpoint

**Dedicated Endpoint:**

```
POST /api/csrf/one-shot
Body: { "action": "POST:/api/account/delete" }
Response: {
  "token": "...",
  "expiresAt": 1234567890,
  "action": "POST:/api/account/delete"
}
```

**Security:**

- Same-origin only
- Authenticated request
- Rate-limited (DoS prevention)

### 4.2 Generation Logic

```javascript
function generateOneShotToken(action, sessionId, userId) {
  // Nonce (unique identifier)
  const nonce = crypto.getRandomValues(new Uint8Array(16))

  // Timestamp
  const ts = Date.now()

  // Action hash
  const actionHash = hash(action)

  // Context binding
  const ctx = hash(sessionId + userId + origin)

  // MAC
  const mac = hmac(secret, nonce + ts + actionHash + ctx)

  // Encode
  const token = base64url(nonce + ts + actionHash + ctx + mac)

  // Cache nonce (TTL = 2-5 minutes)
  nonceCache.set(nonce, { ts, action, used: false }, TTL)

  return { token, expiresAt: ts + TTL }
}
```

### 4.3 Nonce Cache

**Bounded Cache (LRU / TTL):**

```javascript
const nonceCache = new LRUCache({
  max: 10000, // Max 10k concurrent one-shot tokens
  ttl: 5 * 60 * 1000, // 5-minute TTL
})
```

**Properties:**

- Memory-bounded (via TTL)
- Preserves stateless core (cache is temporary)
- Supports high concurrency

---

## 5. Validation

### 5.1 Validation Logic

```javascript
function validateOneShotToken(token, action, sessionId, userId) {
  // Parse token
  const parsed = parseToken(token)

  // TTL check
  const now = Date.now()
  if (now > parsed.ts + TTL) {
    return { valid: false, reason: 'expired' }
  }

  // MAC verification (constant-time)
  const expectedMac = hmac(secret, parsed.nonce + parsed.ts + parsed.actionHash + parsed.ctx)
  if (!crypto.timingSafeEqual(parsed.mac, expectedMac)) {
    return { valid: false, reason: 'invalid_mac' }
  }

  // Action binding check
  const actionHash = hash(action)
  if (parsed.actionHash !== actionHash) {
    return { valid: false, reason: 'action_mismatch' }
  }

  // Context binding check
  const ctx = hash(sessionId + userId + origin)
  if (parsed.ctx !== ctx) {
    return { valid: false, reason: 'context_mismatch' }
  }

  // Nonce check (replay prevention)
  const cached = nonceCache.get(parsed.nonce)
  if (!cached) {
    return { valid: false, reason: 'nonce_not_found' }
  }
  if (cached.used) {
    // CRITICAL: Replay attempt detected
    logger.error('One-shot token replay attempt', {
      nonce: parsed.nonce,
      action,
    })
    return { valid: false, reason: 'replay_attempt' }
  }

  // Mark as used (atomic operation)
  nonceCache.set(parsed.nonce, { ...cached, used: true }, TTL)

  return { valid: true }
}
```

### 5.2 Replay Prevention

**Critical:** The nonce cache "used" flag prevents replay.

**Race Condition Protection:**

```javascript
// Atomic compare-and-swap
function markNonceAsUsed(nonce) {
  return nonceCache.compareAndSwap(
    nonce,
    (cached) => cached.used === false,
    (cached) => ({ ...cached, used: true }),
  )
}

// Within validation logic
if (!markNonceAsUsed(parsed.nonce)) {
  return { valid: false, reason: 'replay_attempt' }
}
```

---

## 6. Integration

### 6.1 Client-Side Usage

**Step 1: Request One-Shot Token**

```javascript
async function deleteAccount() {
  // 1. Fetch one-shot token
  const { token } = await fetch('/api/csrf/one-shot', {
    method: 'POST',
    body: JSON.stringify({ action: 'POST:/api/account/delete' }),
    credentials: 'same-origin',
  }).then((r) => r.json())

  // 2. Execute high-risk action
  const response = await fetch('/api/account/delete', {
    method: 'POST',
    headers: { 'X-CSRF-One-Shot-Token': token },
    credentials: 'same-origin',
  })

  return response
}
```

**Step 2: Token Usage**

- Token can be used exactly once.
- Retries require a new token.

### 6.2 Server-Side Integration

**Middleware:**

```javascript
function oneShotTokenMiddleware(req, res, next) {
  // Check for high-assurance endpoint
  if (!isHighAssuranceEndpoint(req.path)) {
    return next() // Normal CSRF token is sufficient
  }

  // Extract one-shot token
  const token = req.headers['x-csrf-one-shot-token']
  if (!token) {
    return res.status(403).json({
      error: 'One-shot token required',
    })
  }

  // Validate
  const action = `${req.method}:${req.path}`
  const result = validateOneShotToken(token, action, req.sessionId, req.userId)

  if (!result.valid) {
    logger.warn('One-shot token validation failed', {
      reason: result.reason,
      action,
    })
    return res.status(403).json({
      error: 'CSRF validation failed',
    })
  }

  next()
}
```

---

## 7. Configuration

### 7.1 Endpoint Classification

**High-Assurance Endpoints:**

```javascript
const highAssuranceEndpoints = [
  'POST:/api/account/delete',
  'POST:/api/transfer/money',
  'PUT:/api/permissions/grant',
  'DELETE:/api/data/purge',
  'POST:/api/signature/sign',
]

function isHighAssuranceEndpoint(path) {
  return highAssuranceEndpoints.some((pattern) => matchPattern(pattern, path))
}
```

### 7.2 TTL Configuration

```javascript
{
  // One-shot token TTL
  oneShotTTL: 5 * 60 * 1000,      // 5 minutes (short duration)

  // Nonce cache
  nonceCacheSize: 10000,          // Max concurrent tokens
  nonceCacheTTL: 5 * 60 * 1000,   // Same as TTL

  // Rate limiting
  oneShotRateLimit: {
    windowMs: 60 * 1000,          // 1 minute
    max: 10                       // Max 10 tokens/minute
  }
}
```

---

## 8. Security Considerations

### 8.1 Nonce Cache Security

**Question:** Is the nonce cache a memory attack surface?

**Answer:** No, because:

- TTL-bounded (5 minutes)
- Size-bounded (10k max)
- LRU eviction
- Memory footprint: ~1MB (10k entries \* ~100 bytes)

### 8.2 Replay Window

**One-Shot vs Multi-Use:**

- **Multi-Use:** Replay window = TTL (20 minutes)
- **One-Shot:** Replay window = 0 (impossible)

### 8.3 DoS Risk

**Problem:** Can an attacker generate an excessive number of one-shot tokens?

**Mitigation:**

- Rate limiting (10 tokens/minute)
- Authenticated requests required
- Nonce cache size limit (10k)

### 8.4 Action Binding Bypass

**Question:** Can a token be used for a different action?

**Answer:** No, because:

- Action hash is contained within the token.
- Action match is verified during validation.

---

## 9. Performance Impact

### 9.1 Overhead

**Generation:**

- Nonce generation: ~1µs
- HMAC: ~50µs
- Cache write: ~10µs
- **Total:** ~60µs

**Validation:**

- Parsing: ~10µs
- HMAC verification: ~50µs
- Cache read: ~10µs
- Cache update (mark used): ~10µs
- **Total:** ~80µs

**Summary:** Minimal overhead (acceptable for high-assurance endpoints).

### 9.2 Memory Footprint

```
Nonce cache: 10k entries * 100 bytes = ~1MB
```

**Summary:** Negligible for modern server environments.

---

## 10. Error Handling

### 10.1 Token Generation Failure

**Client-Side:**

```javascript
try {
  const { token } = await requestOneShotToken(action)
} catch (error) {
  // Rate limit exceeded
  if (error.status === 429) {
    showError('Too many requests, please wait')
  }
  // Server error
  else {
    showError('Unable to generate token, please try again')
  }
}
```

### 10.2 Validation Failure

**Server-Side:**

```javascript
if (result.reason === 'replay_attempt') {
  // CRITICAL: Security incident detected
  logger.error('One-shot token replay', {
    sessionId,
    userId,
    action,
  })
  // Optional: Invalidate session
  invalidateSession(sessionId)
}
```

---

## 11. Testing

### 11.1 Test Cases

**Functional:**

- [ ] Token generation success
- [ ] Token validation success
- [ ] Token single-use enforcement
- [ ] Replay attempt detection
- [ ] Action binding enforcement
- [ ] Context binding enforcement
- [ ] TTL expiry

**Security:**

- [ ] Replay attack (same token used twice)
- [ ] Cross-action attack (token used for different endpoint)
- [ ] Context mismatch (different session/user)
- [ ] Expired token rejection
- [ ] Invalid MAC rejection

**Performance:**

- [ ] High concurrency (1,000 concurrent tokens)
- [ ] Nonce cache eviction (via TTL)
- [ ] Memory footprint verification (10k tokens)

---

## 12. Migration Path

### 12.1 Backward Compatibility

**Phased Rollout:**

1. **Phase 1:** Add one-shot token generation endpoint.
2. **Phase 2:** Support as optional on high-assurance endpoints.
3. **Phase 3:** Make mandatory on high-assurance endpoints.
4. **Phase 4:** Expand to all high-risk endpoints.

### 12.2 Fallback Strategy

**During transition:**

```javascript
// Use one-shot token if present, otherwise fallback to normal CSRF token
if (req.headers['x-csrf-one-shot-token']) {
  validateOneShotToken(...);
} else if (req.headers['x-csrf-token']) {
  validateNormalToken(...);
} else {
  return 403;
}
```

---

## 13. Conclusion

One-shot tokens provide security at the **request authenticity primitive** level:

✅ **Replay impossible** (via nonce cache)
✅ **Action binding** (prevents cross-action replay)
✅ **Minimal overhead** (~80µs validation)
✅ **Bounded cache** (preserves stateless core)
✅ **Selective usage** (targets only high-assurance endpoints)

**System Evolution:**

- CSRF Middleware → **Request Authenticity Framework**
- Token Validation → **Cryptographic Proof of Intent**

---

