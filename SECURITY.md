# Security Policy

## Supported Versions

| Version        | Supported           |
| -------------- | ------------------- |
| Latest         | Yes                 |
| Previous minor | Security fixes only |
| Older          | No                  |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in Sigil-Security, please report it responsibly:

**Email:** `me@erdem.work`

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected package(s) (`core`, `policy`, `runtime`, `ops`, `client`)
- Potential impact assessment
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 5 business days
- **Fix and disclosure:** Coordinated with reporter, typically within 30 days

### Scope

The following are in scope:

- Token forgery or MAC bypass
- Side-channel vulnerabilities (timing, length oracle)
- Key derivation or rotation flaws
- Replay protection bypass
- Context binding circumvention
- Nonce collision or predictability
- CryptoProvider implementation flaws

The following are out of scope:

- XSS (CSRF defense does not prevent XSS — documented in threat model)
- Denial of service via high request volume (rate limiting is external)
- Issues requiring physical access to the server
- Social engineering

### Disclosure Policy

We follow coordinated disclosure. We will:

1. Confirm the vulnerability and determine its impact.
2. Develop and test a fix.
3. Release the fix with a security advisory.
4. Credit the reporter (unless anonymity is requested).

---

## Known Intentional Spec Deviations

### `X-CSRF-Token-Expired` Response Header

**Specification rule:** "NEVER differentiate error types to the client -- single message: `CSRF validation failed`"

**Deviation:** When a CSRF token is rejected due to TTL expiry, Sigil includes a `X-CSRF-Token-Expired: true` header in the 403 response. The response body remains the uniform `{ "error": "CSRF validation failed" }` message.

**Rationale:** This header enables client-side silent token refresh without user-visible errors. The browser SDK (`@sigil-security/client`) uses this header to detect expiry, request a fresh token, and retry the original request transparently.

**Security impact:** An attacker who observes this header on a rejected request learns that the token was structurally valid and had a correct HMAC -- only the freshness check failed. This narrows the information an attacker needs from "which validation step failed" to "just solve the timing problem." However:

- The attacker already possesses a previously valid token (they cannot forge one).
- Token expiry is time-bounded and not exploitable in practice.
- Without this header, the same information could be inferred by timing (expired tokens still complete full validation, only differing in the last check).

**Mitigation for strict environments:** If this information leak is unacceptable for your threat model, you can override the error response by wrapping the adapter middleware and stripping the header before sending the response.

---

Thank you for helping keep Sigil-Security and its users safe.
