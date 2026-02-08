# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| Latest | Yes |
| Previous minor | Security fixes only |
| Older | No |

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

Thank you for helping keep Sigil-Security and its users safe.
