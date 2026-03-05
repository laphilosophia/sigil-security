# Security Advisories

**Purpose:** Third-party dependency vulnerabilities and Sigil’s exposure.

---

## Runtime Adapter Support Status (2026-03-05)

Sigil temporarily removed support for the following runtime adapters:

- `@sigil-security/runtime/oak`
- `@sigil-security/runtime/hono`

This is a risk-reduction decision based on reported high/medium severity findings. Support will remain disabled until remediation is completed and verified.

### Reported findings (input from security report)

- **Oak:** CWE-35, CVSS 8.7
- **Hono:** CWE-1333, CVSS 6.9
- **Hono:** CWE-208, CVSS 6.3

---

## CVE-2024-49770 — @oakserver/oak (Directory Traversal)

**CWE:** CWE-35 (Path Traversal)  
**CVE:** [CVE-2024-49770](https://www.cve.org/CVERecord?id=CVE-2024-49770)  
**Snyk:** [SNYK-JS-OAKSERVEROAK-8323729](https://security.snyk.io/vuln/SNYK-JS-OAKSERVEROAK-8323729)  
**CVSS:** 8.7 (High)

### Summary

Oak’s **`Context.send`** API (static file serving) is vulnerable to directory traversal when `/` is encoded as `%2F`. Attackers can read files under the served root (e.g. `.env`, `.git/config`).

### Sigil Decision

- Oak adapter support is currently disabled in `@sigil-security/runtime`.
- Oak peer dependency is removed from the runtime package to keep it out of the dependency tree until remediation.

---

**Last Updated:** 2026-03-05
