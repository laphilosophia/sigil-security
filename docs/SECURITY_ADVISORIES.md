# Security Advisories

**Purpose:** Third-party dependency vulnerabilities and Sigil’s exposure.

---

## CVE-2024-49770 — @oakserver/oak (Directory Traversal)

**CWE:** CWE-35 (Path Traversal)  
**CVE:** [CVE-2024-49770](https://www.cve.org/CVERecord?id=CVE-2024-49770)  
**Snyk:** [SNYK-JS-OAKSERVEROAK-8323729](https://security.snyk.io/vuln/SNYK-JS-OAKSERVEROAK-8323729)  
**CVSS:** 8.7 (High)

### Summary

Oak’s **`Context.send`** API (static file serving) is vulnerable to directory traversal when `/` is encoded as `%2F`. Attackers can read files under the served root (e.g. `.env`, `.git/config`).

### Sigil’s Exposure

- **Runtime Oak adapter** (`@sigil-security/runtime/oak`) **does not use `Context.send`**. It only:
  - Reads request path, method, headers, body
  - Handles token endpoint and `protect()` flow
  - Sets `ctx.response.status`, `ctx.response.body`, `ctx.response.headers`
  - Calls `await next()`
- **Ops** does not depend on Oak; it depends on `@sigil-security/runtime`. Snyk may still flag the tree when Oak is installed as a peer of runtime.

**Conclusion:** Sigil’s Oak integration is **not** on a code path that uses the vulnerable API. The risk appears in dependency/audit reports, not in our adapter implementation.

### Upstream Fix

- **Fixed in Oak 17.1.3** (commit `4b2f27e`).
- **npm:** `@oakserver/oak` on npm is at **14.1.0**; 17.x is **not** published on npm. Development has moved to JSR.
- **JSR/Deno:** Use `jsr:@oak/oak@17.1.3` or later for the fix.

### Options (Summary)

| Option | Pros | Cons |
|--------|------|------|
| **Drop Oak support** | No Oak in dependency tree; Snyk clean | Deno users lose the adapter |
| **Ad-hoc patch** | N/A | We don’t publish Oak; npm has no 17.x to patch |
| **Wait for upstream** | No code change | npm may never get 17.1.3+ |
| **Document + optional peer** | Accurate risk (we don’t use `send`); users can choose JSR | Snyk may still report the peer |

**Recommendation:** Keep Oak support; document that our adapter does not use `Context.send` and that users who use Oak for static file serving should use JSR `@oak/oak@17.1.3+` or avoid `context.send()` with user-controlled paths. Optionally constrain or document the Oak peer (e.g. JSR for Deno users).

---

**Last Updated:** 2026-02-15
