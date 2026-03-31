---
name: sigil-boundary-check
description: 'Audit a file, package, or PR for Sigil-Security layer boundary violations. Use when implementing new code in core/policy/runtime/ops/client, reviewing imports, adding dependencies, or checking if a feature belongs in the correct layer. Keywords: boundary, layer violation, architecture, dependency direction, cross-layer, import, core boundary, sigil architecture check.'
argument-hint: "file, package, or description to audit (e.g. 'packages/core/src/validation.ts' or 'policy layer')"
---

# Sigil Boundary Check

Audits source files or packages against the normative layer boundary rules from `docs/BOUNDARY_SPECIFICATION.md`.

## When to Use

- Before adding an import in any package
- When implementing a new feature — to confirm it belongs in the right layer
- When a code review reveals a possible cross-layer dependency
- When scaffolding a new package to verify it respects the hierarchy

## Layer Map

```
client → runtime → policy → core
                   ops ───→ runtime
```

| Package   | May import                | MUST NOT import              |
| --------- | ------------------------- | ---------------------------- |
| `core`    | nothing (sigil packages)  | policy, runtime, ops, client |
| `policy`  | core                      | runtime, ops, client         |
| `runtime` | policy, core              | ops, client                  |
| `ops`     | runtime, policy, core     | client                       |
| `client`  | (standalone browser code) | —                            |

## Audit Procedure

### Step 1 — Identify the target

Determine which package(s) are in scope. If a file path was provided, infer its package from the path prefix.

### Step 2 — Read BOUNDARY_SPECIFICATION.md

Load `docs/BOUNDARY_SPECIFICATION.md` (normative) and `docs/SPECIFICATION.md` for token model context.

### Step 3 — Scan imports

For each TypeScript file in scope, check:

- All `import` statements that reference other `@sigil-security/*` packages
- All `import` statements that reference HTTP objects (`Request`, `Response`, `NextFunction`, framework types)
- Any `process.env` access in `core` or `policy`
- Any I/O calls (`fetch`, `fs.*`, `db.*`) in `core`

### Step 4 — Check `core` hard prohibitions

Flag any occurrence of:

- [ ] `Request`, `Response`, `req`, `res`, `ctx` parameter types in `packages/core/**`
- [ ] Framework imports (`express`, `fastify`, `hono`, `oak`, etc.) in `packages/core/**` or `packages/policy/**`
- [ ] `console.log`, `logger.*`, `metrics.*` in `packages/core/**`
- [ ] `fetch()`, `fs.*`, `process.env` in `packages/core/**`
- [ ] `crypto.subtle` called directly outside `CryptoProvider` implementation

### Step 5 — Verify dependency graph

Check `package.json` in the target package:

- `dependencies` and `devDependencies` entries that are other `@sigil-security/*` packages
- Confirm the direction matches the allowed map above

### Step 6 — Report findings

For each violation, output:

```
VIOLATION [SEVERITY: CRITICAL|WARNING]
File: <path>
Line: <n>
Rule: <which boundary rule was broken>
Fix: <concrete refactoring suggestion>
```

If no violations are found, confirm: `BOUNDARY CHECK PASSED — no layer violations detected.`

## Decision Guide

| Question                                         | Answer                                            |
| ------------------------------------------------ | ------------------------------------------------- |
| Does this code need `Request`/`Response`?        | → It belongs in `runtime`, not `core` or `policy` |
| Does this code check Origin/Method/Content-Type? | → It belongs in `policy`                          |
| Does this code emit metrics or logs?             | → It belongs in `ops` (wrapping `runtime`)        |
| Does this code manage multi-tab sync or refresh? | → It belongs in `client`                          |
| Is this pure crypto / token logic?               | → It belongs in `core`                            |

## References

- [BOUNDARY_SPECIFICATION.md](../../../docs/BOUNDARY_SPECIFICATION.md) — normative (read first)
- [SPECIFICATION.md](../../../docs/SPECIFICATION.md) — token model and validation layers
- [MODEL_GENERALIZATION.md](../../../docs/MODEL_GENERALIZATION.md) — extended security model
