---
name: sigil-code-review
description: 'TypeScript code quality review for Sigil-Security packages. Use when reviewing a PR, refactoring a module, writing new functions, checking naming conventions, evaluating SOLID/KISS/YAGNI/DRY compliance, or assessing test coverage. Keywords: code review, TypeScript, SOLID, KISS, YAGNI, DRY, naming, testing, vitest, strict mode, result pattern, pure function, test coverage, function length, module design.'
argument-hint: "file or module to review (e.g. 'packages/policy/src/fetch-metadata.ts' or a PR diff)"
---

# Sigil Code Review

Reviews TypeScript source files against the code quality standards defined for this project: strict typing, SOLID/KISS/YAGNI/DRY principles, naming conventions, function design, and test coverage expectations.

## When to Use

- Before merging a PR that touches any `.ts` file
- When refactoring an existing module
- When writing new functions, classes, or interfaces
- When evaluating whether a module should be split or merged
- When checking if tests adequately cover new behavior

## Review Checklist

### 1. TypeScript Strictness

- [ ] `strict: true` is set in the relevant `tsconfig.json`
- [ ] No `any` — use `unknown` + type narrowing at system boundaries (framework adapter edges are an exception with runtime validation)
- [ ] All **exported functions have explicit return types**
- [ ] Immutable properties use `readonly`
- [ ] Literal constants use `as const`
- [ ] Security-critical string values use **branded types**: `type TokenString = string & { readonly __brand: 'Token' }`
- [ ] Validation results use the **Result pattern**: `{ valid: true; ... } | { valid: false; reason: string }` — not thrown exceptions

### 2. Function Design

- [ ] Functions in `core` are **pure** — deterministic, no side-effects (except ephemeral cache)
- [ ] Testability injection: `now` (or similar time parameter) is accepted as a parameter, never hardcoded via `Date.now()`
- [ ] Max function length: **~40 lines** — extract sub-operations if longer
- [ ] Max file length: **~300 lines** — split into focused modules if longer
- [ ] Single responsibility per function (no "validate AND log AND mutate" in one function)

Good example:

```typescript
export function validateTTL(
  tokenTimestamp: number,
  ttlMs: number,
  graceWindowMs: number,
  now: number = Date.now(),
): { withinTTL: boolean; inGraceWindow: boolean } { ... }
```

Bad example:

```typescript
export function validate(req: any): boolean { ... }
```

### 3. SOLID / KISS / YAGNI / DRY

- [ ] **S — Single Responsibility**: each file has one clear purpose (`context.ts` = context ops, `token.ts` = token model)
- [ ] **O — Open/Closed**: policy validators are extensible without modifying existing validators
- [ ] **L — Liskov**: all framework adapters are substitutable (same interface, different implementation)
- [ ] **I — Interface Segregation**: interfaces are small and focused (`TokenGenerator`, `TokenValidator`, `PolicyValidator`)
- [ ] **D — Dependency Inversion**: `core` depends on `CryptoProvider` abstraction, not `crypto.subtle` directly
- [ ] **KISS**: smallest correct implementation — no over-engineering, no speculative abstractions
- [ ] **YAGNI**: only what the spec defines — no "nice to have" features
- [ ] **DRY**: shared buffer operations, encoding, and parsing are centralized (not copy-pasted)

### 4. Naming Conventions

| Target             | Convention                            | Example                                     |
| ------------------ | ------------------------------------- | ------------------------------------------- |
| Files              | `kebab-case.ts`                       | `nonce-cache.ts`, `fetch-metadata.ts`       |
| Types / Interfaces | `PascalCase`                          | `ValidationResult`, `TokenConfig`           |
| Functions          | `camelCase`, verb-first               | `generateToken`, `validateMAC`, `deriveKey` |
| Constants          | `UPPER_SNAKE_CASE`                    | `NONCE_SIZE`, `MAX_TOKEN_TTL_MS`            |
| Private            | avoid `_prefix`; prefer module-scoped | —                                           |

### 5. Error Handling

- [ ] `core` returns `Result` objects — **NEVER throws** for validation failures
- [ ] Adapter layer catches errors and **translates to HTTP responses**
- [ ] Unexpected errors (crypto failures) may throw — callers must handle them
- [ ] No empty `catch` blocks; no swallowed errors

### 6. Tests

- [ ] Every exported function has **unit tests**
- [ ] Test file mirrors source: `src/token.ts` → `__tests__/token.test.ts`
- [ ] Test naming: `describe('functionName')` → `it('should [behavior] when [condition]')`
- [ ] Uses **vitest** — no jest
- [ ] Security-specific tests: replay attacks, fuzzing, boundary values, malformed input
- [ ] Benchmark tests for crypto operations (target: validation < 50µs)

### 7. Dependencies

- [ ] `core` has **ZERO runtime dependencies**
- [ ] `policy` depends only on `@sigil-security/core`
- [ ] `runtime` has **peer dependencies** on framework packages (not hard dependencies)
- [ ] Every new dependency has an explicit justification — prefer standard APIs

## Report Format

For each issue found:

```
ISSUE [SEVERITY: BLOCKING|SUGGESTION]
File: <path>
Line: <n>
Category: <strictness / design / naming / tests / dependencies / SOLID>
Issue: <description>
Fix: <concrete action>
```

At the end, provide a summary:

- Total BLOCKING issues (must fix before merge)
- Total SUGGESTION issues (nice to address)
- Overall quality verdict: APPROVED | NEEDS CHANGES

## Procedure

1. Read the target file(s) fully
2. Work through each checklist section — note passes and failures
3. For each failure, record a finding with the correct severity
4. Output the checklist summary, findings grouped by severity, and verdict

## References

- [SPECIFICATION.md](../../../docs/SPECIFICATION.md) — feature scope and expected behaviors
- [BOUNDARY_SPECIFICATION.md](../../../docs/BOUNDARY_SPECIFICATION.md) — what belongs where
- [IMPLEMENTATION_PLAN.md](../../../docs/IMPLEMENTATION_PLAN.md) — intended implementation details
