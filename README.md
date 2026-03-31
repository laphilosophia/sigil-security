# Sigil Security

Stateless cryptographic request intent verification for modern web applications.

Sigil verifies more than "does this request have a token?". It combines cryptographic integrity, request provenance, freshness, and optional replay protection so state-changing requests are both authentic and contextually valid.

[![CodeQL](https://github.com/laphilosophia/sigil-security/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/laphilosophia/sigil-security/actions/workflows/github-code-scanning/codeql)
[![Tests](https://github.com/laphilosophia/sigil-security/actions/workflows/ci.yml/badge.svg)](https://github.com/laphilosophia/sigil-security/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40sigil-security%2Fruntime?label=npm)](https://www.npmjs.com/package/@sigil-security/runtime)
[![License](https://img.shields.io/github/license/laphilosophia/sigil-security)](https://github.com/laphilosophia/sigil-security/blob/main/LICENSE)

## Why Sigil

- moves beyond classic synchronizer-token framing toward request intent verification
- keeps the core security surface stateless and composable
- layers policy, runtime, client, and ops surfaces so teams can adopt only what they need
- ships with in-repo hardening, benchmark, and cross-runtime validation evidence

## What Gets Verified

Sigil treats a request as valid only when all of these hold:

```text
Integrity AND Context AND Freshness AND Provenance
```

- `Integrity`: HMAC-backed token verification
- `Freshness`: TTL enforcement and optional one-shot replay protection
- `Provenance`: Origin and Fetch Metadata validation
- `Context`: optional request, route, or session binding

## Choose Your Package

| Package | Use it when... | Status |
| --- | --- | --- |
| `@sigil-security/runtime` | you want the fastest path to real app integration | production-candidate |
| `@sigil-security/core` | you need low-level token and key primitives | production-candidate |
| `@sigil-security/policy` | you want request context policy checks without full runtime orchestration | production-candidate |
| `@sigil-security/client` | you need browser-side token lifecycle helpers | experimental |
| `@sigil-security/ops` | you want telemetry, anomaly signals, and structured logs | experimental |

Most teams should start with `@sigil-security/runtime`.

## Quick Start

```bash
pnpm add @sigil-security/runtime
```

```ts
import express from 'express'
import { createSigil } from '@sigil-security/runtime'
import { createExpressMiddleware } from '@sigil-security/runtime/express'

const sigil = await createSigil({
  masterSecret: process.env.SIGIL_MASTER_SECRET!,
  allowedOrigins: ['https://app.example.com'],
  oneShotEnabled: true,
})

const app = express()
app.use(express.json())
app.use(createExpressMiddleware(sigil, {
  excludePaths: ['/health'],
}))
```

Expose the built-in token endpoints to the browser:

- `GET /api/csrf/token`
- `POST /api/csrf/one-shot` when one-shot tokens are enabled

For the full first-run path, see [docs/QUICKSTART.md](./docs/QUICKSTART.md).

## Layered Architecture

```text
core -> policy -> runtime -> client / ops
```

- `core` provides cryptographic primitives and validation building blocks
- `policy` evaluates request context rules such as Origin and Fetch Metadata
- `runtime` turns those pieces into framework-ready protection flows
- `client` and `ops` extend the system with browser lifecycle helpers and observability

## Documentation

- [Quickstart](./docs/QUICKSTART.md)
- [Documentation Index](./docs/README.md)
- [Specification](./docs/SPECIFICATION.md)
- [Boundary Specification](./docs/BOUNDARY_SPECIFICATION.md)
- [Operations Manual](./docs/OPERATIONS.md)
- [Benchmarking](./docs/BENCHMARKING.md)
- [Implementation Plan](./docs/IMPLEMENTATION_PLAN.md)

Package guides:

- [core](./packages/core/README.md)
- [policy](./packages/policy/README.md)
- [runtime](./packages/runtime/README.md)
- [client](./packages/client/README.md)
- [ops](./packages/ops/README.md)

## License

Apache-2.0
