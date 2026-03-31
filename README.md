# Sigil-Security

Stateless cryptographic request intent verification for web applications.

Sigil combines cryptographic tokens, request provenance checks, and optional replay protection to verify that a state-changing request is both authentic and contextually valid. The monorepo is organized as layered packages so teams can adopt only the surface they need.

## Packages

| Package | Purpose | Status |
| --- | --- | --- |
| `@sigil-security/core` | token generation, validation, HKDF/HMAC, one-shot primitives | stable |
| `@sigil-security/policy` | Fetch Metadata, Origin, method, content-type, context policies | stable |
| `@sigil-security/runtime` | framework adapters and orchestration | stable |
| `@sigil-security/client` | browser token lifecycle helpers | experimental |
| `@sigil-security/ops` | telemetry and anomaly detection wrappers | experimental |

## Install

Most applications will start with the runtime package:

```bash
pnpm add @sigil-security/runtime
```

Optional packages:

```bash
pnpm add @sigil-security/client
pnpm add @sigil-security/ops
```

## Quick Start

```ts
import { createSigil } from '@sigil-security/runtime'
import { createExpressMiddleware } from '@sigil-security/runtime/express'

const sigil = await createSigil({
  masterSecret: process.env.SIGIL_MASTER_SECRET!,
  allowedOrigins: ['https://app.example.com'],
  oneShotEnabled: true,
})

app.use(createExpressMiddleware(sigil, {
  excludePaths: ['/health'],
}))
```

To issue a token to the browser, expose the built-in token endpoint:

- `GET /api/csrf/token`
- `POST /api/csrf/one-shot` when one-shot tokens are enabled

A fuller getting-started guide lives in [docs/QUICKSTART.md](./docs/QUICKSTART.md).

## Documentation

- [Quickstart](./docs/QUICKSTART.md)
- [Documentation Index](./docs/README.md)
- [Specification](./docs/SPECIFICATION.md)
- [Boundary Specification](./docs/BOUNDARY_SPECIFICATION.md)
- [Operations Manual](./docs/OPERATIONS.md)
- [Benchmarking](./docs/BENCHMARKING.md)
- [Implementation Plan](./docs/IMPLEMENTATION_PLAN.md)

Package-specific READMEs:

- [core](./packages/core/README.md)
- [policy](./packages/policy/README.md)
- [runtime](./packages/runtime/README.md)
- [client](./packages/client/README.md)
- [ops](./packages/ops/README.md)

## Security Model

Sigil treats a request as valid only when all of these hold:

```text
Integrity AND Context AND Freshness AND Provenance
```

In practice that means:

- integrity via HMAC verification
- freshness via TTL and optional one-shot replay prevention
- provenance via Origin and Fetch Metadata signals
- context via optional request/session bindings

## Status

- `core`, `policy`, and `runtime` are production-candidate surfaces in the repository
- `client` and `ops` are implemented but still published as experimental
- Oak and Hono adapters remain disabled pending separate security review
- Phase 6 hardening evidence is in-repo; current focus is Phase 7 release alignment, hosted CI confirmation, and package promotion decisions

## License

Apache-2.0
