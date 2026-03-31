# Quickstart

This guide is the fastest path to a working Sigil setup.

## 1. Pick the package

- Use `@sigil-security/runtime` for almost all application integrations. It is the normal starting point.
- Use `@sigil-security/core` only if you are building a custom runtime or working directly at the cryptographic primitive layer.
- Use `@sigil-security/policy` only if you need to compose request-validation rules outside the shipped runtime adapters.
- Add `@sigil-security/client` if you want browser-side refresh, multi-tab sync, or fetch interception.
- Add `@sigil-security/ops` if you want metrics and structured logging.

## 2. Install

```bash
pnpm add @sigil-security/runtime
```

Advanced or optional packages:

```bash
pnpm add @sigil-security/core
pnpm add @sigil-security/policy
pnpm add @sigil-security/client
pnpm add @sigil-security/ops
```

For most teams, `runtime` alone is enough. `core` and `policy` are intentionally not part of the default install path because they are lower-level building blocks rather than the primary application entry point.

## 3. Create the runtime instance

```ts
import { createSigil } from '@sigil-security/runtime'

export const sigil = await createSigil({
  masterSecret: process.env.SIGIL_MASTER_SECRET!,
  allowedOrigins: ['https://app.example.com'],
  oneShotEnabled: true,
})
```

Recommendations:

- use a master secret with at least 32 bytes of entropy
- list every browser origin that should be allowed to perform protected requests
- enable one-shot tokens only for high-assurance actions

## 4. Protect your framework

### Express

```ts
import express from 'express'
import { createExpressMiddleware } from '@sigil-security/runtime/express'
import { sigil } from './sigil'

const app = express()
app.use(express.json())
app.use(createExpressMiddleware(sigil, {
  excludePaths: ['/health'],
}))
```

### Fastify

```ts
import Fastify from 'fastify'
import { createFastifyPlugin } from '@sigil-security/runtime/fastify'
import { sigil } from './sigil'

const fastify = Fastify()
fastify.register(createFastifyPlugin(sigil, {
  excludePaths: ['/health'],
}))
```

### Native Fetch / Edge

```ts
import { createFetchMiddleware } from '@sigil-security/runtime/fetch'
import { sigil } from './sigil'

const handler = createFetchMiddleware(sigil, async () => {
  return new Response(JSON.stringify({ ok: true }), {
    headers: { 'content-type': 'application/json' },
  })
})
```

## 5. Token endpoints

The runtime layer exposes built-in endpoints:

- `GET /api/csrf/token` returns a regular CSRF token
- `POST /api/csrf/one-shot` returns an action-bound single-use token when one-shot support is enabled

Your frontend should fetch a regular token before the first protected mutation.

## 6. Optional browser client

`@sigil-security/client` wraps that lifecycle for browser apps.

```ts
import { createSigilClient } from '@sigil-security/client'

const sigilClient = createSigilClient({
  autoStart: true,
  tokenEndpointPath: '/api/csrf/token',
  oneShotEndpointPath: '/api/csrf/one-shot',
})

await sigilClient.refreshToken(true)
const response = await sigilClient.fetch('/api/account', {
  method: 'POST',
  body: JSON.stringify({ displayName: 'Ada' }),
})
```

`client` is still experimental and currently best suited for early adopters inside controlled deployments.

## 7. Optional telemetry

```ts
import { createTelemetryMiddleware } from '@sigil-security/ops'
import { createNoopMetricsCollector } from '@sigil-security/ops'

const observedSigil = createTelemetryMiddleware(sigil, {
  metrics: createNoopMetricsCollector(),
})
```

`ops` is also still experimental.

## Next Reads

- [Root README](../README.md)
- [Integration Guide](./INTEGRATION_GUIDE.md)
- [Runtime package README](../packages/runtime/README.md)
- [Specification](./SPECIFICATION.md)
- [Operations Manual](./OPERATIONS.md)
