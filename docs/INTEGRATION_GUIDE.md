# Integration Guide

This guide is the main walkthrough for adopting Sigil in a real application.

Use it when you want to answer questions like:

- which package should we start with?
- what does a complete server integration look like?
- when do we need `client` or `ops`?
- what endpoints do we expose?
- what should the frontend do?
- when is `core` or `policy` the right tool?

If you want the shortest possible path, start with [QUICKSTART.md](./QUICKSTART.md). If you want the fuller mental model and common integration patterns, stay here.

## What Sigil Is

Sigil is a stateless cryptographic request intent verification system for state-changing web requests.

At a high level, a protected request is accepted only when these all hold:

```text
Integrity AND Context AND Freshness AND Provenance
```

In practice that means:

- the token is authentic and untampered
- the request came from an allowed origin or valid browser context
- the token is still fresh
- optional one-shot or context binding rules still match

Sigil is not:

- an authentication system
- a session manager
- a general web framework
- an XSS mitigation layer

## Start With The Right Package

For most teams, the right entry point is `@sigil-security/runtime`.

| Package | Start here when... | Typical user |
| --- | --- | --- |
| `@sigil-security/runtime` | you want working protection in an app server | application teams |
| `@sigil-security/client` | you want browser-side refresh, sync, and wrapped fetch | SPA / frontend teams |
| `@sigil-security/ops` | you want metrics and structured security logs | platform / ops teams |
| `@sigil-security/policy` | you need request-policy building blocks without the full runtime | advanced integrators |
| `@sigil-security/core` | you are building a custom adapter or working at the crypto primitive layer | library / framework authors |

Recommended default:

1. start with `runtime`
2. add `client` only if browser token lifecycle becomes painful
3. add `ops` only if you need observability
4. use `policy` or `core` directly only for advanced customization

## Architecture In One View

```text
core -> policy -> runtime -> client / ops
```

- `core` handles cryptographic primitives, token generation, token validation, one-shot tokens, keyrings, and nonce cache logic
- `policy` evaluates request context such as Origin, Fetch Metadata, methods, and content type
- `runtime` turns the lower layers into framework-ready protection flows
- `client` helps browser apps acquire, refresh, and attach tokens
- `ops` wraps Sigil with metrics, anomaly checks, and structured logging

This separation matters because it keeps the core security surface small and predictable while still giving you practical integration layers.

## The Normal Integration Path

Most production integrations follow this shape:

1. create a `SigilInstance`
2. attach a runtime adapter to your framework
3. expose the built-in token endpoint
4. fetch a token before the first protected mutation
5. optionally use one-shot tokens for high-assurance actions
6. optionally add `client` and `ops`

## 1. Create The Runtime Instance

Install the runtime package:

```bash
pnpm add @sigil-security/runtime
```

Create a shared runtime instance:

```ts
import { createSigil } from '@sigil-security/runtime'

export const sigil = await createSigil({
  masterSecret: process.env.SIGIL_MASTER_SECRET!,
  allowedOrigins: ['https://app.example.com'],
  oneShotEnabled: true,
})
```

Important configuration notes:

- `masterSecret` should have at least 32 bytes of real entropy
- `allowedOrigins` should list browser origins that are allowed to perform protected mutations
- `oneShotEnabled` should be reserved for sensitive or high-assurance actions

## 2. Attach Sigil To Your Framework

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

Use this when:

- your app is mostly Express
- you want the least surprising integration path
- you already handle JSON bodies centrally

### Fastify

```ts
import Fastify from 'fastify'
import { createFastifyPlugin } from '@sigil-security/runtime/fastify'
import { sigil } from './sigil'

const fastify = Fastify()

await fastify.register(createFastifyPlugin(sigil, {
  excludePaths: ['/health'],
}))
```

Use this when:

- your service is already Fastify-first
- you want Sigil as a plugin boundary instead of generic middleware

### Native Fetch / Edge

```ts
import { createFetchMiddleware } from '@sigil-security/runtime/fetch'
import { sigil } from './sigil'

const appHandler = async (_request: Request): Promise<Response> => {
  return new Response(JSON.stringify({ ok: true }), {
    headers: { 'content-type': 'application/json' },
  })
}

export const handler = createFetchMiddleware(sigil, appHandler)
```

Use this when:

- you are on a Fetch-native platform
- you are writing for edge runtimes, workers, or a custom platform boundary

## 3. Expose Token Endpoints

Sigil ships with two built-in endpoint paths:

- `GET /api/csrf/token`
- `POST /api/csrf/one-shot`

The regular token endpoint issues a standard token for the browser.

The one-shot endpoint issues an action-bound token intended for single use. It is only active when `oneShotEnabled` is true, and the request must already carry a valid regular CSRF token.

That means the normal browser flow is:

1. request a regular token from `GET /api/csrf/token`
2. send protected mutations with that token
3. request a one-shot token only for sensitive actions that need stronger replay resistance

## 4. Frontend Integration

### Minimal Browser Flow Without `client`

If you do not need refresh orchestration, you can keep the browser side very small:

```ts
const tokenResponse = await fetch('/api/csrf/token', {
  credentials: 'same-origin',
})

const { token } = await tokenResponse.json()

await fetch('/api/account', {
  method: 'POST',
  credentials: 'same-origin',
  headers: {
    'content-type': 'application/json',
    'x-csrf-token': token,
  },
  body: JSON.stringify({ displayName: 'Ada' }),
})
```

This is often enough for:

- server-rendered apps
- simple dashboards
- forms with limited mutation behavior

### Browser Flow With `@sigil-security/client`

Add `client` when you want Sigil to manage:

- token storage
- refresh windows
- multi-tab sync
- browser fetch interception
- one-shot token acquisition

Install:

```bash
pnpm add @sigil-security/client
```

Example:

```ts
import { createSigilClient } from '@sigil-security/client'

const sigilClient = createSigilClient({
  autoStart: true,
  tokenEndpointPath: '/api/csrf/token',
  oneShotEndpointPath: '/api/csrf/one-shot',
})

await sigilClient.refreshToken(true)

await sigilClient.fetch('/api/account', {
  method: 'POST',
  body: JSON.stringify({ displayName: 'Ada' }),
})
```

Current package status:

- `client` is implemented and tested
- it is still explicitly experimental
- use it when the ergonomics help enough to justify the extra surface

## 5. High-Assurance Actions And One-Shot Tokens

One-shot tokens are for actions where replay resistance matters more than convenience.

Typical examples:

- account deletion
- password rotation
- payout or transfer initiation
- destructive admin actions

You can think of them as "use once for this action only".

Server-side:

```ts
const sigil = await createSigil({
  masterSecret: process.env.SIGIL_MASTER_SECRET!,
  allowedOrigins: ['https://app.example.com'],
  oneShotEnabled: true,
})
```

Client-side:

```ts
const oneShot = await sigilClient.requestOneShotToken('POST:/api/account/delete')
```

Use one-shot selectively. It is not necessary for every mutation in a normal CRUD app.

## 6. Observability With `@sigil-security/ops`

Add `ops` when you want Sigil-aware metrics and structured logging without changing your core integration shape.

Install:

```bash
pnpm add @sigil-security/ops
```

Example:

```ts
import {
  createTelemetryMiddleware,
  createNoopMetricsCollector,
} from '@sigil-security/ops'

const observedSigil = createTelemetryMiddleware(sigil, {
  metrics: createNoopMetricsCollector(),
})
```

Use `ops` when you need:

- metric hooks
- anomaly signals
- structured logs with redaction
- a clean place to attach platform observability

Current package status:

- `ops` is implemented and tested
- it remains explicitly experimental

## 7. Common Integration Patterns

### Pattern A: Server-Rendered App

Recommended stack:

- `runtime`
- no `client`
- no `ops` at first

Flow:

1. issue regular tokens from the runtime endpoint
2. attach them to forms or mutation requests
3. reserve one-shot only for destructive actions

### Pattern B: SPA Or Dashboard

Recommended stack:

- `runtime`
- `client`
- optional `ops`

Flow:

1. initialize `createSigilClient()`
2. let the client refresh and attach tokens
3. use one-shot for sensitive action routes

### Pattern C: Edge / Fetch-Native API

Recommended stack:

- `runtime`
- optional `ops`
- optional custom browser fetch integration instead of full `client`

Flow:

1. protect with `@sigil-security/runtime/fetch`
2. expose token endpoints
3. let the browser acquire tokens directly or via the client package

### Pattern D: Advanced Custom Adapter

Recommended stack:

- `core`
- `policy`
- optional parts of `runtime` as reference

Use this only when:

- you are integrating with a framework Sigil does not ship
- you need a very custom request extraction or platform boundary
- you understand the runtime and policy layers well enough to own the integration

## 8. What Belongs In Each Package

If you are extending Sigil, use this rule of thumb:

- put pure crypto, token, nonce cache, and keyring logic in `core`
- put Origin, Fetch Metadata, method, content-type, and mode rules in `policy`
- put framework request extraction and adapter glue in `runtime`
- put browser refresh, multi-tab sync, and fetch wrapping in `client`
- put metrics, anomaly detection, and logs in `ops`

If a change crosses those boundaries, stop and re-check the package choice.

## 9. Security Boundaries To Remember

Sigil improves state-changing request protection. It does not magically solve every web security problem.

Important boundaries:

- Sigil does not prevent XSS
- if an attacker runs code in-origin, they may still be able to misuse token issuance flows
- Sigil is not authentication or authorization
- one-shot improves replay resistance but should be used where the assurance payoff is worth the extra flow
- token errors sent to clients are intentionally generic

## 10. Common Mistakes

- starting with `core` when `runtime` would do the job
- treating `client` as mandatory when a small browser fetch flow is enough
- enabling one-shot everywhere instead of on sensitive actions only
- forgetting to list all allowed browser origins
- using a weak master secret
- expecting Sigil to solve XSS or session security on its own

## 11. What To Read Next

- [Quickstart](./QUICKSTART.md) for the shortest path
- [Security FAQ](./SECURITY_FAQ.md) for plain-language boundaries and tradeoffs
- [API Guide](./API_GUIDE.md) for package entry points and public API orientation
- [Runtime README](../packages/runtime/README.md) for runtime package details
- [Client README](../packages/client/README.md) for browser lifecycle helpers
- [Ops README](../packages/ops/README.md) for observability hooks
- [Specification](./SPECIFICATION.md) for the deeper security model
- [Boundary Specification](./BOUNDARY_SPECIFICATION.md) for package-boundary rules
- [Operations Manual](./OPERATIONS.md) for operational behavior and monitoring guidance

## Suggested Team Rollout

If your team wants a low-friction rollout, use this sequence:

1. adopt `@sigil-security/runtime`
2. expose `GET /api/csrf/token`
3. protect real mutations on one service or app slice
4. add one-shot only to high-assurance endpoints
5. add `client` only if browser lifecycle pain shows up
6. add `ops` only when you are ready to wire observability

That sequence usually gives the best balance between security value, clarity, and adoption cost.
