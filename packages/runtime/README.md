# @sigil-security/runtime

Framework-facing Sigil package for server integration.

## What it contains

- `createSigil()` orchestration entry point
- Express, Fastify, Elysia, and native Fetch adapters
- built-in token endpoint handling
- request metadata extraction and protection flow

## Install

```bash
pnpm add @sigil-security/runtime
```

Optional peer adapters:

```bash
pnpm add express
pnpm add fastify
pnpm add elysia
```

## Example

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

## Built-in endpoints

- `GET /api/csrf/token`
- `POST /api/csrf/one-shot` when `oneShotEnabled` is true

## Adapter imports

- `@sigil-security/runtime/express`
- `@sigil-security/runtime/fastify`
- `@sigil-security/runtime/elysia`
- `@sigil-security/runtime/fetch`

## Notes

- Oak and Hono adapters are intentionally not shipped right now.
- Most users should start here, then optionally add `@sigil-security/client` or `@sigil-security/ops`.
