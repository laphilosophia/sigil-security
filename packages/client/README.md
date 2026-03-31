# @sigil-security/client

Experimental browser-side Sigil helpers.

## Status

This package is implemented and tested, but still published under the `experimental` tag.

## What it contains

- token storage helpers
- silent refresh controller
- multi-tab sync via BroadcastChannel and storage fallback
- leader election for coordinated refresh
- fetch interception and one-shot token helper

## Install

```bash
pnpm add @sigil-security/client
```

## Example

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

## Use it when

Use `client` if you want Sigil-managed token refresh and browser fetch wrapping. If you only need server-side enforcement, `@sigil-security/runtime` is enough.
