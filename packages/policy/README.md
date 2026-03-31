# @sigil-security/policy

Request-metadata policy building blocks for Sigil.

## What it contains

- Fetch Metadata validation
- Origin / Referer validation
- method and content-type policies
- client mode detection
- composable policy chains

## Install

```bash
pnpm add @sigil-security/policy
```

## Example

```ts
import {
  createFetchMetadataPolicy,
  createOriginPolicy,
  createPolicyChain,
} from '@sigil-security/policy'

const chain = createPolicyChain([
  createFetchMetadataPolicy({ legacyBrowserMode: 'degraded' }),
  createOriginPolicy({ allowedOrigins: ['https://app.example.com'] }),
])

const result = chain.validate({
  method: 'POST',
  origin: 'https://app.example.com',
  referer: null,
  secFetchSite: 'same-origin',
  secFetchMode: 'cors',
  secFetchDest: 'empty',
  contentType: 'application/json',
  tokenSource: { from: 'header', value: 'token' },
})
```

## When to use it directly

Use `policy` when you want to compose or test request-validation rules independently. Application teams usually consume these rules through `@sigil-security/runtime`.
