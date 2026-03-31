# @sigil-security/core

Low-level cryptographic primitives used by the higher Sigil layers.

## What it contains

- HKDF-based domain-separated key derivation
- HMAC token generation and validation
- constant-time comparison helpers
- one-shot token primitives with nonce-cache replay protection
- zero external runtime dependencies

## Install

```bash
pnpm add @sigil-security/core
```

## Example

```ts
import {
  WebCryptoCryptoProvider,
  createKeyring,
  getActiveKey,
  generateToken,
  validateToken,
} from '@sigil-security/core'

const provider = new WebCryptoCryptoProvider()
const masterSecret = new TextEncoder().encode(process.env.SIGIL_MASTER_SECRET!).buffer
const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
const key = getActiveKey(keyring)
if (key === undefined) throw new Error('missing active key')

const issued = await generateToken(provider, key)
if (!issued.success) throw new Error(issued.reason)

const validation = await validateToken(provider, keyring, issued.token)
```

## When to use it directly

Use `core` only if you are building a custom runtime, custom adapter, or doing low-level security experimentation. Most applications should start with `@sigil-security/runtime`.
