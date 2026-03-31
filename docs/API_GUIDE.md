# API Guide

This document explains the public API surface of Sigil in a way that is meant to be read by humans, not generated tooling.

It focuses on:

- the main entry points in each package
- what each exported surface is for
- what most teams should use first
- which APIs are advanced or lower-level

If you want the adoption story first, read [INTEGRATION_GUIDE.md](./INTEGRATION_GUIDE.md). If you want package-by-package API orientation, stay here.

## How To Read This Guide

Use this rule of thumb:

- if you are integrating Sigil into an app, start with `runtime`
- if you are working in the browser, add `client` only if needed
- if you want observability, add `ops`
- only reach for `policy` or `core` directly when you need lower-level control

## `@sigil-security/runtime`

This is the primary application-facing package.

Most teams should start here.

### Main Entry Point

#### `createSigil(config)`

Creates a `SigilInstance`, which is the main runtime object used by adapters and token endpoints.

Use it when:

- you want to protect state-changing requests in a real application
- you want the runtime package to orchestrate `core` and `policy` for you

Minimal example:

```ts
import { createSigil } from '@sigil-security/runtime'

const sigil = await createSigil({
  masterSecret: process.env.SIGIL_MASTER_SECRET!,
  allowedOrigins: ['https://app.example.com'],
})
```

Important config fields:

- `masterSecret`: root key material for HKDF derivation
- `allowedOrigins`: browser origins allowed to perform protected requests
- `tokenTTL`: regular token lifetime
- `graceWindow`: overlap window for in-flight requests
- `oneShotEnabled`: enables action-bound one-shot tokens
- `oneShotTTL`: TTL for one-shot tokens
- `headerName`: custom CSRF header name
- `oneShotHeaderName`: custom one-shot header name
- `allowApiMode`: allows non-browser/API mode token validation
- `legacyBrowserMode`: controls behavior when Fetch Metadata is missing

### `SigilInstance`

The object returned by `createSigil()` exposes the main orchestration methods.

#### `generateToken(context?)`

Issues a regular CSRF token.

Use it when:

- you want to issue a browser token manually
- you are building a custom token endpoint

#### `validateToken(tokenString, expectedContext?)`

Validates a regular token against the active CSRF keyring.

Use it when:

- you are validating tokens outside the built-in adapter flow
- you need lower-level verification than `protect()`

#### `generateOneShotToken(action, context?)`

Issues an action-bound one-shot token.

Use it when:

- the route is high-assurance or destructive
- you want stronger replay resistance for a specific action

#### `validateOneShotToken(tokenString, expectedAction, expectedContext?)`

Validates a one-shot token against the one-shot keyring and nonce cache.

Use it when:

- you are building a custom one-shot validation flow

#### `protect(metadata, contextBindings?)`

Runs the full request protection flow:

1. checks whether the method needs protection
2. detects browser or API mode
3. runs the appropriate policy chain
4. validates the token

Use it when:

- you are building a custom adapter
- you want the full runtime decision in one call

#### `rotateKeys()`

Rotates the active keyring forward.

Use it when:

- you are implementing operational key rotation policies
- you need a controlled security maintenance flow

### Runtime Adapter APIs

These are the normal framework integration entry points.

#### `@sigil-security/runtime/express`

##### `createExpressMiddleware(sigil, options?)`

Express middleware wrapper that performs Sigil protection and token endpoint handling.

Use it when:

- your app is built on Express
- you want the simplest framework integration

#### `@sigil-security/runtime/fastify`

##### `createFastifyPlugin(sigil, options?)`

Fastify plugin for Sigil-protected routes and token endpoint handling.

Use it when:

- your service is Fastify-first

#### `@sigil-security/runtime/elysia`

##### `createElysiaPlugin(sigil, options?)`

Elysia integration for Bun-centric services.

Use it when:

- you are running on Elysia and want the same runtime orchestration model

#### `@sigil-security/runtime/fetch`

##### `createFetchMiddleware(sigil, handler, options?)`

Wraps a Fetch-style handler with Sigil protection.

Use it when:

- you are on a Fetch-native platform
- you want a workers/edge-friendly integration

##### `createFetchTokenEndpoint(sigil, options?)`

Standalone token-endpoint handler for Fetch-native environments.

Use it when:

- you want to expose token endpoints separately from the main protected handler

### Runtime Endpoint Helpers

These are useful when you are building custom adapters or framework glue.

#### `handleTokenEndpoint(...)`

Framework-agnostic token endpoint processor for:

- `GET /api/csrf/token`
- `POST /api/csrf/one-shot`

Use it when:

- you are writing a custom adapter
- you want to reuse the built-in token issuance behavior

#### `createTokenEndpointError(expired)`

Builds a normalized token-endpoint failure shape.

Use it when:

- your adapter needs to translate endpoint failures into framework-specific responses

#### `extractRequestMetadata(...)`

Normalizes request information into the `policy` layer’s `RequestMetadata` shape.

Use it when:

- you are implementing a new adapter

### Runtime Types To Know

- `SigilConfig`: user-supplied runtime configuration
- `SigilInstance`: the orchestration object returned by `createSigil()`
- `ProtectResult`: result of the full protect flow
- `MiddlewareOptions`: common adapter options such as excluded paths and custom endpoint paths

## `@sigil-security/client`

This is the optional browser-side helper package.

It is implemented and tested, but still explicitly experimental.

### Main Entry Point

#### `createSigilClient(config?)`

Creates a browser-oriented client object that manages token refresh, fetch wrapping, and one-shot acquisition.

Use it when:

- browser token lifecycle is becoming repetitive or error-prone
- you want refresh orchestration, multi-tab sync, or wrapped fetch

Returned object:

- `fetch`: protected fetch wrapper
- `start()`: start refresh scheduling
- `stop()`: stop refresh scheduling
- `destroy()`: stop and clean up timers/subscriptions
- `getTokenState()`: read the current cached token
- `setToken(state)`: write a token state manually
- `clearToken()`: clear local token state
- `refreshToken(force?)`: refresh now
- `requestOneShotToken(action, context?)`: request an action-bound one-shot token

### Client Lower-Level APIs

Most teams should not need these directly, but they are useful for custom browser integration.

#### `createRefreshController(...)`

Handles token refresh behavior and refresh windows.

Use it when:

- you want a custom client assembly instead of `createSigilClient()`

#### `createSigilFetchInterceptor(...)`

Builds a protected fetch wrapper that attaches tokens and optionally retries after expiry.

Use it when:

- you want custom fetch orchestration

#### `createTokenStore(...)`

Reads and writes token state to storage.

Use it when:

- you want explicit control over storage behavior

#### `createSyncChannel(...)`

Provides BroadcastChannel or storage-based token sync across tabs.

Use it when:

- you want custom multi-tab coordination

#### `createLeaderCoordinator(...)`

Coordinates refresh leadership across tabs using Web Locks when available.

Use it when:

- you are building a custom multi-tab refresh strategy

#### `createOneShotTokenRequester(...)`

Requests one-shot tokens from the runtime endpoint.

Use it when:

- you want one-shot acquisition without the full client wrapper

### Client Config Fields To Know

- `tokenEndpointPath`
- `oneShotEndpointPath`
- `tokenHeaderName`
- `oneShotHeaderName`
- `refreshWindowRatio`
- `refreshIntervalMs`
- `protectedMethods`
- `autoStart`
- `initialToken`

## `@sigil-security/ops`

This package adds observability around Sigil.

It is also explicitly experimental.

### Main Entry Point

#### `createTelemetryMiddleware(sigil, options?)`

Wraps a `SigilInstance` with metrics, anomaly detection, and structured log hooks.

Use it when:

- you want Sigil-aware telemetry without changing your runtime integration style

### Other Important Ops APIs

#### `createNoopMetricsCollector()`

Returns a no-op metrics collector.

Use it when:

- you want a safe default collector
- you are wiring the telemetry shape before a real backend exists

#### `detectAnomalies(...)`

Evaluates samples against anomaly thresholds.

Use it when:

- you want custom anomaly checks outside the default wrapper

#### `createStructuredLogger(config?)`

Builds a structured logger with redaction behavior for sensitive fields.

Use it when:

- you want Sigil-aware logs without leaking token internals

### Ops Exports To Know

- `METRIC_POINTS`: predefined metric name constants
- `MetricsCollector`: collector interface
- `TelemetryOptions`: config shape for telemetry wrapper
- `StructuredLogger`: structured logger interface

## `@sigil-security/policy`

This package contains request-policy primitives.

Most application teams use it indirectly through `runtime`.

Use it directly when:

- you are building a custom runtime
- you want to test or compose request rules independently

### Main Policy Builders

#### `createFetchMetadataPolicy(config?)`

Builds a policy around `Sec-Fetch-*` headers.

Use it when:

- you want browser provenance checks
- you need degraded vs strict behavior for missing Fetch Metadata

#### `createOriginPolicy(config)`

Builds an Origin / Referer validation policy.

Use it when:

- you want explicit allowed-origin enforcement

#### `createMethodPolicy(config?)`

Builds a policy that decides which HTTP methods require protection.

Use it when:

- you want to change the protected-method set

#### `createContentTypePolicy(config?)`

Builds a content-type validation policy.

Use it when:

- you want to constrain which mutation content types are accepted

#### `createPolicyChain(policies)`

Composes multiple policy validators into one deterministic chain.

Use it when:

- you are building a custom policy stack

### Other Policy Utilities

#### `detectClientMode(...)`

Classifies a request as browser or API mode.

Use it when:

- you need separate validation behavior for browser and API callers

#### `evaluateContextBinding(...)`

Evaluates context binding logic according to the configured risk tier model.

Use it when:

- you want explicit context-binding decisions outside full runtime orchestration

#### `resolveTokenTransport(...)`

Normalizes how the token was supplied.

Use it when:

- you are implementing a custom request extraction path

### Policy Types To Know

- `RequestMetadata`
- `PolicyValidator`
- `PolicyResult`
- `PolicyChainResult`
- `ClientMode`

## `@sigil-security/core`

This is the lowest-level package.

Use it directly only when:

- you are building custom adapters or runtimes
- you need low-level token operations
- you are auditing or extending the cryptographic primitive itself

### Main Crypto Surface

#### `WebCryptoCryptoProvider`

Default WebCrypto-backed crypto implementation.

Use it when:

- you need the standard Sigil crypto provider
- you are building directly on `core`

#### `createKeyring(cryptoProvider, masterSecret, initialKid, domain)`

Builds a keyring for a specific key domain.

Use it when:

- you are initializing token-signing state

#### `rotateKey(keyring, cryptoProvider, masterSecret, newKid)`

Rotates the keyring forward.

Use it when:

- you are implementing key rotation at the `core` layer

#### `generateToken(...)`

Generates a regular CSRF token.

#### `validateToken(...)`

Validates a regular token using deterministic failure behavior.

#### `generateOneShotToken(...)`

Generates an action-bound one-shot token.

#### `validateOneShotToken(...)`

Validates a one-shot token and checks nonce replay semantics.

#### `computeContext(...)`

Computes context-binding bytes from binding inputs.

Use it when:

- you want to bind tokens to additional request or session context

#### `createNonceCache(config?)`

Creates the ephemeral in-memory nonce cache used by one-shot validation.

Use it when:

- you are working directly with one-shot primitives

### Core Types To Know

- `CryptoProvider`
- `Keyring`
- `KeyEntry`
- `ValidationResult`
- `GenerationResult`
- `NonceCache`

## What Most Teams Should Ignore At First

If you are shipping an application, you can usually ignore:

- most direct `core` exports
- most direct `policy` exports
- lower-level `client` wiring helpers

Your likely minimum useful surface is:

- `createSigil()`
- one runtime adapter
- token endpoints

And optionally later:

- `createSigilClient()`
- `createTelemetryMiddleware()`

## Recommended Reading Order

For app teams:

1. [README.md](../README.md)
2. [QUICKSTART.md](./QUICKSTART.md)
3. [INTEGRATION_GUIDE.md](./INTEGRATION_GUIDE.md)
4. this guide

For custom integrators:

1. this guide
2. [BOUNDARY_SPECIFICATION.md](./BOUNDARY_SPECIFICATION.md)
3. [SPECIFICATION.md](./SPECIFICATION.md)
4. package source and tests

## Final Rule Of Thumb

If you are unsure where to begin:

- use `runtime` to adopt Sigil
- use `client` to simplify browser lifecycle
- use `ops` to observe Sigil
- use `policy` and `core` only when you truly need lower-level control
