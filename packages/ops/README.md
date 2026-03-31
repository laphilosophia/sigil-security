# @sigil-security/ops

Experimental telemetry and observability helpers for Sigil.

## Status

This package is implemented and tested, but still published under the `experimental` tag.

## What it contains

- pluggable metrics collector interface
- no-op metrics collector
- anomaly detection helpers
- structured logger with secret redaction
- telemetry wrapper around a `SigilInstance`

## Install

```bash
pnpm add @sigil-security/ops
```

## Example

```ts
import { createTelemetryMiddleware, createNoopMetricsCollector } from '@sigil-security/ops'

const observedSigil = createTelemetryMiddleware(sigil, {
  metrics: createNoopMetricsCollector(),
})
```

## Use it when

Use `ops` when you want Sigil metrics and structured security logging without changing your runtime integration code.
