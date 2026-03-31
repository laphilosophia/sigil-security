import { describe, expect, it, vi } from 'vitest'
import {
  METRIC_POINTS,
  createNoopMetricsCollector,
  createStructuredLogger,
  createTelemetryMiddleware,
  detectAnomalies,
} from '../src/index.js'
import type { MetricsCollector, StructuredLogEntry } from '../src/index.js'
import type { SigilInstance } from '@sigil-security/runtime'

function createMetricsRecorder(): {
  readonly collector: MetricsCollector
  readonly calls: Array<{
    readonly method: 'increment' | 'gauge' | 'histogram'
    readonly name: string
    readonly value?: number | undefined
    readonly labels?: Record<string, string> | undefined
  }>
} {
  const calls: Array<{
    readonly method: 'increment' | 'gauge' | 'histogram'
    readonly name: string
    readonly value?: number | undefined
    readonly labels?: Record<string, string> | undefined
  }> = []

  return {
    collector: {
      increment(name: string, labels?: Record<string, string>): void {
        calls.push({ method: 'increment', name, labels })
      },
      gauge(name: string, value: number, labels?: Record<string, string>): void {
        calls.push({ method: 'gauge', name, value, labels })
      },
      histogram(name: string, value: number, labels?: Record<string, string>): void {
        calls.push({ method: 'histogram', name, value, labels })
      },
    },
    calls,
  }
}

function createSigilStub(): SigilInstance {
  return {
    config: {
      tokenTTL: 1_200_000,
      graceWindow: 60_000,
      allowedOrigins: ['https://example.com'],
      legacyBrowserMode: 'degraded',
      allowApiMode: true,
      protectedMethods: ['POST'],
      contextBinding: undefined,
      oneShotEnabled: true,
      oneShotTTL: 300_000,
      headerName: 'x-csrf-token',
      oneShotHeaderName: 'x-csrf-one-shot-token',
      disableClientModeOverride: false,
    },
    async generateToken() {
      return {
        success: true,
        token: 'token-1',
        expiresAt: 2_000,
      }
    },
    async validateToken() {
      return {
        valid: false,
        reason: 'origin_missing',
      }
    },
    async generateOneShotToken() {
      return {
        success: true,
        token: 'oneshot-1',
        expiresAt: 2_000,
      }
    },
    async validateOneShotToken() {
      return {
        valid: false,
        reason: 'nonce_reused',
      }
    },
    async rotateKeys() {
      return undefined
    },
    async protect() {
      return {
        allowed: false,
        reason: 'fetch_metadata_cross_site',
        expired: false,
        policyResult: null,
      }
    },
  }
}

describe('ops package', () => {
  it('should provide a no-op metrics collector', () => {
    const collector = createNoopMetricsCollector()

    expect(() => {
      collector.increment('metric')
      collector.gauge('metric', 1)
      collector.histogram('metric', 1)
    }).not.toThrow()
  })

  it('should detect anomaly spikes using baseline multipliers', () => {
    const findings = detectAnomalies(
      {
        validationFailRate: 20,
        invalidMacRate: 1,
        generationRate: 5,
        oneShotReplayCount: 1,
        timingVariance: 10,
      },
      {
        validationFailRate: 4,
        invalidMacRate: 1,
        generationRate: 2,
        timingVariance: 2,
      },
    )

    expect(findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: 'validation_fail_spike',
          severity: 'critical',
        }),
        expect.objectContaining({
          type: 'one_shot_replay',
          severity: 'critical',
        }),
      ]),
    )
  })

  it('should redact token-like secrets from structured logs', () => {
    const entries: StructuredLogEntry[] = []
    const logger = createStructuredLogger({
      sink: (entry): void => {
        entries.push(entry)
      },
      now: (): number => 1_234,
    })

    logger.warn('validation failure', {
      token: 'secret-token',
      nonce: 'secret-nonce',
      kid: 7,
      nested: {
        mac: 'secret-mac',
        action: 'POST:/payments',
      },
    })

    expect(entries).toEqual([
      {
        level: 'warn',
        message: 'validation failure',
        timestamp: 1_234,
        context: {
          token: '[REDACTED]',
          nonce: '[REDACTED]',
          kid: 7,
          nested: {
            mac: '[REDACTED]',
            action: 'POST:/payments',
          },
        },
      },
    ])
  })

  it('should emit telemetry metrics and logs around sigil operations', async () => {
    const { collector, calls } = createMetricsRecorder()
    const logs: StructuredLogEntry[] = []
    const logger = createStructuredLogger({
      sink: (entry): void => {
        logs.push(entry)
      },
      now: (): number => 1_000,
    })
    const wrapped = createTelemetryMiddleware(createSigilStub(), {
      metrics: collector,
      logger,
      now: vi.fn()
        .mockReturnValueOnce(0)
        .mockReturnValueOnce(1)
        .mockReturnValueOnce(2)
        .mockReturnValueOnce(3)
        .mockReturnValueOnce(4)
        .mockReturnValueOnce(5)
        .mockReturnValueOnce(6)
        .mockReturnValueOnce(7)
        .mockReturnValueOnce(8)
        .mockReturnValueOnce(9),
    })

    await wrapped.generateToken()
    await wrapped.validateToken('token')
    await wrapped.generateOneShotToken('POST:/payments')
    await wrapped.validateOneShotToken('oneshot', 'POST:/payments')
    await wrapped.rotateKeys()
    await wrapped.protect({
      method: 'POST',
      origin: 'https://example.com',
      referer: null,
      secFetchSite: 'cross-site',
      secFetchMode: 'cors',
      secFetchDest: 'empty',
      contentType: 'application/json',
      tokenSource: { from: 'header', value: 'token' },
    })

    expect(calls).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          method: 'increment',
          name: METRIC_POINTS.TOKEN_GENERATION_TOTAL,
        }),
        expect.objectContaining({
          method: 'increment',
          name: METRIC_POINTS.VALIDATION_FAIL_TOTAL,
        }),
        expect.objectContaining({
          method: 'increment',
          name: METRIC_POINTS.ORIGIN_MISMATCH_TOTAL,
        }),
        expect.objectContaining({
          method: 'increment',
          name: METRIC_POINTS.ONESHOT_REPLAY_ATTEMPT_TOTAL,
        }),
        expect.objectContaining({
          method: 'increment',
          name: METRIC_POINTS.KEY_ROTATION_EVENTS,
        }),
        expect.objectContaining({
          method: 'increment',
          name: METRIC_POINTS.FETCH_METADATA_CROSS_SITE_BLOCKED,
        }),
      ]),
    )

    expect(logs).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          level: 'warn',
          message: 'CSRF validation failed',
        }),
        expect.objectContaining({
          level: 'warn',
          message: 'One-shot validation failed',
        }),
        expect.objectContaining({
          level: 'info',
          message: 'CSRF keys rotated',
        }),
      ]),
    )
  })
})
