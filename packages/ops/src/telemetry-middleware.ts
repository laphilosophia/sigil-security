import type { SigilInstance } from '@sigil-security/runtime'
import { METRIC_POINTS } from './metric-points.js'
import { createNoopMetricsCollector, type MetricsCollector } from './metrics.js'
import { createStructuredLogger, type StructuredLogger } from './structured-logger.js'

export interface TelemetryOptions {
  readonly metrics?: MetricsCollector | undefined
  readonly logger?: StructuredLogger | undefined
  readonly now?: (() => number) | undefined
}

function toMicroseconds(start: number, end: number): number {
  return Math.max(0, end - start) * 1000
}

function emitFailureMetrics(metrics: MetricsCollector, reason: string, durationUs: number): void {
  metrics.increment(METRIC_POINTS.VALIDATION_FAIL_TOTAL)
  metrics.increment(METRIC_POINTS.VALIDATION_FAIL_BY_REASON, { reason })
  metrics.histogram(METRIC_POINTS.VALIDATION_FAIL_DURATION, durationUs)

  if (reason.startsWith('origin_')) {
    metrics.increment(METRIC_POINTS.ORIGIN_MISMATCH_TOTAL)
  }

  if (reason === 'fetch_metadata_cross_site') {
    metrics.increment(METRIC_POINTS.FETCH_METADATA_CROSS_SITE_BLOCKED)
  }

  if (reason === 'fetch_metadata_missing_strict') {
    metrics.increment(METRIC_POINTS.FETCH_METADATA_MISSING)
  }

  if (reason === 'context_mismatch') {
    metrics.increment(METRIC_POINTS.CONTEXT_BINDING_FAIL_TOTAL)
  }

  if (reason === 'nonce_reused') {
    metrics.increment(METRIC_POINTS.ONESHOT_REPLAY_ATTEMPT_TOTAL)
  }

  if (reason === 'action_mismatch') {
    metrics.increment(METRIC_POINTS.ONESHOT_ACTION_MISMATCH)
  }
}

export function createTelemetryMiddleware(
  sigil: SigilInstance,
  options: TelemetryOptions = {},
): SigilInstance {
  const metrics = options.metrics ?? createNoopMetricsCollector()
  const logger = options.logger ?? createStructuredLogger()
  const now = options.now ?? Date.now

  return {
    config: sigil.config,

    async generateToken(context?: readonly string[]) {
      const start = now()
      const result = await sigil.generateToken(context)
      const durationUs = toMicroseconds(start, now())

      metrics.increment(METRIC_POINTS.TOKEN_GENERATION_TOTAL)
      metrics.histogram(METRIC_POINTS.TOKEN_GENERATION_DURATION, durationUs)

      if (!result.success) {
        metrics.increment(METRIC_POINTS.CRYPTO_FAILURES)
        logger.error('CSRF token generation failed', { reason: result.reason })
      }

      return result
    },

    async validateToken(tokenString: string, expectedContext?: readonly string[]) {
      const start = now()
      const result = await sigil.validateToken(tokenString, expectedContext)
      const durationUs = toMicroseconds(start, now())

      metrics.histogram(METRIC_POINTS.VALIDATION_DURATION, durationUs)

      if (result.valid) {
        metrics.increment(METRIC_POINTS.VALIDATION_SUCCESS_TOTAL)
        metrics.histogram(METRIC_POINTS.VALIDATION_SUCCESS_DURATION, durationUs)
      } else {
        emitFailureMetrics(metrics, result.reason, durationUs)
        logger.warn('CSRF validation failed', { reason: result.reason })
      }

      return result
    },

    async generateOneShotToken(action: string, context?: readonly string[]) {
      const start = now()
      const result = await sigil.generateOneShotToken(action, context)
      const durationUs = toMicroseconds(start, now())

      metrics.increment(METRIC_POINTS.ONESHOT_GENERATION_TOTAL)
      metrics.histogram(METRIC_POINTS.ONESHOT_GENERATION_DURATION, durationUs)

      if (!result.success) {
        metrics.increment(METRIC_POINTS.CRYPTO_FAILURES)
        logger.error('One-shot token generation failed', { reason: result.reason, action })
      }

      return result
    },

    async validateOneShotToken(
      tokenString: string,
      expectedAction: string,
      expectedContext?: readonly string[],
    ) {
      const start = now()
      const result = await sigil.validateOneShotToken(
        tokenString,
        expectedAction,
        expectedContext,
      )
      const durationUs = toMicroseconds(start, now())

      metrics.histogram(METRIC_POINTS.VALIDATION_DURATION, durationUs)

      if (result.valid) {
        metrics.increment(METRIC_POINTS.VALIDATION_SUCCESS_TOTAL)
        metrics.histogram(METRIC_POINTS.VALIDATION_SUCCESS_DURATION, durationUs)
      } else {
        emitFailureMetrics(metrics, result.reason, durationUs)
        logger.warn('One-shot validation failed', {
          reason: result.reason,
          action: expectedAction,
        })
      }

      return result
    },

    async rotateKeys() {
      try {
        await sigil.rotateKeys()
        metrics.increment(METRIC_POINTS.KEY_ROTATION_EVENTS)
        logger.info('CSRF keys rotated')
      } catch (error) {
        metrics.increment(METRIC_POINTS.KEY_ROTATION_FAILURES)
        logger.error('CSRF key rotation failed', {
          error: error instanceof Error ? error.message : 'unknown_error',
        })
        throw error
      }
    },

    async protect(
      metadata: Parameters<SigilInstance['protect']>[0],
      contextBindings: Parameters<SigilInstance['protect']>[1],
    ): ReturnType<SigilInstance['protect']> {
      const start = now()
      const result = await sigil.protect(metadata, contextBindings)
      const durationUs = toMicroseconds(start, now())

      metrics.histogram(METRIC_POINTS.VALIDATION_DURATION, durationUs)

      if (result.allowed) {
        metrics.increment(METRIC_POINTS.VALIDATION_SUCCESS_TOTAL)
        metrics.histogram(METRIC_POINTS.VALIDATION_SUCCESS_DURATION, durationUs)
      } else {
        emitFailureMetrics(metrics, result.reason, durationUs)
        logger.warn('Protected request rejected', {
          reason: result.reason,
          expired: result.expired,
        })
      }

      return result
    },
  }
}
