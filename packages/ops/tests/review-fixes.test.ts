import { describe, expect, it } from 'vitest'
import { createStructuredLogger, createTelemetryMiddleware } from '../src/index.js'
import type { StructuredLogEntry } from '../src/index.js'
import type { SigilInstance } from '@sigil-security/runtime'

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
        valid: true,
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
        valid: true,
      }
    },
    async rotateKeys() {
      throw new Error('rotation_failed')
    },
    async protect() {
      return {
        allowed: true,
        tokenValid: true,
        policyResult: {
          allowed: true,
          evaluated: ['policy-chain'],
          failures: [],
        },
      }
    },
  }
}

describe('ops review fixes', () => {
  it('should redact token-like keys beyond the exact token name', () => {
    const entries: StructuredLogEntry[] = []
    const logger = createStructuredLogger({
      sink: (entry): void => {
        entries.push(entry)
      },
      now: (): number => 1,
    })

    logger.info('sanitized', {
      tokenString: 'secret-token',
      csrf_token: 'secret-csrf-token',
      nested: {
        accessToken: 'secret-access-token',
      },
    })

    expect(entries[0]?.context).toEqual({
      tokenString: '[REDACTED]',
      csrf_token: '[REDACTED]',
      nested: {
        accessToken: '[REDACTED]',
      },
    })
  })

  it('should preserve telemetry logging when key rotation fails', async () => {
    const logs: Array<{ readonly level: string; readonly message: string }> = []
    const wrapped = createTelemetryMiddleware(createSigilStub(), {
      logger: createStructuredLogger({
        sink: (entry): void => {
          logs.push({ level: entry.level, message: entry.message })
        },
        now: (): number => 1,
      }),
      now: (() => {
        let tick = 0
        return (): number => tick++
      })(),
    })

    await expect(wrapped.rotateKeys()).rejects.toThrow('rotation_failed')
    expect(logs).toContainEqual({
      level: 'error',
      message: 'CSRF key rotation failed',
    })
  })
})
