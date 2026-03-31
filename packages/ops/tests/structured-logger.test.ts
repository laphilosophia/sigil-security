import { describe, expect, it } from 'vitest'
import { createStructuredLogger } from '../src/index.js'
import type { StructuredLogEntry } from '../src/index.js'

describe('structured logger', () => {
  it('should default to a no-op sink', () => {
    const logger = createStructuredLogger()

    expect(() => {
      logger.info('hello')
      logger.warn('warn', { tokenValue: 'secret' })
      logger.error('error')
    }).not.toThrow()
  })

  it('should redact token-like values inside nested arrays and objects', () => {
    const entries: StructuredLogEntry[] = []
    const logger = createStructuredLogger({
      sink: (entry): void => {
        entries.push(entry)
      },
      now: (): number => 1_234,
    })

    logger.warn('nested secrets', {
      attempts: [
        { csrf_token: 'secret-1', action: 'POST:/checkout' },
        { tokenString: 'secret-2', nested: { macKey: 'secret-3' } },
      ],
    })

    expect(entries).toEqual([
      {
        level: 'warn',
        message: 'nested secrets',
        timestamp: 1_234,
        context: {
          attempts: [
            { csrf_token: '[REDACTED]', action: 'POST:/checkout' },
            { tokenString: '[REDACTED]', nested: { macKey: '[REDACTED]' } },
          ],
        },
      },
    ])
  })
})
