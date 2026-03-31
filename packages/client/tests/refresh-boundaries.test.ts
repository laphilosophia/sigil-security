import { describe, expect, it } from 'vitest'
import { shouldRefreshToken } from '../src/index.js'

describe('refresh boundaries', () => {
  it('should wait until exact expiry when the refresh window ratio is zero', () => {
    expect(
      shouldRefreshToken(
        {
          token: 'token-1',
          expiresAt: 1_000,
        },
        999,
        1_000,
        0,
      ),
    ).toBe(false)

    expect(
      shouldRefreshToken(
        {
          token: 'token-1',
          expiresAt: 1_000,
        },
        1_000,
        1_000,
        0,
      ),
    ).toBe(true)
  })

  it('should refresh immediately when the refresh window covers the full ttl', () => {
    expect(
      shouldRefreshToken(
        {
          token: 'token-1',
          expiresAt: 1_000,
        },
        0,
        1_000,
        1,
      ),
    ).toBe(true)
  })

  it('should behave conservatively for negative ttl inputs', () => {
    expect(
      shouldRefreshToken(
        {
          token: 'token-1',
          expiresAt: 1_000,
        },
        900,
        -1_000,
        0.25,
      ),
    ).toBe(false)
  })

  it('should refresh already-expired states even at a zero timestamp', () => {
    expect(
      shouldRefreshToken(
        {
          token: 'token-1',
          expiresAt: 0,
        },
        0,
        1_000,
        0.25,
      ),
    ).toBe(true)
  })
})
