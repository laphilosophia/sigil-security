import { describe, it, expect } from 'vitest'
import { WebCryptoCryptoProvider } from '../src/web-crypto-provider.js'
import { createKeyring, getActiveKey, rotateKey } from '../src/key-manager.js'
import { generateToken } from '../src/token.js'
import { validateToken, validateTTL, constantTimeEqual } from '../src/validation.js'
import { computeContext } from '../src/context.js'
import { DEFAULT_TOKEN_TTL_MS, DEFAULT_GRACE_WINDOW_MS, TOKEN_RAW_SIZE } from '../src/types.js'
import { fromBase64Url, toBase64Url } from '../src/encoding.js'

describe('validation', () => {
  const provider = new WebCryptoCryptoProvider()
  const masterSecret = globalThis.crypto.getRandomValues(new Uint8Array(32)).buffer

  function flipTokenByte(token: string, byteOffset: number): string {
    const raw = fromBase64Url(token)
    raw[byteOffset] = (raw[byteOffset] ?? 0) ^ 0xff
    return toBase64Url(raw)
  }

  describe('validateToken', () => {
    it('should validate a freshly generated token', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)!
      const now = Date.now()
      const result = await generateToken(provider, key, undefined, undefined, now)

      expect(result.success).toBe(true)
      if (result.success) {
        const validation = await validateToken(
          provider,
          keyring,
          result.token,
          undefined,
          undefined,
          undefined,
          now,
        )
        expect(validation).toEqual({ valid: true })
      }
    })

    it('should validate token with context binding', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)!
      const ctx = await computeContext(provider, 'session123')
      const now = Date.now()
      const result = await generateToken(provider, key, ctx, undefined, now)

      expect(result.success).toBe(true)
      if (result.success) {
        const validation = await validateToken(
          provider,
          keyring,
          result.token,
          ctx,
          undefined,
          undefined,
          now,
        )
        expect(validation).toEqual({ valid: true })
      }
    })

    it('should reject token with wrong context', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)!
      const ctx = await computeContext(provider, 'session123')
      const wrongCtx = await computeContext(provider, 'session999')
      const now = Date.now()
      const result = await generateToken(provider, key, ctx, undefined, now)

      expect(result.success).toBe(true)
      if (result.success) {
        const validation = await validateToken(
          provider,
          keyring,
          result.token,
          wrongCtx,
          undefined,
          undefined,
          now,
        )
        expect(validation.valid).toBe(false)
        if (!validation.valid) {
          expect(validation.reason).toBe('context_mismatch')
        }
      }
    })

    it('should reject expired token', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)!
      const tokenTime = Date.now()
      const result = await generateToken(provider, key, undefined, undefined, tokenTime)

      expect(result.success).toBe(true)
      if (result.success) {
        // Validate far in the future (past TTL + grace window)
        const futureTime = tokenTime + DEFAULT_TOKEN_TTL_MS + DEFAULT_GRACE_WINDOW_MS + 1
        const validation = await validateToken(
          provider,
          keyring,
          result.token,
          undefined,
          undefined,
          undefined,
          futureTime,
        )
        expect(validation.valid).toBe(false)
      }
    })

    it('should accept token within grace window', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)!
      const now = Date.now()
      const result = await generateToken(provider, key, undefined, undefined, now)

      expect(result.success).toBe(true)
      if (result.success) {
        // Validate just past TTL but within grace window
        const graceTime = now + DEFAULT_TOKEN_TTL_MS + DEFAULT_GRACE_WINDOW_MS / 2
        const validation = await validateToken(
          provider,
          keyring,
          result.token,
          undefined,
          undefined,
          undefined,
          graceTime,
        )
        expect(validation).toEqual({ valid: true })
      }
    })

    it('should reject tampered token', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)!
      const now = Date.now()
      const result = await generateToken(provider, key, undefined, undefined, now)

      expect(result.success).toBe(true)
      if (result.success) {
        // Tamper with the token string
        const tampered = result.token.slice(0, -1) + (result.token.endsWith('A') ? 'B' : 'A')
        const validation = await validateToken(
          provider,
          keyring,
          tampered,
          undefined,
          undefined,
          undefined,
          now,
        )
        expect(validation.valid).toBe(false)
      }
    })

    it('should complete HMAC verify even with unknown kid (M1 timing oracle fix)', async () => {
      // Create a keyring with kid=1 and a token with kid=99
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const otherKeyring = await createKeyring(provider, masterSecret, 99, 'csrf')
      const key = getActiveKey(otherKeyring)!
      const now = Date.now()
      const result = await generateToken(provider, key, undefined, undefined, now)

      expect(result.success).toBe(true)
      if (result.success) {
        // This should NOT throw — the fallback key from keyring.keys[0] should be used
        const validation = await validateToken(
          provider,
          keyring,
          result.token,
          undefined,
          undefined,
          undefined,
          now,
        )
        // Must reject, but must not crash (HMAC was executed with fallback key)
        expect(validation.valid).toBe(false)
        if (!validation.valid) {
          // Reason should indicate kid was unknown (not a crash)
          expect(validation.reason).toBe('invalid_mac')
        }
      }
    })

    it('should reject token with unknown kid', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const otherKeyring = await createKeyring(provider, masterSecret, 99, 'csrf')
      const key = getActiveKey(otherKeyring)!
      const now = Date.now()
      const result = await generateToken(provider, key, undefined, undefined, now)

      expect(result.success).toBe(true)
      if (result.success) {
        // Validate against keyring that doesn't have kid=99
        const validation = await validateToken(
          provider,
          keyring,
          result.token,
          undefined,
          undefined,
          undefined,
          now,
        )
        expect(validation.valid).toBe(false)
      }
    })

    it('should validate token after key rotation (old kid still in keyring)', async () => {
      let keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)!
      const now = Date.now()
      const result = await generateToken(provider, key, undefined, undefined, now)

      // Rotate key
      keyring = await rotateKey(keyring, provider, masterSecret, 2)

      expect(result.success).toBe(true)
      if (result.success) {
        const validation = await validateToken(
          provider,
          keyring,
          result.token,
          undefined,
          undefined,
          undefined,
          now,
        )
        expect(validation).toEqual({ valid: true })
      }
    })

    it('should reject garbage input', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const validation = await validateToken(
        provider,
        keyring,
        'garbage-not-a-token',
      )
      expect(validation.valid).toBe(false)
    })

    it('should reject empty string', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const validation = await validateToken(provider, keyring, '')
      expect(validation.valid).toBe(false)
    })

    it('should accept token without context when no expected context', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)!
      const now = Date.now()
      const result = await generateToken(provider, key, undefined, undefined, now)

      expect(result.success).toBe(true)
      if (result.success) {
        // No expected context — should pass
        const validation = await validateToken(
          provider,
          keyring,
          result.token,
          undefined,
          undefined,
          undefined,
          now,
        )
        expect(validation).toEqual({ valid: true })
      }
    })

    it('should reject future-dated token', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)!
      const now = Date.now()
      const futureTime = now + 1000000 // Token created in the future
      const result = await generateToken(provider, key, undefined, undefined, futureTime)

      expect(result.success).toBe(true)
      if (result.success) {
        const validation = await validateToken(
          provider,
          keyring,
          result.token,
          undefined,
          undefined,
          undefined,
          now, // Validate at "now" which is before token creation
        )
        expect(validation.valid).toBe(false)
      }
    })
  })

  describe('validateTTL', () => {
    it('should be within TTL for fresh token', () => {
      const now = Date.now()
      const result = validateTTL(now, DEFAULT_TOKEN_TTL_MS, DEFAULT_GRACE_WINDOW_MS, now)
      expect(result.withinTTL).toBe(true)
      expect(result.inGraceWindow).toBe(false)
    })

    it('should be within TTL at exactly TTL boundary', () => {
      const now = Date.now()
      const tokenTime = now - DEFAULT_TOKEN_TTL_MS
      const result = validateTTL(tokenTime, DEFAULT_TOKEN_TTL_MS, DEFAULT_GRACE_WINDOW_MS, now)
      expect(result.withinTTL).toBe(true)
    })

    it('should be in grace window just past TTL', () => {
      const now = Date.now()
      const tokenTime = now - DEFAULT_TOKEN_TTL_MS - 1 // 1ms past TTL
      const result = validateTTL(tokenTime, DEFAULT_TOKEN_TTL_MS, DEFAULT_GRACE_WINDOW_MS, now)
      expect(result.withinTTL).toBe(false)
      expect(result.inGraceWindow).toBe(true)
    })

    it('should be in grace window at boundary', () => {
      const now = Date.now()
      const tokenTime = now - DEFAULT_TOKEN_TTL_MS - DEFAULT_GRACE_WINDOW_MS
      const result = validateTTL(tokenTime, DEFAULT_TOKEN_TTL_MS, DEFAULT_GRACE_WINDOW_MS, now)
      expect(result.withinTTL).toBe(false)
      expect(result.inGraceWindow).toBe(true)
    })

    it('should be expired past grace window', () => {
      const now = Date.now()
      const tokenTime = now - DEFAULT_TOKEN_TTL_MS - DEFAULT_GRACE_WINDOW_MS - 1
      const result = validateTTL(tokenTime, DEFAULT_TOKEN_TTL_MS, DEFAULT_GRACE_WINDOW_MS, now)
      expect(result.withinTTL).toBe(false)
      expect(result.inGraceWindow).toBe(false)
    })

    it('should reject future timestamps', () => {
      const now = Date.now()
      const futureTime = now + 10000
      const result = validateTTL(futureTime, DEFAULT_TOKEN_TTL_MS, DEFAULT_GRACE_WINDOW_MS, now)
      expect(result.withinTTL).toBe(false)
      expect(result.inGraceWindow).toBe(false)
    })
  })

  describe('constantTimeEqual', () => {
    it('should return true for equal buffers', () => {
      const a = new Uint8Array([1, 2, 3, 4, 5])
      const b = new Uint8Array([1, 2, 3, 4, 5])
      expect(constantTimeEqual(a, b)).toBe(true)
    })

    it('should return false for different buffers', () => {
      const a = new Uint8Array([1, 2, 3, 4, 5])
      const b = new Uint8Array([1, 2, 3, 4, 6])
      expect(constantTimeEqual(a, b)).toBe(false)
    })

    it('should return false for different lengths', () => {
      const a = new Uint8Array([1, 2, 3])
      const b = new Uint8Array([1, 2, 3, 4])
      expect(constantTimeEqual(a, b)).toBe(false)
    })

    it('should return true for empty buffers', () => {
      expect(constantTimeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true)
    })

    it('should return false when only first byte differs', () => {
      const a = new Uint8Array([0, 2, 3])
      const b = new Uint8Array([1, 2, 3])
      expect(constantTimeEqual(a, b)).toBe(false)
    })

    it('should return false when only last byte differs', () => {
      const a = new Uint8Array([1, 2, 3])
      const b = new Uint8Array([1, 2, 4])
      expect(constantTimeEqual(a, b)).toBe(false)
    })

    it('should handle 32-byte buffers (context size)', () => {
      const a = new Uint8Array(32).fill(0xaa)
      const b = new Uint8Array(32).fill(0xaa)
      expect(constantTimeEqual(a, b)).toBe(true)

      b[31] = 0xab
      expect(constantTimeEqual(a, b)).toBe(false)
    })
  })
  describe('hardening coverage', () => {
    it('should allow validating the same regular token multiple times within TTL', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)!
      const now = Date.now()
      const result = await generateToken(provider, key, undefined, undefined, now)

      expect(result.success).toBe(true)
      if (!result.success) return

      const firstValidation = await validateToken(provider, keyring, result.token, undefined, undefined, undefined, now)
      const secondValidation = await validateToken(provider, keyring, result.token, undefined, undefined, undefined, now)

      expect(firstValidation).toEqual({ valid: true })
      expect(secondValidation).toEqual({ valid: true })
    })

    it('should reject a regular token with a modified payload and original MAC', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)!
      const now = Date.now()
      const result = await generateToken(provider, key, undefined, undefined, now)

      expect(result.success).toBe(true)
      if (!result.success) return

      const tamperedToken = flipTokenByte(result.token, 5)
      const validation = await validateToken(provider, keyring, tamperedToken, undefined, undefined, undefined, now)

      expect(validation).toEqual({ valid: false, reason: 'invalid_mac' })
    })

    it('should reject zero-padded regular tokens', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const zeroPaddedToken = toBase64Url(new Uint8Array(TOKEN_RAW_SIZE))

      const validation = await validateToken(provider, keyring, zeroPaddedToken)

      expect(validation).toEqual({ valid: false, reason: 'invalid_mac' })
    })

    it('should reject randomized regular-token inputs without throwing', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')

      for (let index = 0; index < 32; index += 1) {
        const candidate = toBase64Url(globalThis.crypto.getRandomValues(new Uint8Array(13 + index)))
        const validation = await validateToken(provider, keyring, candidate)
        expect(validation.valid).toBe(false)
      }
    })

    it('should reject unicode edge-case regular-token inputs', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const candidates = ['🔥', '令和', 'a\u0000b', 'e\u0301', '\ud83d', '\u0000']

      for (const candidate of candidates) {
        const validation = await validateToken(provider, keyring, candidate)
        expect(validation.valid).toBe(false)
      }
    })

    it('should accept a token exactly at the end of the grace window', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)!
      const tokenTime = 1_700_000_000_000
      const result = await generateToken(provider, key, undefined, undefined, tokenTime)

      expect(result.success).toBe(true)
      if (!result.success) return

      const validation = await validateToken(
        provider,
        keyring,
        result.token,
        undefined,
        DEFAULT_TOKEN_TTL_MS,
        DEFAULT_GRACE_WINDOW_MS,
        tokenTime + DEFAULT_TOKEN_TTL_MS + DEFAULT_GRACE_WINDOW_MS,
      )

      expect(validation).toEqual({ valid: true })
    })

    it('should reject a token 1ms past the grace-window boundary', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)!
      const tokenTime = 1_700_000_000_000
      const result = await generateToken(provider, key, undefined, undefined, tokenTime)

      expect(result.success).toBe(true)
      if (!result.success) return

      const validation = await validateToken(
        provider,
        keyring,
        result.token,
        undefined,
        DEFAULT_TOKEN_TTL_MS,
        DEFAULT_GRACE_WINDOW_MS,
        tokenTime + DEFAULT_TOKEN_TTL_MS + DEFAULT_GRACE_WINDOW_MS + 1,
      )

      expect(validation).toEqual({ valid: false, reason: 'expired' })
    })

    it('should reject a token after its original kid is evicted from the keyring', async () => {
      let keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const originalKey = getActiveKey(keyring)!
      const now = Date.now()
      const result = await generateToken(provider, originalKey, undefined, undefined, now)

      expect(result.success).toBe(true)
      if (!result.success) return

      keyring = await rotateKey(keyring, provider, masterSecret, 2)
      keyring = await rotateKey(keyring, provider, masterSecret, 3)
      keyring = await rotateKey(keyring, provider, masterSecret, 4)

      const validation = await validateToken(provider, keyring, result.token, undefined, undefined, undefined, now)

      expect(validation).toEqual({ valid: false, reason: 'invalid_mac' })
    })
  })
})

