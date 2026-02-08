import { describe, it, expect } from 'vitest'
import { WebCryptoCryptoProvider } from '../src/web-crypto-provider.js'
import { createKeyring, getActiveKey } from '../src/key-manager.js'
import {
  generateOneShotToken,
  parseOneShotToken,
  validateOneShotToken,
  computeAction,
} from '../src/one-shot-token.js'
import { createNonceCache } from '../src/nonce-cache.js'
import { computeContext } from '../src/context.js'
import {
  ONESHOT_RAW_SIZE,
  NONCE_SIZE,
  CONTEXT_SIZE,
  ACTION_SIZE,
  MAC_SIZE,
} from '../src/types.js'
import { fromBase64Url } from '../src/encoding.js'

describe('one-shot-token', () => {
  const provider = new WebCryptoCryptoProvider()
  const masterSecret = crypto.getRandomValues(new Uint8Array(32)).buffer
  const action = 'POST:/api/account/delete'

  describe('computeAction', () => {
    it('should produce 32-byte action hash', async () => {
      const hash = await computeAction(provider, action)
      expect(hash.length).toBe(32)
    })

    it('should produce consistent hashes', async () => {
      const hash1 = await computeAction(provider, action)
      const hash2 = await computeAction(provider, action)
      expect(hash1).toEqual(hash2)
    })

    it('should produce different hashes for different actions', async () => {
      const hash1 = await computeAction(provider, 'POST:/api/account/delete')
      const hash2 = await computeAction(provider, 'POST:/api/account/update')
      expect(hash1).not.toEqual(hash2)
    })
  })

  describe('generateOneShotToken', () => {
    it('should generate a valid one-shot token', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'oneshot')
      const key = getActiveKey(keyring)!
      const result = await generateOneShotToken(provider, key, action)

      expect(result.success).toBe(true)
      if (result.success) {
        expect(typeof result.token).toBe('string')
        expect(result.token.length).toBeGreaterThan(0)
        expect(result.expiresAt).toBeGreaterThan(Date.now())
      }
    })

    it('should produce constant-size tokens (120 bytes raw)', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'oneshot')
      const key = getActiveKey(keyring)!
      const result = await generateOneShotToken(provider, key, action)

      expect(result.success).toBe(true)
      if (result.success) {
        const raw = fromBase64Url(result.token)
        expect(raw.length).toBe(ONESHOT_RAW_SIZE) // 120 bytes FIXED
      }
    })

    it('should generate unique nonces', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'oneshot')
      const key = getActiveKey(keyring)!
      const result1 = await generateOneShotToken(provider, key, action)
      const result2 = await generateOneShotToken(provider, key, action)

      expect(result1.success).toBe(true)
      expect(result2.success).toBe(true)
      if (result1.success && result2.success) {
        expect(result1.token).not.toBe(result2.token)
      }
    })
  })

  describe('parseOneShotToken', () => {
    it('should parse a generated token', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'oneshot')
      const key = getActiveKey(keyring)!
      const result = await generateOneShotToken(provider, key, action)

      expect(result.success).toBe(true)
      if (result.success) {
        const parsed = parseOneShotToken(result.token)
        expect(parsed).not.toBeNull()
        expect(parsed!.nonce.length).toBe(NONCE_SIZE)
        expect(parsed!.timestamp).toBeGreaterThan(0)
        expect(parsed!.action.length).toBe(ACTION_SIZE)
        expect(parsed!.context.length).toBe(CONTEXT_SIZE)
        expect(parsed!.mac.length).toBe(MAC_SIZE)
      }
    })

    it('should return null for empty string', () => {
      expect(parseOneShotToken('')).toBeNull()
    })

    it('should return null for garbage input', () => {
      expect(parseOneShotToken('not-a-valid-token')).toBeNull()
    })

    it('should return null for regular token (wrong size)', async () => {
      // A regular token is 89 bytes, not 120 — should be rejected
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)!
      const result = await import('../src/token.js').then((m) =>
        m.generateToken(provider, key),
      )
      if (result.success) {
        expect(parseOneShotToken(result.token)).toBeNull()
      }
    })
  })

  describe('validateOneShotToken', () => {
    it('should validate a freshly generated token', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'oneshot')
      const key = getActiveKey(keyring)!
      const nonceCache = createNonceCache()
      const now = Date.now()
      const result = await generateOneShotToken(provider, key, action, undefined, undefined, now)

      expect(result.success).toBe(true)
      if (result.success) {
        const validation = await validateOneShotToken(
          provider,
          key,
          result.token,
          action,
          nonceCache,
          undefined,
          undefined,
          now,
        )
        expect(validation).toEqual({ valid: true })
      }
    })

    it('should reject replay (same token used twice)', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'oneshot')
      const key = getActiveKey(keyring)!
      const nonceCache = createNonceCache()
      const now = Date.now()
      const result = await generateOneShotToken(provider, key, action, undefined, undefined, now)

      expect(result.success).toBe(true)
      if (result.success) {
        // First use — should succeed
        const validation1 = await validateOneShotToken(
          provider,
          key,
          result.token,
          action,
          nonceCache,
          undefined,
          undefined,
          now,
        )
        expect(validation1).toEqual({ valid: true })

        // Second use — should be rejected (replay)
        const validation2 = await validateOneShotToken(
          provider,
          key,
          result.token,
          action,
          nonceCache,
          undefined,
          undefined,
          now,
        )
        expect(validation2.valid).toBe(false)
        if (!validation2.valid) {
          expect(validation2.reason).toBe('nonce_reused')
        }
      }
    })

    it('should reject cross-action replay', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'oneshot')
      const key = getActiveKey(keyring)!
      const nonceCache = createNonceCache()
      const now = Date.now()
      const result = await generateOneShotToken(
        provider,
        key,
        'POST:/api/account/delete',
        undefined,
        undefined,
        now,
      )

      expect(result.success).toBe(true)
      if (result.success) {
        // Try to validate with different action
        const validation = await validateOneShotToken(
          provider,
          key,
          result.token,
          'POST:/api/account/update', // Different action
          nonceCache,
          undefined,
          undefined,
          now,
        )
        expect(validation.valid).toBe(false)
      }
    })

    it('should reject expired token', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'oneshot')
      const key = getActiveKey(keyring)!
      const nonceCache = createNonceCache()
      const tokenTime = Date.now()
      const result = await generateOneShotToken(
        provider,
        key,
        action,
        undefined,
        undefined,
        tokenTime,
      )

      expect(result.success).toBe(true)
      if (result.success) {
        // Validate far in the future (past TTL — no grace window for one-shot)
        const futureTime = tokenTime + 5 * 60 * 1000 + 1 // 5 min + 1ms
        const validation = await validateOneShotToken(
          provider,
          key,
          result.token,
          action,
          nonceCache,
          undefined,
          undefined,
          futureTime,
        )
        expect(validation.valid).toBe(false)
      }
    })

    it('should validate with context binding', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'oneshot')
      const key = getActiveKey(keyring)!
      const nonceCache = createNonceCache()
      const ctx = await computeContext(provider, 'session123')
      const now = Date.now()
      const result = await generateOneShotToken(provider, key, action, ctx, undefined, now)

      expect(result.success).toBe(true)
      if (result.success) {
        const validation = await validateOneShotToken(
          provider,
          key,
          result.token,
          action,
          nonceCache,
          ctx,
          undefined,
          now,
        )
        expect(validation).toEqual({ valid: true })
      }
    })

    it('should reject wrong context', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'oneshot')
      const key = getActiveKey(keyring)!
      const nonceCache = createNonceCache()
      const ctx = await computeContext(provider, 'session123')
      const wrongCtx = await computeContext(provider, 'session999')
      const now = Date.now()
      const result = await generateOneShotToken(provider, key, action, ctx, undefined, now)

      expect(result.success).toBe(true)
      if (result.success) {
        const validation = await validateOneShotToken(
          provider,
          key,
          result.token,
          action,
          nonceCache,
          wrongCtx,
          undefined,
          now,
        )
        expect(validation.valid).toBe(false)
      }
    })

    it('should reject tampered token', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'oneshot')
      const key = getActiveKey(keyring)!
      const nonceCache = createNonceCache()
      const now = Date.now()
      const result = await generateOneShotToken(provider, key, action, undefined, undefined, now)

      expect(result.success).toBe(true)
      if (result.success) {
        const tampered = result.token.slice(0, -1) + (result.token.endsWith('A') ? 'B' : 'A')
        const validation = await validateOneShotToken(
          provider,
          key,
          tampered,
          action,
          nonceCache,
          undefined,
          undefined,
          now,
        )
        expect(validation.valid).toBe(false)
      }
    })

    it('should reject garbage input', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'oneshot')
      const key = getActiveKey(keyring)!
      const nonceCache = createNonceCache()

      const validation = await validateOneShotToken(
        provider,
        key,
        'garbage-not-a-token',
        action,
        nonceCache,
      )
      expect(validation.valid).toBe(false)
    })
  })

  describe('nonce protection', () => {
    it('tampered token should NOT burn the nonce (legitimate token still works)', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'oneshot')
      const key = getActiveKey(keyring)!
      const nonceCache = createNonceCache()
      const now = Date.now()
      const result = await generateOneShotToken(provider, key, action, undefined, undefined, now)

      expect(result.success).toBe(true)
      if (result.success) {
        // Submit tampered version first (flip last char)
        const tampered = result.token.slice(0, -1) + (result.token.endsWith('A') ? 'B' : 'A')
        const tamperedResult = await validateOneShotToken(
          provider,
          key,
          tampered,
          action,
          nonceCache,
          undefined,
          undefined,
          now,
        )
        expect(tamperedResult.valid).toBe(false)

        // Now submit the REAL token — should still work (nonce not burned)
        const validResult = await validateOneShotToken(
          provider,
          key,
          result.token,
          action,
          nonceCache,
          undefined,
          undefined,
          now,
        )
        expect(validResult).toEqual({ valid: true })
      }
    })

    it('wrong action should NOT burn the nonce', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'oneshot')
      const key = getActiveKey(keyring)!
      const nonceCache = createNonceCache()
      const now = Date.now()
      const result = await generateOneShotToken(
        provider,
        key,
        'POST:/api/delete',
        undefined,
        undefined,
        now,
      )

      expect(result.success).toBe(true)
      if (result.success) {
        // Submit with wrong action
        const wrongAction = await validateOneShotToken(
          provider,
          key,
          result.token,
          'POST:/api/update', // Wrong action
          nonceCache,
          undefined,
          undefined,
          now,
        )
        expect(wrongAction.valid).toBe(false)

        // Submit with correct action — should still work
        const correctAction = await validateOneShotToken(
          provider,
          key,
          result.token,
          'POST:/api/delete',
          nonceCache,
          undefined,
          undefined,
          now,
        )
        expect(correctAction).toEqual({ valid: true })
      }
    })
  })

  describe('domain separation', () => {
    it('csrf key cannot validate one-shot token', async () => {
      const oneshotKeyring = await createKeyring(provider, masterSecret, 1, 'oneshot')
      const csrfKeyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const oneshotKey = getActiveKey(oneshotKeyring)!
      const csrfKey = getActiveKey(csrfKeyring)!
      const nonceCache = createNonceCache()
      const now = Date.now()

      // Generate one-shot token with oneshot key
      const result = await generateOneShotToken(
        provider,
        oneshotKey,
        action,
        undefined,
        undefined,
        now,
      )

      expect(result.success).toBe(true)
      if (result.success) {
        // Validate with csrf key — should fail (different HKDF derivation path)
        const validation = await validateOneShotToken(
          provider,
          csrfKey,
          result.token,
          action,
          nonceCache,
          undefined,
          undefined,
          now,
        )
        expect(validation.valid).toBe(false)
      }
    })
  })

  describe('token size assertions', () => {
    it('ONESHOT_RAW_SIZE should be exactly 120', () => {
      expect(ONESHOT_RAW_SIZE).toBe(120)
    })

    it('one-shot token raw bytes should always be 120', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'oneshot')
      const key = getActiveKey(keyring)!

      for (let i = 0; i < 10; i++) {
        const result = await generateOneShotToken(provider, key, action)
        if (result.success) {
          const raw = fromBase64Url(result.token)
          expect(raw.length).toBe(120)
        }
      }
    })
  })
})
