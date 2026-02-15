import { describe, it, expect, beforeEach } from 'vitest'
import { createSigil } from '../src/sigil.js'
import type { SigilInstance } from '../src/types.js'
import type { RequestMetadata } from '@sigil-security/policy'

describe('sigil', () => {
  const masterSecret = 'test-master-secret-at-least-32-bytes-long!'
  let sigil: SigilInstance

  beforeEach(async () => {
    sigil = await createSigil({
      masterSecret,
      allowedOrigins: ['https://example.com'],
    })
  })

  describe('createSigil', () => {
    it('should create a sigil instance with default config', () => {
      expect(sigil.config.tokenTTL).toBe(20 * 60 * 1000) // 20 minutes
      expect(sigil.config.graceWindow).toBe(60 * 1000) // 60 seconds
      expect(sigil.config.legacyBrowserMode).toBe('degraded')
      expect(sigil.config.allowApiMode).toBe(true)
      expect(sigil.config.protectedMethods).toEqual(['POST', 'PUT', 'PATCH', 'DELETE'])
      expect(sigil.config.oneShotEnabled).toBe(false)
      expect(sigil.config.headerName).toBe('x-csrf-token')
    })

    it('should accept string master secret', async () => {
      const instance = await createSigil({
        masterSecret: 'my-secret-string-at-least-32-bytes!!',
        allowedOrigins: ['https://example.com'],
      })
      expect(instance).toBeDefined()
    })

    it('should accept ArrayBuffer master secret', async () => {
      const secret = globalThis.crypto.getRandomValues(new Uint8Array(32)).buffer
      const instance = await createSigil({
        masterSecret: secret,
        allowedOrigins: ['https://example.com'],
      })
      expect(instance).toBeDefined()
    })

    it('should reject short string master secret (L1 fix)', async () => {
      await expect(
        createSigil({
          masterSecret: 'too-short',
          allowedOrigins: ['https://example.com'],
        }),
      ).rejects.toThrow('Master secret must be at least 32 bytes')
    })

    it('should reject short ArrayBuffer master secret (L1 fix)', async () => {
      const shortSecret = new ArrayBuffer(16)
      await expect(
        createSigil({
          masterSecret: shortSecret,
          allowedOrigins: ['https://example.com'],
        }),
      ).rejects.toThrow('Master secret must be at least 32 bytes')
    })

    it('should accept exactly 32-byte string master secret', async () => {
      // 32 ASCII characters = 32 bytes when UTF-8 encoded
      const instance = await createSigil({
        masterSecret: 'a]3kf9$mP2nQ7wL!xR4vB8cE1hJ5gT0s',
        allowedOrigins: ['https://example.com'],
      })
      expect(instance).toBeDefined()
    })

    it('should include disableClientModeOverride in resolved config', async () => {
      const instance = await createSigil({
        masterSecret: 'test-master-secret-at-least-32-bytes-long!',
        allowedOrigins: ['https://example.com'],
        disableClientModeOverride: true,
      })
      expect(instance.config.disableClientModeOverride).toBe(true)
    })

    it('should default disableClientModeOverride to false', () => {
      expect(sigil.config.disableClientModeOverride).toBe(false)
    })

    it('should apply custom config', async () => {
      const instance = await createSigil({
        masterSecret,
        allowedOrigins: ['https://custom.com'],
        tokenTTL: 10 * 60 * 1000,
        graceWindow: 30 * 1000,
        legacyBrowserMode: 'strict',
        allowApiMode: false,
        protectedMethods: ['POST', 'DELETE'],
        headerName: 'x-custom-token',
      })

      expect(instance.config.tokenTTL).toBe(10 * 60 * 1000)
      expect(instance.config.graceWindow).toBe(30 * 1000)
      expect(instance.config.legacyBrowserMode).toBe('strict')
      expect(instance.config.allowApiMode).toBe(false)
      expect(instance.config.protectedMethods).toEqual(['POST', 'DELETE'])
      expect(instance.config.headerName).toBe('x-custom-token')
    })
  })

  describe('generateToken', () => {
    it('should generate a token successfully', async () => {
      const result = await sigil.generateToken()

      expect(result.success).toBe(true)
      if (result.success) {
        expect(typeof result.token).toBe('string')
        expect(result.token.length).toBeGreaterThan(0)
        expect(result.expiresAt).toBeGreaterThan(Date.now())
      }
    })

    it('should generate different tokens each time (nonce uniqueness)', async () => {
      const result1 = await sigil.generateToken()
      const result2 = await sigil.generateToken()

      expect(result1.success).toBe(true)
      expect(result2.success).toBe(true)
      if (result1.success && result2.success) {
        expect(result1.token).not.toBe(result2.token)
      }
    })

    it('should accept context bindings', async () => {
      const result = await sigil.generateToken(['session-id', 'user-id'])

      expect(result.success).toBe(true)
      if (result.success) {
        expect(typeof result.token).toBe('string')
      }
    })
  })

  describe('validateToken', () => {
    it('should validate a freshly generated token', async () => {
      const gen = await sigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const result = await sigil.validateToken(gen.token)
      expect(result.valid).toBe(true)
    })

    it('should reject a tampered token', async () => {
      const gen = await sigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      // Tamper with the token — flip a character in the middle of the MAC region.
      // Avoid the last character which may only carry padding bits in base64url.
      const mid = Math.floor(gen.token.length / 2)
      const original = gen.token[mid]
      // Pick a different base64url character (cycle through a few safe choices)
      const replacement = original === 'X' ? 'Y' : 'X'
      const tampered = gen.token.slice(0, mid) + replacement + gen.token.slice(mid + 1)
      expect(tampered).not.toBe(gen.token)

      const result = await sigil.validateToken(tampered)
      expect(result.valid).toBe(false)
    })

    it('should reject a completely invalid token', async () => {
      const result = await sigil.validateToken('not-a-valid-token')
      expect(result.valid).toBe(false)
    })

    it('should validate with context bindings', async () => {
      const context = ['session-123', 'user-456']
      const gen = await sigil.generateToken(context)
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const valid = await sigil.validateToken(gen.token, context)
      expect(valid.valid).toBe(true)
    })

    it('should reject when context bindings differ', async () => {
      const gen = await sigil.generateToken(['session-123'])
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const result = await sigil.validateToken(gen.token, ['different-session'])
      expect(result.valid).toBe(false)
    })
  })

  describe('rotateKeys', () => {
    it('should rotate keys and still validate old tokens', async () => {
      const gen = await sigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      // Rotate keys
      await sigil.rotateKeys()

      // Old token should still be valid (matched by kid)
      const result = await sigil.validateToken(gen.token)
      expect(result.valid).toBe(true)
    })

    it('should generate tokens with new key after rotation', async () => {
      const gen1 = await sigil.generateToken()
      await sigil.rotateKeys()
      const gen2 = await sigil.generateToken()

      expect(gen1.success).toBe(true)
      expect(gen2.success).toBe(true)
      if (gen1.success && gen2.success) {
        expect(gen1.token).not.toBe(gen2.token)
      }
    })
  })

  describe('one-shot tokens', () => {
    let oneShotSigil: SigilInstance

    beforeEach(async () => {
      oneShotSigil = await createSigil({
        masterSecret,
        allowedOrigins: ['https://example.com'],
        oneShotEnabled: true,
      })
    })

    it('should generate a one-shot token', async () => {
      const result = await oneShotSigil.generateOneShotToken('POST:/api/delete')
      expect(result.success).toBe(true)
      if (result.success) {
        expect(typeof result.token).toBe('string')
      }
    })

    it('should validate a one-shot token', async () => {
      const gen = await oneShotSigil.generateOneShotToken('POST:/api/delete')
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const result = await oneShotSigil.validateOneShotToken(
        gen.token,
        'POST:/api/delete',
      )
      expect(result.valid).toBe(true)
    })

    it('should reject one-shot token with wrong action', async () => {
      const gen = await oneShotSigil.generateOneShotToken('POST:/api/delete')
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const result = await oneShotSigil.validateOneShotToken(
        gen.token,
        'POST:/api/transfer',
      )
      expect(result.valid).toBe(false)
    })

    it('should reject one-shot token on replay', async () => {
      const gen = await oneShotSigil.generateOneShotToken('POST:/api/delete')
      expect(gen.success).toBe(true)
      if (!gen.success) return

      // First use — should succeed
      const first = await oneShotSigil.validateOneShotToken(
        gen.token,
        'POST:/api/delete',
      )
      expect(first.valid).toBe(true)

      // Second use — should fail (replay)
      const second = await oneShotSigil.validateOneShotToken(
        gen.token,
        'POST:/api/delete',
      )
      expect(second.valid).toBe(false)
    })

    it('should fail when one-shot is not enabled', async () => {
      const result = await sigil.generateOneShotToken('POST:/api/delete')
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.reason).toBe('oneshot_not_enabled')
      }
    })
  })

  describe('protect', () => {
    function createMetadata(overrides: Partial<RequestMetadata> = {}): RequestMetadata {
      return {
        method: 'POST',
        origin: 'https://example.com',
        referer: null,
        secFetchSite: 'same-origin',
        secFetchMode: 'cors',
        secFetchDest: 'empty',
        contentType: 'application/json',
        tokenSource: { from: 'none' },
        ...overrides,
      }
    }

    it('should allow GET requests without token', async () => {
      const metadata = createMetadata({ method: 'GET' })
      const result = await sigil.protect(metadata)

      expect(result.allowed).toBe(true)
    })

    it('should allow HEAD requests without token', async () => {
      const metadata = createMetadata({ method: 'HEAD' })
      const result = await sigil.protect(metadata)

      expect(result.allowed).toBe(true)
    })

    it('should allow OPTIONS requests without token', async () => {
      const metadata = createMetadata({ method: 'OPTIONS' })
      const result = await sigil.protect(metadata)

      expect(result.allowed).toBe(true)
    })

    it('should reject POST without token', async () => {
      const metadata = createMetadata({ method: 'POST' })
      const result = await sigil.protect(metadata)

      expect(result.allowed).toBe(false)
      if (!result.allowed) {
        expect(result.reason).toBe('no_token_present')
      }
    })

    it('should allow POST with valid token (browser mode)', async () => {
      const gen = await sigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const metadata = createMetadata({
        method: 'POST',
        tokenSource: { from: 'header', value: gen.token },
      })

      const result = await sigil.protect(metadata)
      expect(result.allowed).toBe(true)
    })

    it('should allow POST with valid token (API mode)', async () => {
      const gen = await sigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const metadata = createMetadata({
        method: 'POST',
        secFetchSite: null, // No Fetch Metadata → API mode
        origin: null,
        tokenSource: { from: 'header', value: gen.token },
      })

      const result = await sigil.protect(metadata)
      expect(result.allowed).toBe(true)
    })

    it('should reject cross-site requests in browser mode', async () => {
      const gen = await sigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const metadata = createMetadata({
        method: 'POST',
        secFetchSite: 'cross-site',
        tokenSource: { from: 'header', value: gen.token },
      })

      const result = await sigil.protect(metadata)
      expect(result.allowed).toBe(false)
    })

    it('should reject API mode when disabled', async () => {
      const strictSigil = await createSigil({
        masterSecret,
        allowedOrigins: ['https://example.com'],
        allowApiMode: false,
      })

      const gen = await strictSigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const metadata = createMetadata({
        method: 'POST',
        secFetchSite: null, // API mode
        origin: null,
        tokenSource: { from: 'header', value: gen.token },
      })

      const result = await strictSigil.protect(metadata)
      expect(result.allowed).toBe(false)
      if (!result.allowed) {
        expect(result.reason).toBe('api_mode_not_allowed')
      }
    })

    it('should reject POST with invalid token', async () => {
      const metadata = createMetadata({
        method: 'POST',
        tokenSource: { from: 'header', value: 'invalid-token' },
      })

      const result = await sigil.protect(metadata)
      expect(result.allowed).toBe(false)
    })

    it('should protect with context bindings', async () => {
      const context = ['session-123']
      const gen = await sigil.generateToken(context)
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const metadata = createMetadata({
        method: 'POST',
        tokenSource: { from: 'header', value: gen.token },
      })

      // With matching context → allowed
      const valid = await sigil.protect(metadata, context)
      expect(valid.allowed).toBe(true)

      // With wrong context → rejected
      const invalid = await sigil.protect(metadata, ['wrong-session'])
      expect(invalid.allowed).toBe(false)
    })

    it('should include policy result in response', async () => {
      const gen = await sigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const metadata = createMetadata({
        method: 'POST',
        tokenSource: { from: 'header', value: gen.token },
      })

      const result = await sigil.protect(metadata)
      expect(result.allowed).toBe(true)
      if (result.allowed) {
        expect(result.policyResult).toBeDefined()
        expect(result.policyResult.evaluated.length).toBeGreaterThan(0)
      }
    })

    it('should set expired flag when token is expired', async () => {
      // Create sigil with very short TTL
      const shortSigil = await createSigil({
        masterSecret,
        allowedOrigins: ['https://example.com'],
        tokenTTL: 1, // 1ms TTL
        graceWindow: 0,
      })

      const gen = await shortSigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      // Wait for token to expire
      await new Promise((resolve) => setTimeout(resolve, 10))

      const metadata = createMetadata({
        method: 'POST',
        tokenSource: { from: 'header', value: gen.token },
      })

      const result = await shortSigil.protect(metadata)
      expect(result.allowed).toBe(false)
      if (!result.allowed) {
        expect(result.expired).toBe(true)
      }
    })
  })
})
