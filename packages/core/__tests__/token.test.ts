import { describe, it, expect } from 'vitest'
import { WebCryptoCryptoProvider } from '../src/web-crypto-provider.js'
import { createKeyring, getActiveKey } from '../src/key-manager.js'
import {
  generateToken,
  parseToken,
  serializeToken,
  assemblePayload,
} from '../src/token.js'
import { computeContext, emptyContext } from '../src/context.js'
import { TOKEN_RAW_SIZE, NONCE_SIZE, CONTEXT_SIZE, MAC_SIZE } from '../src/types.js'
import { fromBase64Url, toArrayBuffer } from '../src/encoding.js'

describe('token', () => {
  const provider = new WebCryptoCryptoProvider()
  const masterSecret = crypto.getRandomValues(new Uint8Array(32)).buffer

  describe('generateToken', () => {
    it('should generate a valid token', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)!
      const result = await generateToken(provider, key)

      expect(result.success).toBe(true)
      if (result.success) {
        expect(typeof result.token).toBe('string')
        expect(result.token.length).toBeGreaterThan(0)
        expect(result.expiresAt).toBeGreaterThan(Date.now())
      }
    })

    it('should produce constant-size tokens (89 bytes raw)', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)!
      const result = await generateToken(provider, key)

      expect(result.success).toBe(true)
      if (result.success) {
        const raw = fromBase64Url(result.token)
        expect(raw.length).toBe(TOKEN_RAW_SIZE) // 89 bytes FIXED
      }
    })

    it('should embed kid in token', async () => {
      const keyring = await createKeyring(provider, masterSecret, 42, 'csrf')
      const key = getActiveKey(keyring)!
      const result = await generateToken(provider, key)

      expect(result.success).toBe(true)
      if (result.success) {
        const parsed = parseToken(result.token)
        expect(parsed).not.toBeNull()
        expect(parsed!.kid).toBe(42)
      }
    })

    it('should include context binding when provided', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)!
      const ctx = await computeContext(provider, 'session123', 'user456')
      const result = await generateToken(provider, key, ctx)

      expect(result.success).toBe(true)
      if (result.success) {
        const parsed = parseToken(result.token)
        expect(parsed).not.toBeNull()
        expect(parsed!.context).toEqual(ctx)
      }
    })

    it('should use empty context (SHA-256(0x00)) when no context provided', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)!
      const result = await generateToken(provider, key)

      expect(result.success).toBe(true)
      if (result.success) {
        const parsed = parseToken(result.token)
        const expected = await emptyContext(provider)
        expect(parsed!.context).toEqual(expected)
      }
    })

    it('should generate unique nonces', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)!
      const result1 = await generateToken(provider, key)
      const result2 = await generateToken(provider, key)

      expect(result1.success).toBe(true)
      expect(result2.success).toBe(true)
      if (result1.success && result2.success) {
        // Different tokens (due to different nonces)
        expect(result1.token).not.toBe(result2.token)
        const parsed1 = parseToken(result1.token)
        const parsed2 = parseToken(result2.token)
        expect(parsed1!.nonce).not.toEqual(parsed2!.nonce)
      }
    })

    it('should use provided timestamp', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)!
      const now = 1700000000000
      const result = await generateToken(provider, key, undefined, undefined, now)

      expect(result.success).toBe(true)
      if (result.success) {
        const parsed = parseToken(result.token)
        expect(parsed!.timestamp).toBe(now)
      }
    })

    it('should calculate expiresAt correctly', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)!
      const now = 1700000000000
      const ttl = 600000 // 10 minutes
      const result = await generateToken(provider, key, undefined, ttl, now)

      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.expiresAt).toBe(now + ttl)
      }
    })
  })

  describe('parseToken', () => {
    it('should parse a generated token', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)!
      const result = await generateToken(provider, key)

      expect(result.success).toBe(true)
      if (result.success) {
        const parsed = parseToken(result.token)
        expect(parsed).not.toBeNull()
        expect(parsed!.kid).toBe(1)
        expect(parsed!.nonce.length).toBe(NONCE_SIZE) // 16 bytes
        expect(parsed!.timestamp).toBeGreaterThan(0)
        expect(parsed!.context.length).toBe(CONTEXT_SIZE) // 32 bytes
        expect(parsed!.mac.length).toBe(MAC_SIZE) // 32 bytes
      }
    })

    it('should return null for empty string', () => {
      expect(parseToken('')).toBeNull()
    })

    it('should return null for garbage input', () => {
      expect(parseToken('not-a-valid-token')).toBeNull()
    })

    it('should return null for truncated token', () => {
      expect(parseToken('AAAAAAAAAA')).toBeNull()
    })

    it('should return null for oversized token', async () => {
      // Create a buffer larger than expected
      const oversized = new Uint8Array(TOKEN_RAW_SIZE + 10)
      crypto.getRandomValues(oversized)
      const { toBase64Url } = await import('../src/encoding.js')
      const encoded = toBase64Url(oversized)
      expect(parseToken(encoded)).toBeNull()
    })

    it('should return null for invalid base64url', () => {
      expect(parseToken('!!!invalid!!!')).toBeNull()
    })
  })

  describe('assemblePayload', () => {
    it('should reconstruct payload from parsed token', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)!
      const result = await generateToken(provider, key)

      expect(result.success).toBe(true)
      if (result.success) {
        const parsed = parseToken(result.token)!
        const payload = assemblePayload(parsed)

        // Payload should be kid + nonce + ts + ctx = 57 bytes
        expect(payload.length).toBe(1 + 16 + 8 + 32)

        // Verify the MAC matches
        const valid = await provider.verify(
          key.cryptoKey,
          toArrayBuffer(parsed.mac),
          payload,
        )
        expect(valid).toBe(true)
      }
    })
  })

  describe('serializeToken', () => {
    it('should produce parseable token', () => {
      const kid = 5
      const nonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE))
      const ts = Date.now()
      const ctx = crypto.getRandomValues(new Uint8Array(CONTEXT_SIZE))
      const mac = crypto.getRandomValues(new Uint8Array(MAC_SIZE))

      const token = serializeToken(kid, nonce, ts, ctx, mac)
      const parsed = parseToken(token)

      expect(parsed).not.toBeNull()
      expect(parsed!.kid).toBe(kid)
      expect(parsed!.nonce).toEqual(nonce)
      expect(parsed!.timestamp).toBe(ts)
      expect(parsed!.context).toEqual(ctx)
      expect(parsed!.mac).toEqual(mac)
    })

    it('should produce constant-size output', () => {
      const nonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE))
      const ctx = crypto.getRandomValues(new Uint8Array(CONTEXT_SIZE))
      const mac = crypto.getRandomValues(new Uint8Array(MAC_SIZE))

      const token = serializeToken(0, nonce, 0, ctx, mac)
      const raw = fromBase64Url(token)
      expect(raw.length).toBe(TOKEN_RAW_SIZE)
    })
  })

  describe('kid edge cases', () => {
    it('should handle kid=0 (falsy value)', async () => {
      const keyring = await createKeyring(provider, masterSecret, 0, 'csrf')
      const key = getActiveKey(keyring)!
      const now = Date.now()
      const result = await generateToken(provider, key, undefined, undefined, now)

      expect(result.success).toBe(true)
      if (result.success) {
        const parsed = parseToken(result.token)
        expect(parsed).not.toBeNull()
        expect(parsed!.kid).toBe(0)
      }
    })

    it('should handle kid=255 (max 8-bit value)', async () => {
      const keyring = await createKeyring(provider, masterSecret, 255, 'csrf')
      const key = getActiveKey(keyring)!
      const now = Date.now()
      const result = await generateToken(provider, key, undefined, undefined, now)

      expect(result.success).toBe(true)
      if (result.success) {
        const parsed = parseToken(result.token)
        expect(parsed).not.toBeNull()
        expect(parsed!.kid).toBe(255)
      }
    })

    it('should truncate kid > 255 to 8-bit', async () => {
      // kid=256 → 0x100 & 0xFF = 0x00
      const keyring = await createKeyring(provider, masterSecret, 256, 'csrf')
      const key = getActiveKey(keyring)!
      const result = await generateToken(provider, key)

      expect(result.success).toBe(true)
      if (result.success) {
        const parsed = parseToken(result.token)
        expect(parsed).not.toBeNull()
        expect(parsed!.kid).toBe(0) // Truncated to 8-bit
      }
    })
  })

  describe('token size assertions', () => {
    it('TOKEN_RAW_SIZE should be exactly 89', () => {
      expect(TOKEN_RAW_SIZE).toBe(89)
    })

    it('token raw bytes should always be 89', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)!

      // Generate multiple tokens and check all are 89 bytes
      for (let i = 0; i < 10; i++) {
        const result = await generateToken(provider, key)
        if (result.success) {
          const raw = fromBase64Url(result.token)
          expect(raw.length).toBe(89)
        }
      }
    })
  })
})
