import { describe, expect, it } from 'vitest'
import { WebCryptoCryptoProvider } from '../src/web-crypto-provider.js'
import { createKeyring, getActiveKey, rotateKey } from '../src/key-manager.js'
import { fromBase64Url, toBase64Url } from '../src/encoding.js'
import { generateToken, validateToken } from '../src/index.js'
import { generateOneShotToken, validateOneShotToken } from '../src/one-shot-token.js'
import { createNonceCache } from '../src/nonce-cache.js'
import {
  DEFAULT_GRACE_WINDOW_MS,
  DEFAULT_TOKEN_TTL_MS,
  ONESHOT_RAW_SIZE,
  TOKEN_RAW_SIZE,
} from '../src/types.js'

function flipByte(token: string, byteOffset: number): string {
  const raw = fromBase64Url(token)
  raw[byteOffset] = (raw[byteOffset] ?? 0) ^ 0xff
  return toBase64Url(raw)
}

describe('hardening', () => {
  const provider = new WebCryptoCryptoProvider()
  const masterSecret = globalThis.crypto.getRandomValues(new Uint8Array(32)).buffer
  const action = 'POST:/api/account/delete'

  describe('replay semantics', () => {
    it('should allow validating the same regular token multiple times within TTL', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)
      expect(key).toBeDefined()
      if (key === undefined) {
        return
      }

      const now = Date.now()
      const tokenResult = await generateToken(provider, key, undefined, undefined, now)
      expect(tokenResult.success).toBe(true)
      if (!tokenResult.success) {
        return
      }

      const firstValidation = await validateToken(
        provider,
        keyring,
        tokenResult.token,
        undefined,
        undefined,
        undefined,
        now,
      )
      const secondValidation = await validateToken(
        provider,
        keyring,
        tokenResult.token,
        undefined,
        undefined,
        undefined,
        now,
      )

      expect(firstValidation).toEqual({ valid: true })
      expect(secondValidation).toEqual({ valid: true })
    })
  })

  describe('forgery rejection', () => {
    it('should reject a regular token with a modified payload and original MAC', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)
      expect(key).toBeDefined()
      if (key === undefined) {
        return
      }

      const now = Date.now()
      const tokenResult = await generateToken(provider, key, undefined, undefined, now)
      expect(tokenResult.success).toBe(true)
      if (!tokenResult.success) {
        return
      }

      const tamperedToken = flipByte(tokenResult.token, 5)
      const validation = await validateToken(
        provider,
        keyring,
        tamperedToken,
        undefined,
        undefined,
        undefined,
        now,
      )

      expect(validation).toEqual({ valid: false, reason: 'invalid_mac' })
    })

    it('should reject a one-shot token with a modified payload and original MAC', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'oneshot')
      const key = getActiveKey(keyring)
      expect(key).toBeDefined()
      if (key === undefined) {
        return
      }

      const nonceCache = createNonceCache()
      const now = Date.now()
      const tokenResult = await generateOneShotToken(provider, key, action, undefined, undefined, now)
      expect(tokenResult.success).toBe(true)
      if (!tokenResult.success) {
        return
      }

      const tamperedToken = flipByte(tokenResult.token, 10)
      const validation = await validateOneShotToken(
        provider,
        key,
        tamperedToken,
        action,
        nonceCache,
        undefined,
        undefined,
        now,
      )

      expect(validation).toEqual({ valid: false, reason: 'invalid_mac' })
    })

    it('should reject zero-padded regular tokens', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const zeroPaddedToken = toBase64Url(new Uint8Array(TOKEN_RAW_SIZE))

      const validation = await validateToken(provider, keyring, zeroPaddedToken)

      expect(validation).toEqual({ valid: false, reason: 'invalid_mac' })
    })

    it('should reject zero-padded one-shot tokens', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'oneshot')
      const key = getActiveKey(keyring)
      expect(key).toBeDefined()
      if (key === undefined) {
        return
      }

      const nonceCache = createNonceCache()
      const zeroPaddedToken = toBase64Url(new Uint8Array(ONESHOT_RAW_SIZE))

      const validation = await validateOneShotToken(
        provider,
        key,
        zeroPaddedToken,
        action,
        nonceCache,
      )

      expect(validation).toEqual({ valid: false, reason: 'invalid_mac' })
    })
  })

  describe('fuzz and malformed input handling', () => {
    it('should reject randomized regular-token inputs without throwing', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')

      for (let index = 0; index < 32; index += 1) {
        const candidate = toBase64Url(globalThis.crypto.getRandomValues(new Uint8Array(13 + index)))
        const validation = await validateToken(provider, keyring, candidate)
        expect(validation.valid).toBe(false)
      }
    })

    it('should reject randomized one-shot inputs without throwing', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'oneshot')
      const key = getActiveKey(keyring)
      expect(key).toBeDefined()
      if (key === undefined) {
        return
      }

      for (let index = 0; index < 32; index += 1) {
        const candidate = toBase64Url(globalThis.crypto.getRandomValues(new Uint8Array(17 + index)))
        const validation = await validateOneShotToken(
          provider,
          key,
          candidate,
          action,
          createNonceCache(),
        )
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

    it('should reject unicode edge-case one-shot inputs', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'oneshot')
      const key = getActiveKey(keyring)
      expect(key).toBeDefined()
      if (key === undefined) {
        return
      }

      const candidates = ['🔥', '令和', 'a\u0000b', 'e\u0301', '\ud83d', '\u0000']

      for (const candidate of candidates) {
        const validation = await validateOneShotToken(
          provider,
          key,
          candidate,
          action,
          createNonceCache(),
        )
        expect(validation.valid).toBe(false)
      }
    })
  })

  describe('boundary and key lifecycle', () => {
    it('should accept a token exactly at the end of the grace window', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)
      expect(key).toBeDefined()
      if (key === undefined) {
        return
      }

      const tokenTime = 1_700_000_000_000
      const tokenResult = await generateToken(provider, key, undefined, undefined, tokenTime)
      expect(tokenResult.success).toBe(true)
      if (!tokenResult.success) {
        return
      }

      const validation = await validateToken(
        provider,
        keyring,
        tokenResult.token,
        undefined,
        DEFAULT_TOKEN_TTL_MS,
        DEFAULT_GRACE_WINDOW_MS,
        tokenTime + DEFAULT_TOKEN_TTL_MS + DEFAULT_GRACE_WINDOW_MS,
      )

      expect(validation).toEqual({ valid: true })
    })

    it('should reject a token 1ms past the grace-window boundary', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const key = getActiveKey(keyring)
      expect(key).toBeDefined()
      if (key === undefined) {
        return
      }

      const tokenTime = 1_700_000_000_000
      const tokenResult = await generateToken(provider, key, undefined, undefined, tokenTime)
      expect(tokenResult.success).toBe(true)
      if (!tokenResult.success) {
        return
      }

      const validation = await validateToken(
        provider,
        keyring,
        tokenResult.token,
        undefined,
        DEFAULT_TOKEN_TTL_MS,
        DEFAULT_GRACE_WINDOW_MS,
        tokenTime + DEFAULT_TOKEN_TTL_MS + DEFAULT_GRACE_WINDOW_MS + 1,
      )

      expect(validation.valid).toBe(false)
      if (!validation.valid) {
        expect(validation.reason).toBe('expired')
      }
    })

    it('should reject a token after its original kid is evicted from the keyring', async () => {
      let keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const originalKey = getActiveKey(keyring)
      expect(originalKey).toBeDefined()
      if (originalKey === undefined) {
        return
      }

      const now = Date.now()
      const tokenResult = await generateToken(provider, originalKey, undefined, undefined, now)
      expect(tokenResult.success).toBe(true)
      if (!tokenResult.success) {
        return
      }

      keyring = await rotateKey(keyring, provider, masterSecret, 2)
      keyring = await rotateKey(keyring, provider, masterSecret, 3)
      keyring = await rotateKey(keyring, provider, masterSecret, 4)

      const validation = await validateToken(
        provider,
        keyring,
        tokenResult.token,
        undefined,
        undefined,
        undefined,
        now,
      )

      expect(validation).toEqual({ valid: false, reason: 'invalid_mac' })
    })
  })
})
