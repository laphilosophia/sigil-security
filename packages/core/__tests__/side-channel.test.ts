import { describe, expect, it, vi } from 'vitest'
import type { CryptoProvider } from '../src/crypto-provider.js'
import type { NonceCache } from '../src/nonce-cache.js'
import { WebCryptoCryptoProvider } from '../src/web-crypto-provider.js'
import { createKeyring, getActiveKey } from '../src/key-manager.js'
import { toBase64Url } from '../src/encoding.js'
import { generateToken } from '../src/token.js'
import { generateOneShotToken, validateOneShotToken } from '../src/one-shot-token.js'
import { validateToken } from '../src/validation.js'

function createSpyProvider(): {
  provider: CryptoProvider
  verifySpy: ReturnType<typeof vi.fn>
  hashSpy: ReturnType<typeof vi.fn>
} {
  const realProvider = new WebCryptoCryptoProvider()

  const verifySpy = vi.fn(
    async (key: CryptoKey, signature: ArrayBuffer, data: Uint8Array) =>
      realProvider.verify(key, signature, data),
  )
  const hashSpy = vi.fn(async (data: Uint8Array) => realProvider.hash(data))

  const provider: CryptoProvider = {
    sign: (key, data) => realProvider.sign(key, data),
    verify: verifySpy,
    deriveKey: (master, salt, info) => realProvider.deriveKey(master, salt, info),
    randomBytes: (length) => realProvider.randomBytes(length),
    hash: hashSpy,
  }

  return { provider, verifySpy, hashSpy }
}

function createNonceCacheSpy(): {
  nonceCache: NonceCache
  hasSpy: ReturnType<typeof vi.fn>
  markUsedSpy: ReturnType<typeof vi.fn>
} {
  const seen = new Set<string>()
  const getNonceKey = (nonce: Uint8Array): string => toBase64Url(nonce)

  const hasSpy = vi.fn((nonce: Uint8Array) => seen.has(getNonceKey(nonce)))
  const markUsedSpy = vi.fn((nonce: Uint8Array) => {
    const key = getNonceKey(nonce)
    if (seen.has(key)) {
      return false
    }

    seen.add(key)
    return true
  })

  return {
    nonceCache: {
      get size(): number {
        return seen.size
      },
      has: hasSpy,
      add: (nonce: Uint8Array) => {
        seen.add(getNonceKey(nonce))
      },
      markUsed: markUsedSpy,
    },
    hasSpy,
    markUsedSpy,
  }
}

describe('side-channel verification', () => {
  const masterSecret = globalThis.crypto.getRandomValues(new Uint8Array(32)).buffer
  const action = 'POST:/api/account/delete'

  it('should still perform HMAC verification for malformed regular tokens', async () => {
    const { provider, verifySpy } = createSpyProvider()
    const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')

    const validation = await validateToken(provider, keyring, 'not-a-token')

    expect(validation).toEqual({ valid: false, reason: 'invalid_mac' })
    expect(verifySpy).toHaveBeenCalledTimes(1)
  })

  it('should still perform HMAC verification when regular-token kid is unknown', async () => {
    const { provider, verifySpy } = createSpyProvider()
    const validationProvider = new WebCryptoCryptoProvider()
    const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
    const otherKeyring = await createKeyring(validationProvider, masterSecret, 99, 'csrf')
    const otherKey = getActiveKey(otherKeyring)
    expect(otherKey).toBeDefined()
    if (otherKey === undefined) {
      return
    }

    const now = Date.now()
    const tokenResult = await generateToken(validationProvider, otherKey, undefined, undefined, now)
    expect(tokenResult.success).toBe(true)
    if (!tokenResult.success) {
      return
    }

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
    expect(verifySpy).toHaveBeenCalledTimes(1)
  })

  it('should still hash the expected action and verify malformed one-shot tokens', async () => {
    const { provider, verifySpy, hashSpy } = createSpyProvider()
    const keyring = await createKeyring(provider, masterSecret, 1, 'oneshot')
    const key = getActiveKey(keyring)
    expect(key).toBeDefined()
    if (key === undefined) {
      return
    }

    const { nonceCache, hasSpy, markUsedSpy } = createNonceCacheSpy()

    const validation = await validateOneShotToken(
      provider,
      key,
      'not-a-token',
      action,
      nonceCache,
    )

    expect(validation).toEqual({ valid: false, reason: 'nonce_reused' })
    expect(hashSpy).toHaveBeenCalledTimes(1)
    expect(verifySpy).toHaveBeenCalledTimes(1)
    expect(hasSpy).not.toHaveBeenCalled()
    expect(markUsedSpy).not.toHaveBeenCalled()
  })

  it('should check nonce presence even when one-shot MAC validation fails', async () => {
    const { provider, verifySpy, hashSpy } = createSpyProvider()
    const generationProvider = new WebCryptoCryptoProvider()
    const keyring = await createKeyring(provider, masterSecret, 1, 'oneshot')
    const generationKeyring = await createKeyring(generationProvider, masterSecret, 1, 'oneshot')
    const key = getActiveKey(keyring)
    const generationKey = getActiveKey(generationKeyring)
    expect(key).toBeDefined()
    expect(generationKey).toBeDefined()
    if (key === undefined || generationKey === undefined) {
      return
    }

    const { nonceCache, hasSpy, markUsedSpy } = createNonceCacheSpy()
    const now = Date.now()
    const tokenResult = await generateOneShotToken(
      generationProvider,
      generationKey,
      action,
      undefined,
      undefined,
      now,
    )
    expect(tokenResult.success).toBe(true)
    if (!tokenResult.success) {
      return
    }

    const tamperedToken = `${tokenResult.token.slice(0, -1)}${tokenResult.token.endsWith('A') ? 'B' : 'A'}`
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
    expect(hashSpy).toHaveBeenCalledTimes(1)
    expect(verifySpy).toHaveBeenCalledTimes(1)
    expect(hasSpy).toHaveBeenCalledTimes(1)
    expect(markUsedSpy).not.toHaveBeenCalled()
  })

  it('should only consume the one-shot nonce on the successful path', async () => {
    const { provider, verifySpy, hashSpy } = createSpyProvider()
    const keyring = await createKeyring(provider, masterSecret, 1, 'oneshot')
    const key = getActiveKey(keyring)
    expect(key).toBeDefined()
    if (key === undefined) {
      return
    }

    const { nonceCache, hasSpy, markUsedSpy } = createNonceCacheSpy()
    const now = Date.now()
    const tokenResult = await generateOneShotToken(provider, key, action, undefined, undefined, now)
    expect(tokenResult.success).toBe(true)
    if (!tokenResult.success) {
      return
    }
    hashSpy.mockClear()
    verifySpy.mockClear()

    const validation = await validateOneShotToken(
      provider,
      key,
      tokenResult.token,
      action,
      nonceCache,
      undefined,
      undefined,
      now,
    )

    expect(validation).toEqual({ valid: true })
    expect(hashSpy).toHaveBeenCalledTimes(1)
    expect(verifySpy).toHaveBeenCalledTimes(1)
    expect(hasSpy).toHaveBeenCalledTimes(1)
    expect(markUsedSpy).toHaveBeenCalledTimes(1)
  })
})
