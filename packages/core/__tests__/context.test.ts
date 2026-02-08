import { describe, it, expect } from 'vitest'
import { WebCryptoCryptoProvider } from '../src/web-crypto-provider.js'
import { computeContext, emptyContext } from '../src/context.js'
import { CONTEXT_SIZE } from '../src/types.js'

describe('context', () => {
  const provider = new WebCryptoCryptoProvider()

  describe('emptyContext', () => {
    it('should return 32 bytes', async () => {
      const ctx = await emptyContext(provider)
      expect(ctx.length).toBe(CONTEXT_SIZE)
    })

    it('should be deterministic', async () => {
      const ctx1 = await emptyContext(provider)
      const ctx2 = await emptyContext(provider)
      expect(ctx1).toEqual(ctx2)
    })

    it('should be SHA-256(0x00)', async () => {
      const ctx = await emptyContext(provider)
      // Known SHA-256 of single zero byte (0x00)
      const hash = await provider.hash(new Uint8Array([0x00]))
      expect(ctx).toEqual(new Uint8Array(hash))
    })
  })

  describe('computeContext', () => {
    it('should return 32 bytes for any binding', async () => {
      const ctx = await computeContext(provider, 'session123')
      expect(ctx.length).toBe(CONTEXT_SIZE)
    })

    it('should be deterministic', async () => {
      const ctx1 = await computeContext(provider, 'session123')
      const ctx2 = await computeContext(provider, 'session123')
      expect(ctx1).toEqual(ctx2)
    })

    it('should return emptyContext when no bindings', async () => {
      const ctx = await computeContext(provider)
      const empty = await emptyContext(provider)
      expect(ctx).toEqual(empty)
    })

    it('should produce different hashes for different bindings', async () => {
      const ctx1 = await computeContext(provider, 'session123')
      const ctx2 = await computeContext(provider, 'session456')
      expect(ctx1).not.toEqual(ctx2)
    })

    it('should produce different hashes for different binding counts', async () => {
      const ctx1 = await computeContext(provider, 'ab', 'cd')
      const ctx2 = await computeContext(provider, 'abcd')
      expect(ctx1).not.toEqual(ctx2) // Must NOT collide
    })

    it('should prevent concatenation collision (separator test)', async () => {
      // These MUST produce different hashes due to length-prefix encoding
      const ctx1 = await computeContext(provider, 'ab', 'cd')
      const ctx2 = await computeContext(provider, 'a', 'bcd')
      const ctx3 = await computeContext(provider, 'abc', 'd')
      const ctx4 = await computeContext(provider, 'abcd')

      // All four must be different
      const hashes = [ctx1, ctx2, ctx3, ctx4].map((h) =>
        Array.from(h)
          .map((b) => b.toString(16).padStart(2, '0'))
          .join(''),
      )
      const uniqueHashes = new Set(hashes)
      expect(uniqueHashes.size).toBe(4)
    })

    it('should handle empty string binding differently from no binding', async () => {
      const noBinding = await computeContext(provider) // emptyContext
      const emptyBinding = await computeContext(provider, '') // SHA-256 of length-prefixed ""
      expect(noBinding).not.toEqual(emptyBinding)
    })

    it('should handle unicode bindings', async () => {
      const ctx = await computeContext(provider, '日本語テスト')
      expect(ctx.length).toBe(CONTEXT_SIZE)
    })

    it('should handle many bindings', async () => {
      const ctx = await computeContext(
        provider,
        'session123',
        'user456',
        'https://example.com',
        'POST:/api/transfer',
      )
      expect(ctx.length).toBe(CONTEXT_SIZE)
    })
  })
})
