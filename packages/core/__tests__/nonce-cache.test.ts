import { describe, it, expect, vi, afterEach } from 'vitest'
import { createNonceCache } from '../src/nonce-cache.js'

describe('nonce-cache', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  function randomNonce(): Uint8Array {
    return globalThis.crypto.getRandomValues(new Uint8Array(16))
  }

  describe('createNonceCache', () => {
    it('should create an empty cache', () => {
      const cache = createNonceCache()
      expect(cache.size).toBe(0)
    })
  })

  describe('add / has', () => {
    it('should add and find a nonce', () => {
      const cache = createNonceCache()
      const nonce = randomNonce()
      cache.add(nonce, 60000)
      expect(cache.has(nonce)).toBe(true)
    })

    it('should not find a nonce that was not added', () => {
      const cache = createNonceCache()
      const nonce = randomNonce()
      expect(cache.has(nonce)).toBe(false)
    })

    it('should track size correctly', () => {
      const cache = createNonceCache()
      cache.add(randomNonce(), 60000)
      expect(cache.size).toBe(1)
      cache.add(randomNonce(), 60000)
      expect(cache.size).toBe(2)
    })
  })

  describe('markUsed (atomic CAS)', () => {
    it('should mark new nonce as used (returns true)', () => {
      const cache = createNonceCache()
      const nonce = randomNonce()
      expect(cache.markUsed(nonce)).toBe(true)
    })

    it('should reject already-used nonce (returns false)', () => {
      const cache = createNonceCache()
      const nonce = randomNonce()
      expect(cache.markUsed(nonce)).toBe(true)
      expect(cache.markUsed(nonce)).toBe(false) // Replay detected
    })

    it('should mark previously added (unused) nonce as used', () => {
      const cache = createNonceCache()
      const nonce = randomNonce()
      cache.add(nonce, 60000)
      expect(cache.markUsed(nonce)).toBe(true) // First use
      expect(cache.markUsed(nonce)).toBe(false) // Replay
    })

    it('should handle concurrent-like mark attempts', () => {
      const cache = createNonceCache()
      const nonce = randomNonce()

      // Simulate two near-simultaneous attempts
      const result1 = cache.markUsed(nonce)
      const result2 = cache.markUsed(nonce)

      // Exactly one should succeed
      expect(result1).toBe(true)
      expect(result2).toBe(false)
    })
  })

  describe('TTL expiration', () => {
    it('should expire entries after TTL', () => {
      const cache = createNonceCache()
      const nonce = randomNonce()

      // Mock Date.now to control time
      const startTime = 1000000
      vi.spyOn(Date, 'now').mockReturnValue(startTime)

      cache.add(nonce, 5000) // 5 second TTL
      expect(cache.has(nonce)).toBe(true)

      // Advance time past TTL
      vi.spyOn(Date, 'now').mockReturnValue(startTime + 5001)
      expect(cache.has(nonce)).toBe(false)
    })

    it('should allow markUsed on expired nonce (treated as new)', () => {
      const cache = createNonceCache()
      const nonce = randomNonce()

      const startTime = 1000000
      vi.spyOn(Date, 'now').mockReturnValue(startTime)

      // Add and mark as used
      expect(cache.markUsed(nonce)).toBe(true)
      expect(cache.markUsed(nonce)).toBe(false) // Replay

      // Advance time past TTL
      vi.spyOn(Date, 'now').mockReturnValue(startTime + 300001) // Past default 5 min TTL

      // Expired — should be treated as new
      expect(cache.markUsed(nonce)).toBe(true)
    })
  })

  describe('LRU eviction', () => {
    it('should evict oldest entries when at capacity', () => {
      const cache = createNonceCache({ maxEntries: 3, defaultTTLMs: 60000 })
      const nonce1 = randomNonce()
      const nonce2 = randomNonce()
      const nonce3 = randomNonce()
      const nonce4 = randomNonce()

      cache.add(nonce1, 60000)
      cache.add(nonce2, 60000)
      cache.add(nonce3, 60000)
      expect(cache.size).toBe(3)

      // Adding 4th should evict nonce1 (oldest)
      cache.add(nonce4, 60000)
      expect(cache.size).toBe(3)
      expect(cache.has(nonce1)).toBe(false) // Evicted
      expect(cache.has(nonce2)).toBe(true)
      expect(cache.has(nonce3)).toBe(true)
      expect(cache.has(nonce4)).toBe(true)
    })

    it('should respect maxEntries configuration', () => {
      const cache = createNonceCache({ maxEntries: 2, defaultTTLMs: 60000 })

      for (let i = 0; i < 10; i++) {
        cache.add(randomNonce(), 60000)
      }

      // Should never exceed maxEntries
      expect(cache.size).toBeLessThanOrEqual(2)
    })
  })

  describe('default configuration', () => {
    it('should use default max of 10000 entries', () => {
      const cache = createNonceCache()
      // Just verify it creates without error
      expect(cache.size).toBe(0)
    })

    it('should use default TTL of 5 minutes for markUsed', () => {
      const cache = createNonceCache()
      const nonce = randomNonce()

      const startTime = 1000000
      vi.spyOn(Date, 'now').mockReturnValue(startTime)

      expect(cache.markUsed(nonce)).toBe(true)

      // Still within 5 minutes
      vi.spyOn(Date, 'now').mockReturnValue(startTime + 4 * 60 * 1000)
      expect(cache.markUsed(nonce)).toBe(false) // Still used

      // Past 5 minutes
      vi.spyOn(Date, 'now').mockReturnValue(startTime + 5 * 60 * 1000 + 1)
      expect(cache.markUsed(nonce)).toBe(true) // Expired, treated as new
    })
  })
})
