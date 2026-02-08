import { describe, it, expect } from 'vitest'
import { WebCryptoCryptoProvider } from '../src/web-crypto-provider.js'

describe('WebCryptoCryptoProvider', () => {
  const provider = new WebCryptoCryptoProvider()

  describe('randomBytes', () => {
    it('should return buffer of requested length', () => {
      const bytes = provider.randomBytes(16)
      expect(bytes).toBeInstanceOf(Uint8Array)
      expect(bytes.length).toBe(16)
    })

    it('should return different values on each call', () => {
      const a = provider.randomBytes(16)
      const b = provider.randomBytes(16)
      // Extremely unlikely to be equal
      expect(a).not.toEqual(b)
    })

    it('should return buffer of any requested length', () => {
      expect(provider.randomBytes(0).length).toBe(0)
      expect(provider.randomBytes(1).length).toBe(1)
      expect(provider.randomBytes(32).length).toBe(32)
      expect(provider.randomBytes(64).length).toBe(64)
    })
  })

  describe('hash (SHA-256)', () => {
    it('should produce 32-byte hash', async () => {
      const data = new TextEncoder().encode('hello')
      const hash = await provider.hash(data)
      expect(hash.byteLength).toBe(32)
    })

    it('should produce consistent hashes', async () => {
      const data = new TextEncoder().encode('hello')
      const hash1 = await provider.hash(data)
      const hash2 = await provider.hash(data)
      expect(new Uint8Array(hash1)).toEqual(new Uint8Array(hash2))
    })

    it('should produce different hashes for different inputs', async () => {
      const hash1 = await provider.hash(new TextEncoder().encode('hello'))
      const hash2 = await provider.hash(new TextEncoder().encode('world'))
      expect(new Uint8Array(hash1)).not.toEqual(new Uint8Array(hash2))
    })

    it('should hash empty input', async () => {
      const hash = await provider.hash(new Uint8Array(0))
      expect(hash.byteLength).toBe(32)
    })

    it('should produce known SHA-256 hash for "hello"', async () => {
      const data = new TextEncoder().encode('hello')
      const hash = await provider.hash(data)
      const hex = Array.from(new Uint8Array(hash))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
      // Known SHA-256 of "hello"
      expect(hex).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824')
    })
  })

  describe('deriveKey (HKDF-SHA256)', () => {
    it('should derive a CryptoKey', async () => {
      const master = crypto.getRandomValues(new Uint8Array(32)).buffer
      const key = await provider.deriveKey(master, 'sigil-v1', 'csrf-signing-key-1')
      expect(key).toBeDefined()
      expect(key.type).toBe('secret')
      expect(key.algorithm).toMatchObject({ name: 'HMAC' })
    })

    it('should derive different keys for different info strings', async () => {
      const master = crypto.getRandomValues(new Uint8Array(32)).buffer
      const key1 = await provider.deriveKey(master, 'sigil-v1', 'csrf-signing-key-1')
      const key2 = await provider.deriveKey(master, 'sigil-v1', 'csrf-signing-key-2')

      // Sign the same data with both keys — should produce different MACs
      const data = new Uint8Array([1, 2, 3, 4])
      const mac1 = await provider.sign(key1, data)
      const mac2 = await provider.sign(key2, data)
      expect(new Uint8Array(mac1)).not.toEqual(new Uint8Array(mac2))
    })

    it('should derive different keys for different salts', async () => {
      const master = crypto.getRandomValues(new Uint8Array(32)).buffer
      const key1 = await provider.deriveKey(master, 'salt-1', 'info')
      const key2 = await provider.deriveKey(master, 'salt-2', 'info')

      const data = new Uint8Array([1, 2, 3, 4])
      const mac1 = await provider.sign(key1, data)
      const mac2 = await provider.sign(key2, data)
      expect(new Uint8Array(mac1)).not.toEqual(new Uint8Array(mac2))
    })

    it('should derive different keys for different masters', async () => {
      const master1 = crypto.getRandomValues(new Uint8Array(32)).buffer
      const master2 = crypto.getRandomValues(new Uint8Array(32)).buffer
      const key1 = await provider.deriveKey(master1, 'sigil-v1', 'csrf-signing-key-1')
      const key2 = await provider.deriveKey(master2, 'sigil-v1', 'csrf-signing-key-1')

      const data = new Uint8Array([1, 2, 3, 4])
      const mac1 = await provider.sign(key1, data)
      const mac2 = await provider.sign(key2, data)
      expect(new Uint8Array(mac1)).not.toEqual(new Uint8Array(mac2))
    })

    it('should derive deterministic keys (same input = same output)', async () => {
      const masterBytes = crypto.getRandomValues(new Uint8Array(32))
      const key1 = await provider.deriveKey(masterBytes.buffer.slice(0), 'sigil-v1', 'info')
      const key2 = await provider.deriveKey(masterBytes.buffer.slice(0), 'sigil-v1', 'info')

      const data = new Uint8Array([1, 2, 3, 4])
      const mac1 = await provider.sign(key1, data)
      const mac2 = await provider.sign(key2, data)
      expect(new Uint8Array(mac1)).toEqual(new Uint8Array(mac2))
    })
  })

  describe('sign / verify (HMAC-SHA256)', () => {
    it('should sign and verify successfully', async () => {
      const master = crypto.getRandomValues(new Uint8Array(32)).buffer
      const key = await provider.deriveKey(master, 'sigil-v1', 'test-key')
      const data = new Uint8Array([1, 2, 3, 4, 5])

      const mac = await provider.sign(key, data)
      expect(mac.byteLength).toBe(32) // Full 256-bit, NO truncation

      const valid = await provider.verify(key, mac, data)
      expect(valid).toBe(true)
    })

    it('should reject tampered data', async () => {
      const master = crypto.getRandomValues(new Uint8Array(32)).buffer
      const key = await provider.deriveKey(master, 'sigil-v1', 'test-key')
      const data = new Uint8Array([1, 2, 3, 4, 5])

      const mac = await provider.sign(key, data)

      // Tamper with data
      const tampered = new Uint8Array([1, 2, 3, 4, 6])
      const valid = await provider.verify(key, mac, tampered)
      expect(valid).toBe(false)
    })

    it('should reject tampered MAC', async () => {
      const master = crypto.getRandomValues(new Uint8Array(32)).buffer
      const key = await provider.deriveKey(master, 'sigil-v1', 'test-key')
      const data = new Uint8Array([1, 2, 3, 4, 5])

      const mac = await provider.sign(key, data)
      const tamperedMac = new ArrayBuffer(32)
      const tamperedView = new Uint8Array(tamperedMac)
      tamperedView.set(new Uint8Array(mac))
      tamperedView[0] = (tamperedView[0] ?? 0) ^ 0xff // Flip bits

      const valid = await provider.verify(key, tamperedMac, data)
      expect(valid).toBe(false)
    })

    it('should reject wrong key', async () => {
      const master = crypto.getRandomValues(new Uint8Array(32)).buffer
      const key1 = await provider.deriveKey(master, 'sigil-v1', 'key-1')
      const key2 = await provider.deriveKey(master, 'sigil-v1', 'key-2')
      const data = new Uint8Array([1, 2, 3, 4, 5])

      const mac = await provider.sign(key1, data)
      const valid = await provider.verify(key2, mac, data)
      expect(valid).toBe(false)
    })

    it('should produce 32-byte MAC (full 256-bit, no truncation)', async () => {
      const master = crypto.getRandomValues(new Uint8Array(32)).buffer
      const key = await provider.deriveKey(master, 'sigil-v1', 'test-key')
      const mac = await provider.sign(key, new Uint8Array([1]))
      expect(mac.byteLength).toBe(32)
    })
  })
})
