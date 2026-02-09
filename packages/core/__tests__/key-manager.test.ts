import { describe, it, expect } from 'vitest'
import { WebCryptoCryptoProvider } from '../src/web-crypto-provider.js'
import {
  createKeyring,
  rotateKey,
  resolveKey,
  getActiveKey,
} from '../src/key-manager.js'

describe('key-manager', () => {
  const provider = new WebCryptoCryptoProvider()
  const masterSecret = crypto.getRandomValues(new Uint8Array(32)).buffer

  describe('createKeyring', () => {
    it('should create a keyring with one key', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      expect(keyring.keys).toHaveLength(1)
      expect(keyring.activeKid).toBe(1)
      expect(keyring.domain).toBe('csrf')
    })

    it('should create a key with correct kid', async () => {
      const keyring = await createKeyring(provider, masterSecret, 42, 'csrf')
      expect(keyring.keys[0]!.kid).toBe(42)
      expect(keyring.keys[0]!.cryptoKey).toBeDefined()
      expect(keyring.keys[0]!.createdAt).toBeGreaterThan(0)
    })

    it('should create domain-separated keyrings', async () => {
      const csrfKeyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const oneshotKeyring = await createKeyring(provider, masterSecret, 1, 'oneshot')

      // Same kid + master but different domains should produce different keys
      const data = new Uint8Array([1, 2, 3])
      const mac1 = await provider.sign(csrfKeyring.keys[0]!.cryptoKey, data)
      const mac2 = await provider.sign(oneshotKeyring.keys[0]!.cryptoKey, data)
      expect(new Uint8Array(mac1)).not.toEqual(new Uint8Array(mac2))
    })
  })

  describe('rotateKey', () => {
    it('should add new key as active', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const rotated = await rotateKey(keyring, provider, masterSecret, 2)

      expect(rotated.activeKid).toBe(2)
      expect(rotated.keys).toHaveLength(2)
      expect(rotated.keys[0]!.kid).toBe(2) // New key is first
      expect(rotated.keys[1]!.kid).toBe(1) // Old key is second
    })

    it('should keep max 3 keys', async () => {
      let keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      keyring = await rotateKey(keyring, provider, masterSecret, 2)
      keyring = await rotateKey(keyring, provider, masterSecret, 3)
      expect(keyring.keys).toHaveLength(3)

      // Fourth rotation should evict oldest
      keyring = await rotateKey(keyring, provider, masterSecret, 4)
      expect(keyring.keys).toHaveLength(3)
      expect(keyring.activeKid).toBe(4)

      // kid=1 should be evicted
      expect(resolveKey(keyring, 1)).toBeUndefined()
      // kid=2, 3, 4 should exist
      expect(resolveKey(keyring, 2)).toBeDefined()
      expect(resolveKey(keyring, 3)).toBeDefined()
      expect(resolveKey(keyring, 4)).toBeDefined()
    })

    it('should preserve domain across rotations', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'oneshot')
      const rotated = await rotateKey(keyring, provider, masterSecret, 2)
      expect(rotated.domain).toBe('oneshot')
    })
  })

  describe('resolveKey', () => {
    it('should find key by kid', async () => {
      let keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      keyring = await rotateKey(keyring, provider, masterSecret, 2)

      const key1 = resolveKey(keyring, 1)
      expect(key1).toBeDefined()
      expect(key1!.kid).toBe(1)

      const key2 = resolveKey(keyring, 2)
      expect(key2).toBeDefined()
      expect(key2!.kid).toBe(2)
    })

    it('should return undefined for unknown kid', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      expect(resolveKey(keyring, 99)).toBeUndefined()
    })
  })

  describe('getActiveKey', () => {
    it('should return the active key', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const active = getActiveKey(keyring)
      expect(active).toBeDefined()
      expect(active!.kid).toBe(1)
    })

    it('should return rotated active key', async () => {
      let keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      keyring = await rotateKey(keyring, provider, masterSecret, 2)

      const active = getActiveKey(keyring)
      expect(active).toBeDefined()
      expect(active!.kid).toBe(2)
    })
  })

  describe('kid range validation (L4 fix)', () => {
    it('should accept kid=0 (minimum)', async () => {
      const keyring = await createKeyring(provider, masterSecret, 0, 'csrf')
      expect(keyring.keys[0]!.kid).toBe(0)
    })

    it('should accept kid=255 (maximum)', async () => {
      const keyring = await createKeyring(provider, masterSecret, 255, 'csrf')
      expect(keyring.keys[0]!.kid).toBe(255)
    })

    it('should reject kid=256 (overflow)', async () => {
      await expect(
        createKeyring(provider, masterSecret, 256, 'csrf'),
      ).rejects.toThrow(RangeError)
    })

    it('should reject kid=-1 (underflow)', async () => {
      await expect(
        createKeyring(provider, masterSecret, -1, 'csrf'),
      ).rejects.toThrow(RangeError)
    })

    it('should reject non-integer kid', async () => {
      await expect(
        createKeyring(provider, masterSecret, 1.5, 'csrf'),
      ).rejects.toThrow(RangeError)
    })

    it('should reject NaN kid', async () => {
      await expect(
        createKeyring(provider, masterSecret, NaN, 'csrf'),
      ).rejects.toThrow(RangeError)
    })

    it('should reject kid overflow in rotateKey', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      await expect(
        rotateKey(keyring, provider, masterSecret, 256),
      ).rejects.toThrow(RangeError)
    })

    it('should reject negative kid in rotateKey', async () => {
      const keyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      await expect(
        rotateKey(keyring, provider, masterSecret, -1),
      ).rejects.toThrow(RangeError)
    })
  })

  describe('cross-domain key isolation', () => {
    it('should not validate across domains', async () => {
      const csrfKeyring = await createKeyring(provider, masterSecret, 1, 'csrf')
      const oneshotKeyring = await createKeyring(provider, masterSecret, 1, 'oneshot')

      const data = new Uint8Array([1, 2, 3, 4, 5])
      const csrfKey = getActiveKey(csrfKeyring)!
      const oneshotKey = getActiveKey(oneshotKeyring)!

      // Sign with csrf key
      const mac = await provider.sign(csrfKey.cryptoKey, data)

      // Verify with oneshot key should fail
      const valid = await provider.verify(oneshotKey.cryptoKey, mac, data)
      expect(valid).toBe(false)

      // Verify with csrf key should succeed
      const validSelf = await provider.verify(csrfKey.cryptoKey, mac, data)
      expect(validSelf).toBe(true)
    })
  })
})
