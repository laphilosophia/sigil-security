// @sigil-security/core — WebCrypto-based CryptoProvider implementation

import type { CryptoProvider } from './crypto-provider.js'
import { toBase64Url } from './encoding.js'

/**
 * Default CryptoProvider implementation using the WebCrypto API.
 *
 * - HMAC-SHA256 for sign/verify (full 256-bit, NO truncation)
 * - HKDF-SHA256 for key derivation (RFC 5869)
 * - crypto.getRandomValues for secure randomness
 * - SHA-256 for hashing
 *
 * Zero external dependencies. Works in Node 18+, Bun, Deno, and Edge runtimes.
 */
export class WebCryptoCryptoProvider implements CryptoProvider {
  private readonly encoder = new TextEncoder()

  private readonly hkdfBaseKeyCache = new Map<string, Promise<CryptoKey>>()

  private readonly hkdfDerivedKeyCache = new Map<string, Map<string, Map<string, Promise<CryptoKey>>>>()

  private readonly encodedStringCache = new Map<string, BufferSource>()

  private getEncodedString(value: string): BufferSource {
    const cached = this.encodedStringCache.get(value)
    if (cached !== undefined) {
      return cached
    }

    const encoded = this.encoder.encode(value)
    this.encodedStringCache.set(value, encoded)
    return encoded
  }

  private getMasterCacheKey(master: ArrayBuffer): string {
    return toBase64Url(new Uint8Array(master))
  }

  private getHkdfBaseKey(masterKey: string, master: ArrayBuffer): Promise<CryptoKey> {
    const cached = this.hkdfBaseKeyCache.get(masterKey)
    if (cached !== undefined) {
      return cached
    }

    const importedKey = globalThis.crypto.subtle
      .importKey('raw', master, { name: 'HKDF' }, false, ['deriveKey'])
      .catch((error: unknown) => {
        this.hkdfBaseKeyCache.delete(masterKey)
        throw error
      })

    this.hkdfBaseKeyCache.set(masterKey, importedKey)
    return importedKey
  }

  private getDerivedKeyCache(
    masterKey: string,
    salt: string,
  ): Map<string, Promise<CryptoKey>> {
    let masterCache = this.hkdfDerivedKeyCache.get(masterKey)
    if (masterCache === undefined) {
      masterCache = new Map<string, Map<string, Promise<CryptoKey>>>()
      this.hkdfDerivedKeyCache.set(masterKey, masterCache)
    }

    let saltCache = masterCache.get(salt)
    if (saltCache === undefined) {
      saltCache = new Map<string, Promise<CryptoKey>>()
      masterCache.set(salt, saltCache)
    }

    return saltCache
  }

  /**
   * Signs data with HMAC-SHA256 using WebCrypto.
   * Returns full 256-bit (32-byte) MAC, NO truncation.
   */
  async sign(key: CryptoKey, data: Uint8Array): Promise<ArrayBuffer> {
    return globalThis.crypto.subtle.sign('HMAC', key, data as Uint8Array<ArrayBuffer>)
  }

  /**
   * Verifies an HMAC-SHA256 signature using WebCrypto.
   * Inherently constant-time via crypto.subtle.verify.
   */
  async verify(key: CryptoKey, signature: ArrayBuffer, data: Uint8Array): Promise<boolean> {
    return globalThis.crypto.subtle.verify('HMAC', key, signature, data as Uint8Array<ArrayBuffer>)
  }

  /**
   * Derives an HMAC-SHA256 signing key from a master secret via HKDF-SHA256.
   *
   * HKDF (RFC 5869) with:
   * - Hash: SHA-256
   * - Salt: encoded string
   * - Info: encoded string (includes domain separation)
   * - Output: HMAC-SHA256 key, 256-bit, non-extractable
   */
  async deriveKey(master: ArrayBuffer, salt: string, info: string): Promise<CryptoKey> {
    const masterKey = this.getMasterCacheKey(master)
    const derivedKeyCache = this.getDerivedKeyCache(masterKey, salt)
    const cached = derivedKeyCache.get(info)
    if (cached !== undefined) {
      return cached
    }

    const baseKey = await this.getHkdfBaseKey(masterKey, master)

    const derivedKey = globalThis.crypto.subtle
      .deriveKey(
        {
          name: 'HKDF',
          hash: 'SHA-256',
          salt: this.getEncodedString(salt),
          info: this.getEncodedString(info),
        },
        baseKey,
        { name: 'HMAC', hash: 'SHA-256', length: 256 },
        false,
        ['sign', 'verify'],
      )
      .catch((error: unknown) => {
        derivedKeyCache.delete(info)
        throw error
      })

    derivedKeyCache.set(info, derivedKey)
    return derivedKey
  }

  /**
   * Generates cryptographically secure random bytes via crypto.getRandomValues.
   * NEVER uses Math.random.
   */
  randomBytes(length: number): Uint8Array {
    const buffer = new Uint8Array(length)
    globalThis.crypto.getRandomValues(buffer)
    return buffer
  }

  /**
   * Computes SHA-256 hash via WebCrypto.
   * Returns full 256-bit (32-byte) digest.
   */
  async hash(data: Uint8Array): Promise<ArrayBuffer> {
    return globalThis.crypto.subtle.digest('SHA-256', data as Uint8Array<ArrayBuffer>)
  }
}
