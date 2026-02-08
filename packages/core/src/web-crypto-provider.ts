// @sigil-security/core — WebCrypto-based CryptoProvider implementation

import type { CryptoProvider } from './crypto-provider.js'

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
  /**
   * Signs data with HMAC-SHA256 using WebCrypto.
   * Returns full 256-bit (32-byte) MAC, NO truncation.
   */
  async sign(key: CryptoKey, data: Uint8Array): Promise<ArrayBuffer> {
    return crypto.subtle.sign('HMAC', key, data as Uint8Array<ArrayBuffer>)
  }

  /**
   * Verifies an HMAC-SHA256 signature using WebCrypto.
   * Inherently constant-time via crypto.subtle.verify.
   */
  async verify(key: CryptoKey, signature: ArrayBuffer, data: Uint8Array): Promise<boolean> {
    return crypto.subtle.verify('HMAC', key, signature, data as Uint8Array<ArrayBuffer>)
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
    const encoder = new TextEncoder()

    // Import master as raw key material for HKDF
    const baseKey = await crypto.subtle.importKey('raw', master, { name: 'HKDF' }, false, [
      'deriveKey',
    ])

    // Derive HMAC-SHA256 signing key via HKDF
    return crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: encoder.encode(salt),
        info: encoder.encode(info),
      },
      baseKey,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      false,
      ['sign', 'verify'],
    )
  }

  /**
   * Generates cryptographically secure random bytes via crypto.getRandomValues.
   * NEVER uses Math.random.
   */
  randomBytes(length: number): Uint8Array {
    const buffer = new Uint8Array(length)
    crypto.getRandomValues(buffer)
    return buffer
  }

  /**
   * Computes SHA-256 hash via WebCrypto.
   * Returns full 256-bit (32-byte) digest.
   */
  async hash(data: Uint8Array): Promise<ArrayBuffer> {
    return crypto.subtle.digest('SHA-256', data as Uint8Array<ArrayBuffer>)
  }
}
