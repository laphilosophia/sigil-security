// @sigil-security/core — CryptoProvider abstraction

/**
 * CryptoProvider abstraction for all cryptographic operations.
 *
 * All crypto operations in sigil-core go through this interface —
 * never call `crypto.subtle` directly from token/validation code.
 *
 * Default implementation: WebCryptoCryptoProvider (ships with core, zero deps).
 * Extension point for KMS/HSM/Node native — documented, not built until needed.
 */
export interface CryptoProvider {
  /**
   * Signs data with HMAC-SHA256.
   * Returns the full 256-bit MAC (NO truncation).
   */
  sign(key: CryptoKey, data: Uint8Array): Promise<ArrayBuffer>

  /**
   * Verifies an HMAC-SHA256 signature.
   * MUST be constant-time (crypto.subtle.verify is inherently constant-time).
   */
  verify(key: CryptoKey, signature: ArrayBuffer, data: Uint8Array): Promise<boolean>

  /**
   * Derives an HMAC signing key from a master secret using HKDF-SHA256.
   *
   * @param master - Master secret as raw bytes
   * @param salt - HKDF salt string (e.g., "sigil-v1")
   * @param info - HKDF info string with domain separation (e.g., "csrf-signing-key-1")
   */
  deriveKey(master: ArrayBuffer, salt: string, info: string): Promise<CryptoKey>

  /**
   * Generates cryptographically secure random bytes.
   * Uses crypto.getRandomValues (NOT Math.random).
   */
  randomBytes(length: number): Uint8Array

  /**
   * Computes SHA-256 hash of the input data.
   * Returns the full 256-bit (32-byte) digest.
   */
  hash(data: Uint8Array): Promise<ArrayBuffer>
}
