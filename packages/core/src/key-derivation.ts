// @sigil-security/core — HKDF key derivation with domain separation

import type { CryptoProvider } from './crypto-provider.js'

/**
 * Domain separation for HKDF key derivation.
 *
 * Different token types derive keys from different HKDF paths,
 * closing the cross-protocol attack surface:
 *
 * - `csrf`: Regular CSRF token signing keys
 * - `oneshot`: One-shot token signing keys
 * - `internal`: Internal/service-to-service signing keys
 */
export type KeyDomain = 'csrf' | 'oneshot' | 'internal'

/** HKDF salt — fixed for all Sigil v1 key derivations */
const HKDF_SALT = 'sigil-v1'

/** Domain-specific HKDF info prefix mapping */
const DOMAIN_INFO_PREFIX: Readonly<Record<KeyDomain, string>> = {
  csrf: 'csrf-signing-key-',
  oneshot: 'oneshot-signing-key-',
  internal: 'internal-signing-key-',
}

/**
 * Derives a signing key using HKDF-SHA256 with domain separation.
 *
 * Key derivation path:
 * ```
 * HKDF(master, salt="sigil-v1", info="{domain}-signing-key-{kid}")
 * ```
 *
 * A key derived for one domain CANNOT validate tokens from another domain.
 * This closes the cross-protocol attack surface.
 *
 * @param cryptoProvider - CryptoProvider for HKDF operations
 * @param master - Master secret as raw bytes
 * @param kid - Key identifier (8-bit)
 * @param domain - Key domain for separation (csrf/oneshot/internal)
 * @returns Derived HMAC-SHA256 CryptoKey
 */
export async function deriveSigningKey(
  cryptoProvider: CryptoProvider,
  master: ArrayBuffer,
  kid: number,
  domain: KeyDomain,
): Promise<CryptoKey> {
  const info = `${DOMAIN_INFO_PREFIX[domain]}${String(kid)}`
  return cryptoProvider.deriveKey(master, HKDF_SALT, info)
}
