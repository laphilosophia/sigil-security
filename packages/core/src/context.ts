// @sigil-security/core — Context binding (always 32 bytes)

import type { CryptoProvider } from './crypto-provider.js'

/** Zero byte used for empty context hashing */
const ZERO_BYTE = new Uint8Array([0x00])

/**
 * Computes context binding hash from string bindings.
 *
 * Context is ALWAYS 32 bytes (SHA-256 output) — eliminates length oracle.
 *
 * - If bindings provided: `SHA-256(binding1 + binding2 + ...)`
 * - If no bindings: `SHA-256(0x00)` — zero-padded, NEVER empty
 *
 * @param cryptoProvider - CryptoProvider for hashing
 * @param bindings - Strings to bind into context (e.g., sessionId, userId, origin)
 * @returns 32-byte context hash
 */
export async function computeContext(
  cryptoProvider: CryptoProvider,
  ...bindings: string[]
): Promise<Uint8Array> {
  if (bindings.length === 0) {
    return emptyContext(cryptoProvider)
  }

  const encoder = new TextEncoder()
  const concatenated = bindings.join('')
  const data = encoder.encode(concatenated)
  const hash = await cryptoProvider.hash(data)
  return new Uint8Array(hash)
}

/**
 * Returns the empty context value: SHA-256(0x00).
 *
 * Used when no context binding is specified.
 * Always returns exactly 32 bytes — never an empty buffer.
 *
 * @param cryptoProvider - CryptoProvider for hashing
 * @returns 32-byte empty context hash
 */
export async function emptyContext(cryptoProvider: CryptoProvider): Promise<Uint8Array> {
  const hash = await cryptoProvider.hash(ZERO_BYTE)
  return new Uint8Array(hash)
}
