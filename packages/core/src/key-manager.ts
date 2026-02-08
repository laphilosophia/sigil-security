// @sigil-security/core — Keyring management (max 3 keys, rotation, resolve)

import type { CryptoProvider } from './crypto-provider.js'
import { type KeyDomain, deriveSigningKey } from './key-derivation.js'

/** Maximum number of keys in a keyring (active + 2 previous) */
const MAX_KEYS = 3

/**
 * A single key entry in the keyring.
 */
export interface KeyEntry {
  /** Key identifier (8-bit, embedded in token) */
  readonly kid: number
  /** Derived HMAC-SHA256 CryptoKey */
  readonly cryptoKey: CryptoKey
  /** Timestamp when this key was created */
  readonly createdAt: number
}

/**
 * Keyring holds max 3 keys (active + 2 previous) per domain.
 *
 * - Token generation: ALWAYS uses the active key
 * - Token validation: tries ALL keys in the keyring (match by kid from token)
 * - Rotation: new key becomes active, oldest dropped if > MAX_KEYS
 */
export interface Keyring {
  /** All keys in the keyring, ordered newest-first */
  readonly keys: readonly KeyEntry[]
  /** The kid of the currently active key */
  readonly activeKid: number
  /** The domain this keyring belongs to */
  readonly domain: KeyDomain
}

/**
 * Creates a new keyring with an initial key.
 *
 * @param cryptoProvider - CryptoProvider for key derivation
 * @param masterSecret - Master secret as raw bytes
 * @param initialKid - Initial key identifier (8-bit)
 * @param domain - Key domain for HKDF separation
 * @returns A new Keyring with one key
 */
export async function createKeyring(
  cryptoProvider: CryptoProvider,
  masterSecret: ArrayBuffer,
  initialKid: number,
  domain: KeyDomain,
): Promise<Keyring> {
  const cryptoKey = await deriveSigningKey(cryptoProvider, masterSecret, initialKid, domain)
  const entry: KeyEntry = {
    kid: initialKid,
    cryptoKey,
    createdAt: Date.now(),
  }
  return {
    keys: [entry],
    activeKid: initialKid,
    domain,
  }
}

/**
 * Rotates the keyring: new key becomes active, oldest dropped if > MAX_KEYS.
 *
 * @param keyring - Current keyring to rotate
 * @param cryptoProvider - CryptoProvider for key derivation
 * @param masterSecret - Master secret as raw bytes
 * @param newKid - New key identifier (must be unique in keyring)
 * @returns Updated Keyring with the new active key
 */
export async function rotateKey(
  keyring: Keyring,
  cryptoProvider: CryptoProvider,
  masterSecret: ArrayBuffer,
  newKid: number,
): Promise<Keyring> {
  const cryptoKey = await deriveSigningKey(
    cryptoProvider,
    masterSecret,
    newKid,
    keyring.domain,
  )
  const entry: KeyEntry = {
    kid: newKid,
    cryptoKey,
    createdAt: Date.now(),
  }

  // New key at front, trim to MAX_KEYS
  const keys = [entry, ...keyring.keys].slice(0, MAX_KEYS)
  return {
    keys,
    activeKid: newKid,
    domain: keyring.domain,
  }
}

/**
 * Resolves a key by kid from the keyring.
 * Returns undefined if no matching key is found.
 *
 * Token validation tries ALL keys to support key rotation overlap.
 */
export function resolveKey(keyring: Keyring, kid: number): KeyEntry | undefined {
  return keyring.keys.find((k) => k.kid === kid)
}

/**
 * Returns the active key entry from the keyring.
 * Token generation ALWAYS uses the active key.
 */
export function getActiveKey(keyring: Keyring): KeyEntry | undefined {
  return resolveKey(keyring, keyring.activeKid)
}
