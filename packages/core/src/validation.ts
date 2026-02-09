// @sigil-security/core — Deterministic failure model, constant-time token validation

import type { CryptoProvider } from './crypto-provider.js'
import type { Keyring } from './key-manager.js'
import { resolveKey } from './key-manager.js'
import type { ValidationResult } from './types.js'
import {
  CONTEXT_SIZE,
  DEFAULT_GRACE_WINDOW_MS,
  DEFAULT_TOKEN_TTL_MS,
  KID_SIZE,
  NONCE_SIZE,
  TIMESTAMP_SIZE,
} from './types.js'
import { toArrayBuffer } from './encoding.js'
import { assemblePayload, parseToken } from './token.js'

/**
 * Dummy payload for constant-time HMAC computation when earlier steps failed.
 * Same size as real payload to preserve timing characteristics.
 */
const DUMMY_PAYLOAD = new Uint8Array(KID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE + CONTEXT_SIZE)

/**
 * Dummy MAC (32 bytes of zeros) for constant-time verify when key resolution failed.
 */
const DUMMY_MAC = new ArrayBuffer(32)

/**
 * Validates a CSRF token using the Deterministic Failure Model.
 *
 * **CRITICAL (spec Section 5.8):**
 * ALL validation steps MUST complete. No early return. Single exit point.
 * Timing is deterministic regardless of which step fails.
 *
 * Steps:
 * 1. Parse token (constant-time length check)
 * 2. Resolve key from keyring (match by kid)
 * 3. TTL check (within TTL or grace window)
 * 4. HMAC verify (constant-time via crypto.subtle.verify) — runs even if earlier steps failed
 * 5. Context check (if expected context provided)
 *
 * `reason` captures the LAST failure (internal logging only).
 * Client receives ONLY `{ valid: false, reason: "CSRF validation failed" }`.
 *
 * @param cryptoProvider - CryptoProvider for HMAC verification
 * @param keyring - Keyring to resolve keys from
 * @param tokenString - The token string to validate
 * @param expectedContext - Optional expected 32-byte context hash
 * @param ttlMs - Token TTL in milliseconds (default: 20 minutes)
 * @param graceWindowMs - Grace window in milliseconds (default: 60 seconds)
 * @param now - Current timestamp override for testing
 */
export async function validateToken(
  cryptoProvider: CryptoProvider,
  keyring: Keyring,
  tokenString: string,
  expectedContext?: Uint8Array,
  ttlMs: number = DEFAULT_TOKEN_TTL_MS,
  graceWindowMs: number = DEFAULT_GRACE_WINDOW_MS,
  now: number = Date.now(),
): Promise<ValidationResult> {
  let valid = true
  let reason = 'unknown'

  // Step 1: Parse (constant-time length check)
  const parsed = parseToken(tokenString)
  const parseOk = parsed !== null
  valid &&= parseOk
  if (!parseOk) reason = 'parse_failed'

  // Step 2: Resolve key (try all keys in keyring by kid)
  const key = parseOk ? resolveKey(keyring, parsed.kid) : undefined
  const keyOk = key !== undefined
  valid &&= keyOk
  if (!keyOk) reason = 'unknown_kid'

  // Step 3: TTL check
  const ttlResult = parseOk
    ? validateTTL(parsed.timestamp, ttlMs, graceWindowMs, now)
    : { withinTTL: false, inGraceWindow: false }
  const ttlOk = ttlResult.withinTTL || ttlResult.inGraceWindow
  valid &&= ttlOk
  if (!ttlOk) reason = 'expired'

  // Step 4: HMAC verify (constant-time via crypto.subtle.verify)
  // MUST run even if earlier steps failed (deterministic timing)
  const macPayload = parseOk ? assemblePayload(parsed) : DUMMY_PAYLOAD
  const macSignature = parseOk ? toArrayBuffer(parsed.mac) : DUMMY_MAC

  // Always perform HMAC verify — even when key resolution failed.
  // Using a fallback key from the keyring ensures identical timing profile
  // regardless of whether kid matched. Without this, an attacker could
  // enumerate active kid values by timing the response (~30µs difference).
  const verifyKey = keyOk ? key.cryptoKey : keyring.keys[0]?.cryptoKey
  let macOk: boolean
  if (verifyKey !== undefined) {
    const actualResult = await cryptoProvider.verify(verifyKey, macSignature, macPayload)
    // Only trust the result if we used the correct (kid-matched) key
    macOk = keyOk ? actualResult : false
  } else {
    // Keyring is empty (should never happen by construction) — fail closed
    macOk = false
  }
  valid &&= macOk
  if (!macOk) reason = 'invalid_mac'

  // Step 5: Context check
  let contextOk = true
  if (expectedContext !== undefined) {
    contextOk = parseOk ? constantTimeEqual(parsed.context, expectedContext) : false
  }
  valid &&= contextOk
  if (!contextOk) reason = 'context_mismatch'

  // Single exit point — deterministic
  return valid ? { valid: true } : { valid: false, reason }
}

/**
 * Validates token TTL against the current time.
 *
 * @param tokenTimestamp - Token creation timestamp (milliseconds)
 * @param ttlMs - Token TTL in milliseconds
 * @param graceWindowMs - Grace window after TTL (for in-flight requests)
 * @param now - Current timestamp
 * @returns Whether the token is within TTL or within the grace window
 */
export function validateTTL(
  tokenTimestamp: number,
  ttlMs: number,
  graceWindowMs: number,
  now: number,
): { withinTTL: boolean; inGraceWindow: boolean } {
  const age = now - tokenTimestamp
  const withinTTL = age >= 0 && age <= ttlMs
  const inGraceWindow = !withinTTL && age > ttlMs && age <= ttlMs + graceWindowMs
  return { withinTTL, inGraceWindow }
}

/**
 * Constant-time buffer comparison.
 *
 * Compares all bytes regardless of where a mismatch occurs.
 * Length difference is also detected without early return.
 *
 * @param a - First buffer
 * @param b - Second buffer
 * @returns true if buffers are identical, false otherwise
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  const length = Math.max(a.length, b.length)
  let result = a.length ^ b.length // Non-zero if lengths differ
  for (let i = 0; i < length; i++) {
    result |= (a[i] ?? 0) ^ (b[i] ?? 0)
  }
  return result === 0
}
