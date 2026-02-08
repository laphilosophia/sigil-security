// @sigil-security/core — One-shot token generation, parsing, validation (120 bytes fixed)

import type { CryptoProvider } from './crypto-provider.js'
import type { KeyEntry } from './key-manager.js'
import type { NonceCache } from './nonce-cache.js'
import type {
  OneShotGenerationResult,
  OneShotTokenString,
  ParsedOneShotToken,
  ValidationResult,
} from './types.js'
import {
  ACTION_SIZE,
  CONTEXT_SIZE,
  DEFAULT_ONESHOT_TTL_MS,
  MAC_SIZE,
  NONCE_SIZE,
  ONESHOT_OFFSETS,
  ONESHOT_RAW_SIZE,
  TIMESTAMP_SIZE,
} from './types.js'
import { fromBase64Url, readUint64BE, toArrayBuffer, toBase64Url, writeUint64BE } from './encoding.js'
import { emptyContext } from './context.js'
import { constantTimeEqual, validateTTL } from './validation.js'

/**
 * Size of the one-shot payload (everything except the MAC).
 * nonce(16) + ts(8) + action(32) + ctx(32) = 88 bytes
 */
const ONESHOT_PAYLOAD_SIZE = NONCE_SIZE + TIMESTAMP_SIZE + ACTION_SIZE + CONTEXT_SIZE

/** Dummy payload for constant-time HMAC when earlier steps failed */
const DUMMY_ONESHOT_PAYLOAD = new Uint8Array(ONESHOT_PAYLOAD_SIZE)

/** Dummy MAC (32 bytes) for constant-time operations */
const DUMMY_MAC = new ArrayBuffer(32)

/**
 * Computes the action binding hash: SHA-256(actionString).
 *
 * Example: SHA-256("POST:/api/account/delete") → 32 bytes.
 * Token is bound to a specific action — cross-action replay is impossible.
 */
export async function computeAction(
  cryptoProvider: CryptoProvider,
  action: string,
): Promise<Uint8Array> {
  const encoder = new TextEncoder()
  const data = encoder.encode(action)
  const hash = await cryptoProvider.hash(data)
  return new Uint8Array(hash)
}

/**
 * Generates a one-shot token.
 *
 * One-shot tokens are:
 * - Bound to a specific action (e.g., "POST:/api/account/delete")
 * - Used exactly once (replay protection via nonce cache)
 * - Signed with a domain-separated key (oneshot HKDF path)
 *
 * Wire format: 120 bytes raw → base64url encoded
 * ```
 * [ nonce:16 ][ ts:8 ][ action:32 ][ ctx:32 ][ mac:32 ]
 * ```
 *
 * @param cryptoProvider - CryptoProvider for crypto operations
 * @param key - KeyEntry derived with 'oneshot' domain
 * @param action - Action string to bind (e.g., "POST:/api/account/delete")
 * @param context - Optional 32-byte context binding hash
 * @param ttlMs - Token TTL in milliseconds (default: 5 minutes)
 * @param now - Current timestamp override for testing
 */
export async function generateOneShotToken(
  cryptoProvider: CryptoProvider,
  key: KeyEntry,
  action: string,
  context?: Uint8Array,
  ttlMs: number = DEFAULT_ONESHOT_TTL_MS,
  now: number = Date.now(),
): Promise<OneShotGenerationResult> {
  try {
    // 1. Generate 128-bit nonce
    const nonce = cryptoProvider.randomBytes(NONCE_SIZE)

    // 2. Timestamp
    const ts = now

    // 3. Action hash (SHA-256 of action string, always 32 bytes)
    const actionHash = await computeAction(cryptoProvider, action)

    // 4. Context (always 32 bytes — zero-pad if not provided)
    const ctx = context ?? (await emptyContext(cryptoProvider))

    // 5. Assemble payload: nonce | ts | action | ctx
    const payload = new Uint8Array(ONESHOT_PAYLOAD_SIZE)
    payload.set(nonce, 0)
    writeUint64BE(payload, ts, NONCE_SIZE)
    payload.set(actionHash, NONCE_SIZE + TIMESTAMP_SIZE)
    payload.set(ctx, NONCE_SIZE + TIMESTAMP_SIZE + ACTION_SIZE)

    // 6. Sign with HMAC-SHA256
    const macBuffer = await cryptoProvider.sign(key.cryptoKey, payload)
    const mac = new Uint8Array(macBuffer)

    // 7. Assemble full token: payload | mac
    const tokenRaw = new Uint8Array(ONESHOT_RAW_SIZE)
    tokenRaw.set(payload, 0)
    tokenRaw.set(mac, ONESHOT_PAYLOAD_SIZE)

    // 8. Encode as base64url
    const token = toBase64Url(tokenRaw) as OneShotTokenString

    return {
      success: true,
      token,
      expiresAt: ts + ttlMs,
    }
  } catch {
    return {
      success: false,
      reason: 'oneshot_generation_failed',
    }
  }
}

/**
 * Parses a one-shot token string into its constituent fields.
 *
 * Uses fixed offsets — no length oracle. Token must be exactly 120 bytes raw.
 *
 * Parse offsets:
 * - nonce @ 0 (16 bytes)
 * - ts @ 16 (8 bytes)
 * - action @ 24 (32 bytes)
 * - ctx @ 56 (32 bytes)
 * - mac @ 88 (32 bytes)
 *
 * @returns ParsedOneShotToken or null if the token cannot be parsed
 */
export function parseOneShotToken(tokenString: string): ParsedOneShotToken | null {
  let raw: Uint8Array
  try {
    raw = fromBase64Url(tokenString)
  } catch {
    return null
  }

  // Constant-length check
  if (raw.length !== ONESHOT_RAW_SIZE) {
    return null
  }

  // Extract fields at fixed offsets
  const nonce = raw.slice(ONESHOT_OFFSETS.NONCE, ONESHOT_OFFSETS.NONCE + NONCE_SIZE)
  const timestamp = readUint64BE(raw, ONESHOT_OFFSETS.TIMESTAMP)
  const action = raw.slice(ONESHOT_OFFSETS.ACTION, ONESHOT_OFFSETS.ACTION + ACTION_SIZE)
  const context = raw.slice(ONESHOT_OFFSETS.CONTEXT, ONESHOT_OFFSETS.CONTEXT + CONTEXT_SIZE)
  const mac = raw.slice(ONESHOT_OFFSETS.MAC, ONESHOT_OFFSETS.MAC + MAC_SIZE)

  return { nonce, timestamp, action, context, mac }
}

/**
 * Validates a one-shot token using the Deterministic Failure Model.
 *
 * Additional checks over regular validation:
 * - Action binding: token must match the expected action
 * - Nonce replay: token nonce must not have been used before (via NonceCache)
 *
 * ALL validation steps MUST complete. No early return. Single exit point.
 *
 * @param cryptoProvider - CryptoProvider for HMAC verification
 * @param key - KeyEntry derived with 'oneshot' domain
 * @param tokenString - The one-shot token string to validate
 * @param expectedAction - The expected action string (e.g., "POST:/api/account/delete")
 * @param nonceCache - NonceCache for replay detection
 * @param expectedContext - Optional expected 32-byte context hash
 * @param ttlMs - Token TTL in milliseconds (default: 5 minutes)
 * @param now - Current timestamp override for testing
 */
export async function validateOneShotToken(
  cryptoProvider: CryptoProvider,
  key: KeyEntry,
  tokenString: string,
  expectedAction: string,
  nonceCache: NonceCache,
  expectedContext?: Uint8Array,
  ttlMs: number = DEFAULT_ONESHOT_TTL_MS,
  now: number = Date.now(),
): Promise<ValidationResult> {
  let valid = true
  let reason = 'unknown'

  // Step 1: Parse (constant-time length check)
  const parsed = parseOneShotToken(tokenString)
  const parseOk = parsed !== null
  valid &&= parseOk
  if (!parseOk) reason = 'parse_failed'

  // Step 2: TTL check
  const ttlResult = parseOk
    ? validateTTL(parsed.timestamp, ttlMs, 0, now) // One-shot tokens have no grace window
    : { withinTTL: false, inGraceWindow: false }
  const ttlOk = ttlResult.withinTTL
  valid &&= ttlOk
  if (!ttlOk) reason = 'expired'

  // Step 3: Action binding check
  const expectedActionHash = await computeAction(cryptoProvider, expectedAction)
  const actionOk = parseOk ? constantTimeEqual(parsed.action, expectedActionHash) : false
  valid &&= actionOk
  if (!actionOk) reason = 'action_mismatch'

  // Step 4: HMAC verify (constant-time — runs even if earlier steps failed)
  const macPayload = parseOk ? assembleOneShotPayload(parsed) : DUMMY_ONESHOT_PAYLOAD
  const macSignature = parseOk ? toArrayBuffer(parsed.mac) : DUMMY_MAC

  const macOk = await cryptoProvider.verify(key.cryptoKey, macSignature, macPayload)
  valid &&= macOk
  if (!macOk) reason = 'invalid_mac'

  // Step 5: Context check
  let contextOk = true
  if (expectedContext !== undefined) {
    contextOk = parseOk ? constantTimeEqual(parsed.context, expectedContext) : false
  }
  valid &&= contextOk
  if (!contextOk) reason = 'context_mismatch'

  // Step 6: Nonce replay check (atomic CAS)
  // Must run AFTER MAC verification succeeds conceptually, but we accumulate all results
  let nonceOk = true
  if (parseOk) {
    // markUsed returns true if nonce was successfully marked (not previously used)
    nonceOk = nonceCache.markUsed(parsed.nonce)
  } else {
    nonceOk = false
  }
  valid &&= nonceOk
  if (!nonceOk) reason = 'nonce_reused'

  // Single exit point — deterministic
  return valid ? { valid: true } : { valid: false, reason }
}

/**
 * Assembles the payload bytes from a parsed one-shot token for MAC verification.
 * Returns: nonce | ts | action | ctx
 */
function assembleOneShotPayload(parsed: ParsedOneShotToken): Uint8Array {
  const payload = new Uint8Array(ONESHOT_PAYLOAD_SIZE)
  payload.set(parsed.nonce, 0)
  writeUint64BE(payload, parsed.timestamp, NONCE_SIZE)
  payload.set(parsed.action, NONCE_SIZE + TIMESTAMP_SIZE)
  payload.set(parsed.context, NONCE_SIZE + TIMESTAMP_SIZE + ACTION_SIZE)
  return payload
}
