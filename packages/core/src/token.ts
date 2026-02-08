// @sigil-security/core — Token generation, parsing, serialization (89 bytes fixed)

import type { CryptoProvider } from './crypto-provider.js'
import type { KeyEntry } from './key-manager.js'
import type { GenerationResult, ParsedToken, TokenString } from './types.js'
import {
  CONTEXT_SIZE,
  DEFAULT_TOKEN_TTL_MS,
  KID_SIZE,
  MAC_SIZE,
  NONCE_SIZE,
  TIMESTAMP_SIZE,
  TOKEN_OFFSETS,
  TOKEN_RAW_SIZE,
} from './types.js'
import { fromBase64Url, readUint64BE, toBase64Url, writeUint64BE } from './encoding.js'
import { emptyContext } from './context.js'

/**
 * Generates a CSRF token.
 *
 * Steps:
 * 1. Generate nonce: crypto.randomBytes(16)
 * 2. Get current timestamp
 * 3. Compute context (provided or SHA-256(0x00), ALWAYS 32 bytes)
 * 4. Assemble payload: kid | nonce | ts | ctx
 * 5. Sign: HMAC-SHA256(derived_key, payload)
 * 6. Encode: base64url(kid | nonce | ts | ctx | mac)
 *
 * Token wire format: 89 bytes raw → base64url encoded
 * ```
 * [ kid:1 ][ nonce:16 ][ ts:8 ][ ctx:32 ][ mac:32 ]
 * ```
 *
 * @param cryptoProvider - CryptoProvider for crypto operations
 * @param key - Active KeyEntry from the keyring
 * @param context - Optional 32-byte context binding hash
 * @param ttlMs - Token TTL in milliseconds (default: 20 minutes)
 * @param now - Current timestamp override for testing
 */
export async function generateToken(
  cryptoProvider: CryptoProvider,
  key: KeyEntry,
  context?: Uint8Array,
  ttlMs: number = DEFAULT_TOKEN_TTL_MS,
  now: number = Date.now(),
): Promise<GenerationResult> {
  try {
    // 1. Generate 128-bit nonce
    const nonce = cryptoProvider.randomBytes(NONCE_SIZE)

    // 2. Timestamp
    const ts = now

    // 3. Context (always 32 bytes — zero-pad if not provided)
    const ctx = context ?? (await emptyContext(cryptoProvider))

    // 4. Assemble payload for signing: kid | nonce | ts | ctx
    const payloadSize = KID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE + CONTEXT_SIZE
    const payload = new Uint8Array(payloadSize)
    payload[0] = key.kid & 0xff
    payload.set(nonce, KID_SIZE)
    writeUint64BE(payload, ts, KID_SIZE + NONCE_SIZE)
    payload.set(ctx, KID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE)

    // 5. Sign with HMAC-SHA256
    const macBuffer = await cryptoProvider.sign(key.cryptoKey, payload)
    const mac = new Uint8Array(macBuffer)

    // 6. Assemble full token: payload | mac
    const tokenRaw = new Uint8Array(TOKEN_RAW_SIZE)
    tokenRaw.set(payload, 0)
    tokenRaw.set(mac, payloadSize)

    // 7. Encode as base64url
    const token = toBase64Url(tokenRaw) as TokenString

    return {
      success: true,
      token,
      expiresAt: ts + ttlMs,
    }
  } catch {
    return {
      success: false,
      reason: 'token_generation_failed',
    }
  }
}

/**
 * Parses a token string into its constituent fields.
 *
 * Uses fixed offsets — no length oracle. Token must be exactly 89 bytes raw.
 *
 * Parse offsets:
 * - kid @ 0 (1 byte)
 * - nonce @ 1 (16 bytes)
 * - ts @ 17 (8 bytes)
 * - ctx @ 25 (32 bytes)
 * - mac @ 57 (32 bytes)
 *
 * @returns ParsedToken or null if the token cannot be parsed
 */
export function parseToken(tokenString: string): ParsedToken | null {
  let raw: Uint8Array
  try {
    raw = fromBase64Url(tokenString)
  } catch {
    return null
  }

  // Constant-length check: must be exactly TOKEN_RAW_SIZE bytes
  if (raw.length !== TOKEN_RAW_SIZE) {
    return null
  }

  // Extract fields at fixed offsets
  const kid = raw[TOKEN_OFFSETS.KID]
  if (kid === undefined) {
    return null
  }
  const nonce = raw.slice(TOKEN_OFFSETS.NONCE, TOKEN_OFFSETS.NONCE + NONCE_SIZE)
  const timestamp = readUint64BE(raw, TOKEN_OFFSETS.TIMESTAMP)
  const context = raw.slice(TOKEN_OFFSETS.CONTEXT, TOKEN_OFFSETS.CONTEXT + CONTEXT_SIZE)
  const mac = raw.slice(TOKEN_OFFSETS.MAC, TOKEN_OFFSETS.MAC + MAC_SIZE)

  return { kid, nonce, timestamp, context, mac }
}

/**
 * Assembles the payload bytes from a parsed token for MAC verification.
 * Returns: kid | nonce | ts | ctx
 */
export function assemblePayload(parsed: ParsedToken): Uint8Array {
  const payload = new Uint8Array(KID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE + CONTEXT_SIZE)
  payload[0] = parsed.kid & 0xff
  payload.set(parsed.nonce, KID_SIZE)
  writeUint64BE(payload, parsed.timestamp, KID_SIZE + NONCE_SIZE)
  payload.set(parsed.context, KID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE)
  return payload
}

/**
 * Serializes token fields into a TokenString.
 *
 * @param kid - Key identifier (8-bit)
 * @param nonce - 16-byte nonce
 * @param ts - Timestamp as milliseconds
 * @param ctx - 32-byte context hash
 * @param mac - 32-byte MAC
 */
export function serializeToken(
  kid: number,
  nonce: Uint8Array,
  ts: number,
  ctx: Uint8Array,
  mac: Uint8Array,
): TokenString {
  const tokenRaw = new Uint8Array(TOKEN_RAW_SIZE)
  tokenRaw[0] = kid & 0xff
  tokenRaw.set(nonce, KID_SIZE)
  writeUint64BE(tokenRaw, ts, KID_SIZE + NONCE_SIZE)
  tokenRaw.set(ctx, KID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE)
  tokenRaw.set(mac, KID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE + CONTEXT_SIZE)
  return toBase64Url(tokenRaw) as TokenString
}
