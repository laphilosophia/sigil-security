// @sigil-security/core — Types, constants, and branded types

// ============================================================
// Branded Types
// ============================================================

declare const TOKEN_BRAND: unique symbol
declare const ONESHOT_TOKEN_BRAND: unique symbol

/** Branded string type for regular CSRF tokens */
export type TokenString = string & { readonly [TOKEN_BRAND]: 'SigilToken' }

/** Branded string type for one-shot tokens */
export type OneShotTokenString = string & {
  readonly [ONESHOT_TOKEN_BRAND]: 'SigilOneShotToken'
}

// ============================================================
// Token Structure Constants
// ============================================================

/** Key ID size in bytes (8-bit key identifier) */
export const KID_SIZE = 1

/** Nonce size in bytes (128-bit random) */
export const NONCE_SIZE = 16

/** Timestamp size in bytes (int64 big-endian) */
export const TIMESTAMP_SIZE = 8

/** Context hash size in bytes (SHA-256 output) */
export const CONTEXT_SIZE = 32

/** MAC size in bytes (HMAC-SHA256, full 256-bit, NO truncation) */
export const MAC_SIZE = 32

/** Action hash size in bytes (SHA-256 of action string) */
export const ACTION_SIZE = 32

/**
 * Regular token raw size: kid(1) + nonce(16) + ts(8) + ctx(32) + mac(32) = 89 bytes FIXED
 */
export const TOKEN_RAW_SIZE =
  KID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE + CONTEXT_SIZE + MAC_SIZE // 89

/**
 * One-shot token raw size: nonce(16) + ts(8) + action(32) + ctx(32) + mac(32) = 120 bytes FIXED
 */
export const ONESHOT_RAW_SIZE =
  NONCE_SIZE + TIMESTAMP_SIZE + ACTION_SIZE + CONTEXT_SIZE + MAC_SIZE // 120

// ============================================================
// Token Field Offsets (Regular Token — fixed-offset parsing)
// ============================================================

/** Regular token field offsets */
export const TOKEN_OFFSETS = {
  /** kid starts at byte 0 */
  KID: 0,
  /** nonce starts at byte 1 */
  NONCE: KID_SIZE,
  /** timestamp starts at byte 17 */
  TIMESTAMP: KID_SIZE + NONCE_SIZE,
  /** context starts at byte 25 */
  CONTEXT: KID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE,
  /** mac starts at byte 57 */
  MAC: KID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE + CONTEXT_SIZE,
} as const

/** One-shot token field offsets */
export const ONESHOT_OFFSETS = {
  /** nonce starts at byte 0 */
  NONCE: 0,
  /** timestamp starts at byte 16 */
  TIMESTAMP: NONCE_SIZE,
  /** action starts at byte 24 */
  ACTION: NONCE_SIZE + TIMESTAMP_SIZE,
  /** context starts at byte 56 */
  CONTEXT: NONCE_SIZE + TIMESTAMP_SIZE + ACTION_SIZE,
  /** mac starts at byte 88 */
  MAC: NONCE_SIZE + TIMESTAMP_SIZE + ACTION_SIZE + CONTEXT_SIZE,
} as const

// ============================================================
// Parsed Token Types
// ============================================================

/** Parsed regular token (extracted from wire format) */
export interface ParsedToken {
  readonly kid: number
  readonly nonce: Uint8Array
  readonly timestamp: number
  readonly context: Uint8Array
  readonly mac: Uint8Array
}

/** Parsed one-shot token (extracted from wire format) */
export interface ParsedOneShotToken {
  readonly nonce: Uint8Array
  readonly timestamp: number
  readonly action: Uint8Array
  readonly context: Uint8Array
  readonly mac: Uint8Array
}

// ============================================================
// Result Types (never throw for validation)
// ============================================================

/** Token validation result */
export type ValidationResult =
  | { readonly valid: true }
  | { readonly valid: false; readonly reason: string }

/** Token generation result */
export type GenerationResult =
  | { readonly success: true; readonly token: TokenString; readonly expiresAt: number }
  | { readonly success: false; readonly reason: string }

/** One-shot token generation result */
export type OneShotGenerationResult =
  | {
      readonly success: true
      readonly token: OneShotTokenString
      readonly expiresAt: number
    }
  | { readonly success: false; readonly reason: string }

// ============================================================
// Default Configuration Constants
// ============================================================

/** Default token TTL in milliseconds (20 minutes) */
export const DEFAULT_TOKEN_TTL_MS = 20 * 60 * 1000

/** Default grace window in milliseconds (60 seconds) */
export const DEFAULT_GRACE_WINDOW_MS = 60 * 1000

/** Default one-shot token TTL in milliseconds (5 minutes) */
export const DEFAULT_ONESHOT_TTL_MS = 5 * 60 * 1000

/** Default nonce cache max entries */
export const DEFAULT_NONCE_CACHE_MAX = 10_000

/** Default nonce cache TTL in milliseconds (5 minutes) */
export const DEFAULT_NONCE_CACHE_TTL_MS = 5 * 60 * 1000
