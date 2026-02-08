// @sigil-security/core — Public API surface
// Cryptographic request intent verification primitive

// ============================================================
// Types
// ============================================================

export type { CryptoProvider } from './crypto-provider.js'

export type {
  TokenString,
  OneShotTokenString,
  ParsedToken,
  ParsedOneShotToken,
  ValidationResult,
  GenerationResult,
  OneShotGenerationResult,
} from './types.js'

export type { KeyEntry, Keyring } from './key-manager.js'

export type { KeyDomain } from './key-derivation.js'

export type { NonceCache, NonceCacheConfig } from './nonce-cache.js'

// ============================================================
// CryptoProvider
// ============================================================

export { WebCryptoCryptoProvider } from './web-crypto-provider.js'

// ============================================================
// Key Management
// ============================================================

export { createKeyring, rotateKey, resolveKey, getActiveKey } from './key-manager.js'

export { deriveSigningKey } from './key-derivation.js'

// ============================================================
// Token Operations
// ============================================================

export { generateToken, parseToken, serializeToken, assemblePayload } from './token.js'

export { validateToken, validateTTL, constantTimeEqual } from './validation.js'

export { computeContext, emptyContext } from './context.js'

// ============================================================
// One-Shot Token Operations
// ============================================================

export {
  generateOneShotToken,
  parseOneShotToken,
  validateOneShotToken,
  computeAction,
} from './one-shot-token.js'

// ============================================================
// Nonce Cache
// ============================================================

export { createNonceCache } from './nonce-cache.js'

// ============================================================
// Constants
// ============================================================

export {
  KID_SIZE,
  NONCE_SIZE,
  TIMESTAMP_SIZE,
  CONTEXT_SIZE,
  MAC_SIZE,
  ACTION_SIZE,
  TOKEN_RAW_SIZE,
  ONESHOT_RAW_SIZE,
  TOKEN_OFFSETS,
  ONESHOT_OFFSETS,
  DEFAULT_TOKEN_TTL_MS,
  DEFAULT_GRACE_WINDOW_MS,
  DEFAULT_ONESHOT_TTL_MS,
  DEFAULT_NONCE_CACHE_MAX,
  DEFAULT_NONCE_CACHE_TTL_MS,
} from './types.js'

// ============================================================
// Encoding Utilities
// ============================================================

export { toBase64Url, fromBase64Url, toArrayBuffer } from './encoding.js'
