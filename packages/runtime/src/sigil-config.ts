// @sigil-security/runtime — Sigil configuration normalization helpers

import {
  DEFAULT_GRACE_WINDOW_MS,
  DEFAULT_ONESHOT_TTL_MS,
  DEFAULT_TOKEN_TTL_MS,
} from '@sigil-security/core'
import {
  DEFAULT_HEADER_NAME,
  DEFAULT_ONESHOT_HEADER_NAME,
  DEFAULT_PROTECTED_METHODS,
} from '@sigil-security/policy'
import type { ResolvedSigilConfig, SigilConfig } from './types.js'

/** Minimum master secret length in bytes for adequate security */
const MIN_MASTER_SECRET_BYTES = 32

/**
 * Converts a string master secret to ArrayBuffer.
 * If already an ArrayBuffer, returns as-is.
 *
 * **Security:** Validates that the master secret is at least 32 bytes.
 * HKDF handles short inputs correctly, but effective security is bounded by
 * the input entropy. A weak master secret undermines the entire key hierarchy.
 *
 * @throws {Error} If the master secret is shorter than 32 bytes
 */
export function normalizeMasterSecret(secret: ArrayBuffer | string): ArrayBuffer {
  if (typeof secret !== 'string') {
    if (secret.byteLength < MIN_MASTER_SECRET_BYTES) {
      throw new Error(
        `Master secret must be at least ${String(MIN_MASTER_SECRET_BYTES)} bytes, ` +
        `got ${String(secret.byteLength)} bytes. Use a cryptographically strong secret.`,
      )
    }
    return secret
  }

  const encoder = new TextEncoder()
  const bytes = encoder.encode(secret)
  if (bytes.byteLength < MIN_MASTER_SECRET_BYTES) {
    throw new Error(
      `Master secret must be at least ${String(MIN_MASTER_SECRET_BYTES)} bytes when UTF-8 encoded, ` +
      `got ${String(bytes.byteLength)} bytes. Use a cryptographically strong secret.`,
    )
  }

  // Create a clean ArrayBuffer (not a view into a shared buffer)
  const buffer = new ArrayBuffer(bytes.byteLength)
  new Uint8Array(buffer).set(bytes)
  return buffer
}

/**
 * Resolves user config with defaults applied.
 */
export function resolveConfig(config: SigilConfig): ResolvedSigilConfig {
  return {
    tokenTTL: config.tokenTTL ?? DEFAULT_TOKEN_TTL_MS,
    graceWindow: config.graceWindow ?? DEFAULT_GRACE_WINDOW_MS,
    allowedOrigins: config.allowedOrigins,
    legacyBrowserMode: config.legacyBrowserMode ?? 'degraded',
    allowApiMode: config.allowApiMode ?? true,
    protectedMethods: config.protectedMethods ?? DEFAULT_PROTECTED_METHODS,
    contextBinding: config.contextBinding,
    oneShotEnabled: config.oneShotEnabled ?? false,
    oneShotTTL: config.oneShotTTL ?? DEFAULT_ONESHOT_TTL_MS,
    headerName: config.headerName ?? DEFAULT_HEADER_NAME,
    oneShotHeaderName: config.oneShotHeaderName ?? DEFAULT_ONESHOT_HEADER_NAME,
    disableClientModeOverride: config.disableClientModeOverride ?? false,
  }
}
