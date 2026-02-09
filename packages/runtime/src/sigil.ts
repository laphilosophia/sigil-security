// @sigil-security/runtime — Core Sigil instance (orchestration layer)
// Reference: SPECIFICATION.md Sections 3, 5, 8

import {
  WebCryptoCryptoProvider,
  createKeyring,
  rotateKey,
  getActiveKey,
  generateToken as coreGenerateToken,
  validateToken as coreValidateToken,
  computeContext,
  generateOneShotToken as coreGenerateOneShotToken,
  validateOneShotToken as coreValidateOneShotToken,
  createNonceCache,
  DEFAULT_TOKEN_TTL_MS,
  DEFAULT_GRACE_WINDOW_MS,
  DEFAULT_ONESHOT_TTL_MS,
} from '@sigil-security/core'
import type { CryptoProvider, Keyring, NonceCache, ValidationResult } from '@sigil-security/core'
import {
  createFetchMetadataPolicy,
  createOriginPolicy,
  createMethodPolicy,
  createContentTypePolicy,
  detectClientMode,
  isProtectedMethod,
  evaluatePolicyChain,
  DEFAULT_HEADER_NAME,
  DEFAULT_ONESHOT_HEADER_NAME,
  DEFAULT_PROTECTED_METHODS,
} from '@sigil-security/policy'
import type { PolicyValidator, RequestMetadata, PolicyChainResult } from '@sigil-security/policy'
import type {
  SigilConfig,
  SigilInstance,
  ResolvedSigilConfig,
  TokenGenerationResponse,
  TokenValidationResponse,
  ProtectResult,
} from './types.js'

// ============================================================
// Master Secret Normalization
// ============================================================

/** Minimum master secret length in bytes for adequate security */
const MIN_MASTER_SECRET_BYTES = 32

/**
 * Converts a string master secret to ArrayBuffer.
 * If already an ArrayBuffer, returns as-is.
 *
 * **Security (L1 fix):** Validates that the master secret is at least 32 bytes.
 * HKDF handles short inputs correctly, but effective security is bounded by
 * the input entropy. A weak master secret undermines the entire key hierarchy.
 *
 * @throws {Error} If the master secret is shorter than 32 bytes
 */
function normalizeMasterSecret(secret: ArrayBuffer | string): ArrayBuffer {
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

// ============================================================
// Configuration Resolution
// ============================================================

/**
 * Resolves user config with defaults applied.
 */
function resolveConfig(config: SigilConfig): ResolvedSigilConfig {
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

// ============================================================
// One-Shot Keyring Validation Helper
// ============================================================

/**
 * Validates a one-shot token against all keys in a keyring.
 *
 * One-shot tokens do NOT embed a kid, so we must try all keys.
 * The nonce is only consumed on the first successful validation.
 *
 * @returns The first successful result, or the last failure
 */
async function validateOneShotWithKeyring(
  cryptoProvider: CryptoProvider,
  keyring: Keyring,
  tokenString: string,
  expectedAction: string,
  nonceCache: NonceCache,
  expectedContext: Uint8Array | undefined,
  ttlMs: number,
): Promise<ValidationResult> {
  let lastResult: ValidationResult = { valid: false, reason: 'no_keys' }

  for (const key of keyring.keys) {
    const result = await coreValidateOneShotToken(
      cryptoProvider,
      key,
      tokenString,
      expectedAction,
      nonceCache,
      expectedContext,
      ttlMs,
    )
    if (result.valid) return result
    lastResult = result
  }

  return lastResult
}

// ============================================================
// Sigil Instance Factory
// ============================================================

/**
 * Creates a Sigil runtime instance.
 *
 * This is the main entry point for Sigil. It initializes keyrings,
 * sets up policy chains, and returns an orchestration instance
 * that adapters use for token generation, validation, and request protection.
 *
 * @param config - Sigil configuration
 * @returns Initialized SigilInstance
 *
 * @example
 * ```typescript
 * const sigil = await createSigil({
 *   masterSecret: process.env.CSRF_SECRET!,
 *   allowedOrigins: ['https://example.com'],
 * })
 *
 * // Generate a token
 * const result = await sigil.generateToken()
 *
 * // Protect a request
 * const protection = await sigil.protect(metadata)
 * ```
 */
export async function createSigil(config: SigilConfig): Promise<SigilInstance> {
  const resolved = resolveConfig(config)
  const cryptoProvider: CryptoProvider = config.cryptoProvider ?? new WebCryptoCryptoProvider()
  const masterSecret = normalizeMasterSecret(config.masterSecret)

  // Instance-scoped kid counter (avoids global state)
  let kidCounter = 0
  function nextKid(): number {
    kidCounter = (kidCounter + 1) & 0xff // 8-bit wrap
    return kidCounter
  }

  // Initialize CSRF keyring
  const initialKid = nextKid()
  let csrfKeyring = await createKeyring(cryptoProvider, masterSecret, initialKid, 'csrf')

  // Initialize one-shot keyring and nonce cache (if enabled)
  let oneShotKeyring: Keyring | null = null
  let nonceCache: NonceCache | null = null
  if (resolved.oneShotEnabled) {
    oneShotKeyring = await createKeyring(cryptoProvider, masterSecret, initialKid, 'oneshot')
    nonceCache = createNonceCache()
  }

  // Build policy chains
  const browserPolicies: PolicyValidator[] = [
    createMethodPolicy({ protectedMethods: [...resolved.protectedMethods] }),
    createFetchMetadataPolicy({ legacyBrowserMode: resolved.legacyBrowserMode }),
    createOriginPolicy({ allowedOrigins: [...resolved.allowedOrigins] }),
    createContentTypePolicy(),
  ]

  const apiPolicies: PolicyValidator[] = [
    createMethodPolicy({ protectedMethods: [...resolved.protectedMethods] }),
    createContentTypePolicy(),
  ]

  // ============================================================
  // Instance Methods
  // ============================================================

  const instance: SigilInstance = {
    config: resolved,

    async generateToken(
      context?: readonly string[],
    ): Promise<TokenGenerationResponse> {
      const activeKey = getActiveKey(csrfKeyring)
      if (activeKey === undefined) {
        return { success: false, reason: 'no_active_key' }
      }

      let contextBytes: Uint8Array | undefined
      if (context !== undefined && context.length > 0) {
        contextBytes = await computeContext(cryptoProvider, ...context)
      }

      return coreGenerateToken(cryptoProvider, activeKey, contextBytes, resolved.tokenTTL)
    },

    async validateToken(
      tokenString: string,
      expectedContext?: readonly string[],
    ): Promise<TokenValidationResponse> {
      let contextBytes: Uint8Array | undefined
      if (expectedContext !== undefined && expectedContext.length > 0) {
        contextBytes = await computeContext(cryptoProvider, ...expectedContext)
      }

      return coreValidateToken(
        cryptoProvider,
        csrfKeyring,
        tokenString,
        contextBytes,
        resolved.tokenTTL,
        resolved.graceWindow,
      )
    },

    async generateOneShotToken(
      action: string,
      context?: readonly string[],
    ): Promise<TokenGenerationResponse> {
      if (!resolved.oneShotEnabled || oneShotKeyring === null) {
        return { success: false, reason: 'oneshot_not_enabled' }
      }

      const activeKey = getActiveKey(oneShotKeyring)
      if (activeKey === undefined) {
        return { success: false, reason: 'no_active_key' }
      }

      let contextBytes: Uint8Array | undefined
      if (context !== undefined && context.length > 0) {
        contextBytes = await computeContext(cryptoProvider, ...context)
      }

      return coreGenerateOneShotToken(
        cryptoProvider,
        activeKey,
        action,
        contextBytes,
        resolved.oneShotTTL,
      )
    },

    async validateOneShotToken(
      tokenString: string,
      expectedAction: string,
      expectedContext?: readonly string[],
    ): Promise<TokenValidationResponse> {
      if (!resolved.oneShotEnabled || oneShotKeyring === null || nonceCache === null) {
        return { valid: false, reason: 'oneshot_not_enabled' }
      }

      let contextBytes: Uint8Array | undefined
      if (expectedContext !== undefined && expectedContext.length > 0) {
        contextBytes = await computeContext(cryptoProvider, ...expectedContext)
      }

      // One-shot tokens have no kid — try all keys in the keyring
      return validateOneShotWithKeyring(
        cryptoProvider,
        oneShotKeyring,
        tokenString,
        expectedAction,
        nonceCache,
        contextBytes,
        resolved.oneShotTTL,
      )
    },

    async rotateKeys(): Promise<void> {
      const newKid = nextKid()
      csrfKeyring = await rotateKey(csrfKeyring, cryptoProvider, masterSecret, newKid)

      if (oneShotKeyring !== null) {
        oneShotKeyring = await rotateKey(oneShotKeyring, cryptoProvider, masterSecret, newKid)
      }
    },

    async protect(
      metadata: RequestMetadata,
      contextBindings?: readonly string[],
    ): Promise<ProtectResult> {
      // Step 1: Safe methods don't need protection
      if (!isProtectedMethod(metadata.method, [...resolved.protectedMethods])) {
        return {
          allowed: true,
          tokenValid: false,
          policyResult: { allowed: true, evaluated: [], failures: [] },
        }
      }

      // Step 2: Detect client mode
      const mode = detectClientMode(metadata, {
        disableClientModeOverride: resolved.disableClientModeOverride,
      })

      // Step 3: API mode check
      if (mode === 'api' && !resolved.allowApiMode) {
        return {
          allowed: false,
          reason: 'api_mode_not_allowed',
          expired: false,
          policyResult: null,
        }
      }

      // Step 4: Run policy chain based on detected mode
      const policies = mode === 'browser' ? browserPolicies : apiPolicies
      const policyResult: PolicyChainResult = evaluatePolicyChain(policies, metadata)

      if (!policyResult.allowed) {
        return {
          allowed: false,
          reason: policyResult.reason,
          expired: false,
          policyResult,
        }
      }

      // Step 5: Token must be present
      if (metadata.tokenSource.from === 'none') {
        return {
          allowed: false,
          reason: 'no_token_present',
          expired: false,
          policyResult,
        }
      }

      // Step 6: Compute context binding (if provided)
      let contextBytes: Uint8Array | undefined
      if (contextBindings !== undefined && contextBindings.length > 0) {
        contextBytes = await computeContext(cryptoProvider, ...contextBindings)
      }

      // Step 7: Validate CSRF token
      const tokenResult = await coreValidateToken(
        cryptoProvider,
        csrfKeyring,
        metadata.tokenSource.value,
        contextBytes,
        resolved.tokenTTL,
        resolved.graceWindow,
      )

      if (!tokenResult.valid) {
        return {
          allowed: false,
          reason: tokenResult.reason,
          expired: tokenResult.reason === 'expired',
          policyResult,
        }
      }

      return {
        allowed: true,
        tokenValid: true,
        policyResult,
      }
    },
  }

  return instance
}
