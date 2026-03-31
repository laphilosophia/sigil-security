// @sigil-security/runtime — Core Sigil instance (orchestration layer)
// Reference: SPECIFICATION.md Sections 3, 5, 8

import {
  WebCryptoCryptoProvider,
  createKeyring,
  getActiveKey,
  generateToken as coreGenerateToken,
  validateToken as coreValidateToken,
  generateOneShotToken as coreGenerateOneShotToken,
  createNonceCache,
  rotateKey,
} from '@sigil-security/core'
import type { CryptoProvider, Keyring, NonceCache } from '@sigil-security/core'
import {
  detectClientMode,
  isProtectedMethod,
  evaluatePolicyChain,
} from '@sigil-security/policy'
import type { PolicyChainResult, RequestMetadata } from '@sigil-security/policy'
import { resolveConfig, normalizeMasterSecret } from './sigil-config.js'
import { createKidGenerator, resolveContextBytes, validateOneShotWithKeyring } from './sigil-helpers.js'
import { createPolicySet } from './sigil-policies.js'
import type {
  ProtectResult,
  SigilConfig,
  SigilInstance,
  TokenGenerationResponse,
  TokenValidationResponse,
} from './types.js'

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
  const nextKid = createKidGenerator()

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

  const policies = createPolicySet(resolved)

  const instance: SigilInstance = {
    config: resolved,

    async generateToken(
      context?: readonly string[],
    ): Promise<TokenGenerationResponse> {
      const activeKey = getActiveKey(csrfKeyring)
      if (activeKey === undefined) {
        return { success: false, reason: 'no_active_key' }
      }

      const contextBytes = await resolveContextBytes(cryptoProvider, context)
      return coreGenerateToken(cryptoProvider, activeKey, contextBytes, resolved.tokenTTL)
    },

    async validateToken(
      tokenString: string,
      expectedContext?: readonly string[],
    ): Promise<TokenValidationResponse> {
      const contextBytes = await resolveContextBytes(cryptoProvider, expectedContext)
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

      const contextBytes = await resolveContextBytes(cryptoProvider, context)
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

      const contextBytes = await resolveContextBytes(cryptoProvider, expectedContext)
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
      const policyChain = mode === 'browser' ? policies.browser : policies.api
      const policyResult: PolicyChainResult = evaluatePolicyChain(policyChain, metadata)

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
      const contextBytes = await resolveContextBytes(cryptoProvider, contextBindings)

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
