// @sigil-security/runtime — Types and configuration interfaces
// Reference: SPECIFICATION.md Sections 3, 8

import type { CryptoProvider } from '@sigil-security/core'
import type {
  ContextBindingConfig,
  LegacyBrowserMode,
  PolicyChainResult,
  RequestMetadata,
} from '@sigil-security/policy'

// ============================================================
// Sigil Configuration
// ============================================================

/**
 * Main configuration for Sigil runtime.
 *
 * This is the single entry point for configuring CSRF protection.
 * The runtime layer orchestrates all interactions between core and policy.
 *
 * @example
 * ```typescript
 * const sigil = await createSigil({
 *   masterSecret: process.env.CSRF_SECRET,
 *   allowedOrigins: ['https://example.com'],
 * })
 * ```
 */
export interface SigilConfig {
  // ---- Core ----

  /** Master secret for HKDF key derivation (minimum 32 bytes recommended) */
  readonly masterSecret: ArrayBuffer | string

  /** Token TTL in milliseconds (default: 20 minutes = 1_200_000ms) */
  readonly tokenTTL?: number | undefined

  /** Grace window after TTL expiry for in-flight requests (default: 60s = 60_000ms) */
  readonly graceWindow?: number | undefined

  // ---- Policy ----

  /** List of allowed origins (e.g., ['https://example.com']) */
  readonly allowedOrigins: readonly string[]

  /** How to handle legacy browsers without Fetch Metadata (default: 'degraded') */
  readonly legacyBrowserMode?: LegacyBrowserMode | undefined

  /** Allow API mode (non-browser clients with token-only validation) (default: true) */
  readonly allowApiMode?: boolean | undefined

  /** HTTP methods that require CSRF protection (default: ['POST','PUT','PATCH','DELETE']) */
  readonly protectedMethods?: readonly string[] | undefined

  // ---- Context Binding ----

  /** Context binding configuration (risk tier model) */
  readonly contextBinding?: ContextBindingConfig | undefined

  // ---- One-Shot ----

  /** Enable one-shot token support (default: false) */
  readonly oneShotEnabled?: boolean | undefined

  /** One-shot token TTL in milliseconds (default: 5 minutes = 300_000ms) */
  readonly oneShotTTL?: number | undefined

  // ---- Token Transport ----

  /** Custom header name for CSRF tokens (default: 'x-csrf-token') */
  readonly headerName?: string | undefined

  /** Custom header name for one-shot tokens (default: 'x-csrf-one-shot-token') */
  readonly oneShotHeaderName?: string | undefined

  // ---- Security Hardening ----

  /**
   * Disable X-Client-Type header override for mode detection.
   * When true, clients cannot self-declare as API mode to bypass
   * Fetch Metadata and Origin validation policies.
   *
   * Enable this if CORS configuration cannot be tightly controlled.
   * Default: false
   */
  readonly disableClientModeOverride?: boolean | undefined

  // ---- Provider Override ----

  /** Custom CryptoProvider implementation (default: WebCryptoCryptoProvider) */
  readonly cryptoProvider?: CryptoProvider | undefined
}

// ============================================================
// Resolved Configuration (defaults applied)
// ============================================================

/**
 * Fully resolved configuration with all defaults applied.
 * Exposed as `sigil.config` on a SigilInstance.
 */
export interface ResolvedSigilConfig {
  readonly tokenTTL: number
  readonly graceWindow: number
  readonly allowedOrigins: readonly string[]
  readonly legacyBrowserMode: LegacyBrowserMode
  readonly allowApiMode: boolean
  readonly protectedMethods: readonly string[]
  readonly contextBinding: ContextBindingConfig | undefined
  readonly oneShotEnabled: boolean
  readonly oneShotTTL: number
  readonly headerName: string
  readonly oneShotHeaderName: string
  readonly disableClientModeOverride: boolean
}

// ============================================================
// Sigil Instance (Orchestration Core)
// ============================================================

/**
 * The Sigil runtime instance.
 *
 * Created by `createSigil(config)`. Holds the keyring, nonce cache,
 * and provides token generation / validation / protection methods.
 */
export interface SigilInstance {
  /** Generate a new CSRF token */
  generateToken(context?: readonly string[]): Promise<TokenGenerationResponse>

  /** Validate a CSRF token */
  validateToken(
    tokenString: string,
    expectedContext?: readonly string[],
  ): Promise<TokenValidationResponse>

  /** Generate a one-shot token (requires `oneShotEnabled: true`) */
  generateOneShotToken(
    action: string,
    context?: readonly string[],
  ): Promise<TokenGenerationResponse>

  /** Validate a one-shot token (tries all keys in the oneshot keyring) */
  validateOneShotToken(
    tokenString: string,
    expectedAction: string,
    expectedContext?: readonly string[],
  ): Promise<TokenValidationResponse>

  /** Rotate keyrings — new key becomes active, oldest dropped */
  rotateKeys(): Promise<void>

  /**
   * Full request protection: policy chain + token validation.
   *
   * 1. Checks if the method needs protection
   * 2. Detects client mode (browser vs API)
   * 3. Runs appropriate policy chain
   * 4. Validates CSRF token
   *
   * @param metadata - Normalized request metadata (extracted by adapter)
   * @param contextBindings - Optional context bindings for token validation
   */
  protect(
    metadata: RequestMetadata,
    contextBindings?: readonly string[],
  ): Promise<ProtectResult>

  /** Resolved configuration (readonly) */
  readonly config: ResolvedSigilConfig
}

// ============================================================
// Token Response Types
// ============================================================

/** Token generation response */
export type TokenGenerationResponse =
  | { readonly success: true; readonly token: string; readonly expiresAt: number }
  | { readonly success: false; readonly reason: string }

/** Token validation response */
export type TokenValidationResponse =
  | { readonly valid: true }
  | { readonly valid: false; readonly reason: string }

// ============================================================
// Protection Result
// ============================================================

/**
 * Result of full request protection (policy chain + token validation).
 *
 * - `allowed: true` → request passed all checks
 * - `allowed: false` → request blocked, `reason` is for internal logging only
 */
export type ProtectResult =
  | {
      readonly allowed: true
      readonly tokenValid: boolean
      readonly policyResult: PolicyChainResult
    }
  | {
      readonly allowed: false
      readonly reason: string
      readonly expired: boolean
      readonly policyResult: PolicyChainResult | null
    }

// ============================================================
// Metadata Extractor Contract
// ============================================================

/**
 * Extracts normalized `RequestMetadata` from a framework-specific request object.
 *
 * Each framework adapter implements this for its own request type.
 * This bridges framework HTTP objects to the policy layer.
 */
export type MetadataExtractor<TRequest> = (req: TRequest) => RequestMetadata

// ============================================================
// Token Endpoint Types
// ============================================================

/** Minimal request shape for the token endpoint handler */
export interface TokenEndpointRequest {
  readonly method: string
  readonly path: string
  readonly body?: Record<string, unknown> | undefined
}

/** Token endpoint response (returned by `handleTokenEndpoint`) */
export interface TokenEndpointResult {
  readonly handled: boolean
  readonly status: number
  readonly body: Record<string, unknown>
  readonly headers: Record<string, string>
}

/** One-shot token request body */
export interface OneShotTokenRequestBody {
  readonly action: string
  readonly context?: readonly string[] | undefined
}

// ============================================================
// Error Response Types
// ============================================================

/** Uniform error response body — NEVER differentiates error types to client */
export interface ErrorResponseBody {
  readonly error: string
}

// ============================================================
// Middleware Options
// ============================================================

/**
 * Options for framework middleware adapters.
 *
 * Controls path exclusion, token endpoint paths, and context binding extraction.
 */
export interface MiddlewareOptions {
  /** Paths to exclude from protection (exact match) */
  readonly excludePaths?: readonly string[] | undefined

  /** Token generation endpoint path (default: '/api/csrf/token') */
  readonly tokenEndpointPath?: string | undefined

  /** One-shot token endpoint path (default: '/api/csrf/one-shot') */
  readonly oneShotEndpointPath?: string | undefined
}

// ============================================================
// Default Constants
// ============================================================

/** Default token generation endpoint path */
export const DEFAULT_TOKEN_ENDPOINT_PATH = '/api/csrf/token'

/** Default one-shot token endpoint path */
export const DEFAULT_ONESHOT_ENDPOINT_PATH = '/api/csrf/one-shot'
