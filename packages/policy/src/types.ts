// @sigil-security/policy — Types and interfaces
// Reference: SPECIFICATION.md Sections 5, 6, 8

// ============================================================
// Token Source (how the token was transported)
// ============================================================

/**
 * Describes where a CSRF token was found in the request.
 *
 * Transport precedence (strict order per SPECIFICATION.md §8.3):
 * 1. Custom header (X-CSRF-Token)
 * 2. Request body (JSON)
 * 3. Request body (form)
 * 4. None (no token found)
 *
 * Query parameter transport is NEVER allowed.
 */
export type TokenSource =
  | { readonly from: 'header'; readonly value: string }
  | { readonly from: 'body-json'; readonly value: string }
  | { readonly from: 'body-form'; readonly value: string }
  | { readonly from: 'none' }

// ============================================================
// Request Metadata (normalized, framework-agnostic)
// ============================================================

/**
 * Normalized request metadata extracted from HTTP requests.
 *
 * **CRITICAL:** This is a plain object — NOT a framework-specific Request, req, res,
 * or any HTTP object. The runtime layer is responsible for extracting RequestMetadata
 * from framework objects (Express, Fastify, Hono, etc.).
 *
 * The policy layer NEVER touches raw HTTP objects.
 */
export interface RequestMetadata {
  /** HTTP method (uppercase: GET, POST, PUT, PATCH, DELETE, etc.) */
  readonly method: string

  /** Origin header value, or null if absent */
  readonly origin: string | null

  /** Referer header value, or null if absent */
  readonly referer: string | null

  /** Sec-Fetch-Site header: same-origin, same-site, cross-site, none, or null */
  readonly secFetchSite: string | null

  /** Sec-Fetch-Mode header: cors, navigate, no-cors, same-origin, websocket, or null */
  readonly secFetchMode: string | null

  /** Sec-Fetch-Dest header: document, embed, font, image, script, style, etc., or null */
  readonly secFetchDest: string | null

  /** Content-Type header value (without parameters), or null if absent */
  readonly contentType: string | null

  /** Describes how the CSRF token was transported */
  readonly tokenSource: TokenSource

  /** Optional: explicit client type override header (X-Client-Type) */
  readonly clientType?: string | undefined
}

// ============================================================
// Policy Result
// ============================================================

/**
 * Result of a policy validation check.
 *
 * - `allowed: true` — request passes this policy check
 * - `allowed: false` — request fails with an internal reason (NEVER exposed to client)
 */
export type PolicyResult =
  | { readonly allowed: true }
  | { readonly allowed: false; readonly reason: string }

// ============================================================
// Policy Validator Interface
// ============================================================

/**
 * A single validation policy that examines request metadata.
 *
 * Policies are composable via `createPolicyChain`.
 * Each policy is a pure function of `RequestMetadata` — no side effects, no I/O.
 */
export interface PolicyValidator {
  /** Unique identifier for this policy (for logging/metrics) */
  readonly name: string

  /** Validate request metadata against this policy */
  validate(metadata: RequestMetadata): PolicyResult
}

// ============================================================
// Configuration Types
// ============================================================

/** Legacy browser handling mode for Fetch Metadata policy */
export type LegacyBrowserMode = 'degraded' | 'strict'

/** Configuration for Fetch Metadata policy */
export interface FetchMetadataConfig {
  /** How to handle requests without Fetch Metadata headers (default: 'degraded') */
  readonly legacyBrowserMode?: LegacyBrowserMode | undefined
}

/** Configuration for Origin policy */
export interface OriginConfig {
  /** List of allowed origins (e.g., ['https://example.com', 'https://api.example.com']) */
  readonly allowedOrigins: readonly string[]
}

/** Configuration for Method policy */
export interface MethodConfig {
  /** HTTP methods that require CSRF protection (default: POST, PUT, PATCH, DELETE) */
  readonly protectedMethods?: readonly string[] | undefined
}

/** Configuration for Content-Type policy */
export interface ContentTypeConfig {
  /** Allowed Content-Type values (default: application/json, application/x-www-form-urlencoded, multipart/form-data) */
  readonly allowedContentTypes?: readonly string[] | undefined
}

// ============================================================
// Context Binding Types (Risk Tier Model)
// ============================================================

/** Risk tier for context binding per SPECIFICATION.md §6.2 */
export type RiskTier = 'low' | 'medium' | 'high'

/** Configuration for context binding policy */
export interface ContextBindingConfig {
  /** Risk tier determining binding strictness */
  readonly tier: RiskTier

  /**
   * Grace period in milliseconds for session rotation tolerance.
   * Only applies to 'medium' tier (soft-fail with grace period).
   * Default: 5 minutes (300_000 ms)
   */
  readonly gracePeriodMs?: number | undefined
}

// ============================================================
// Token Transport Types
// ============================================================

/** Configuration for token transport extraction */
export interface TokenTransportConfig {
  /** Custom header name (default: 'x-csrf-token') */
  readonly headerName?: string | undefined

  /** JSON body field name (default: 'csrf_token') */
  readonly jsonFieldName?: string | undefined

  /** Form body field name (default: 'csrf_token') */
  readonly formFieldName?: string | undefined
}

/** Result of token transport extraction */
export type TokenTransportResult =
  | { readonly found: true; readonly source: TokenSource; readonly warnings: readonly string[] }
  | { readonly found: false; readonly reason: string }

// ============================================================
// Client Mode
// ============================================================

/** Detected client mode per SPECIFICATION.md §8.2 */
export type ClientMode = 'browser' | 'api'

// ============================================================
// Default Constants
// ============================================================

/** Default HTTP methods requiring CSRF protection */
export const DEFAULT_PROTECTED_METHODS: readonly string[] = ['POST', 'PUT', 'PATCH', 'DELETE']

/** Default allowed Content-Type values */
export const DEFAULT_ALLOWED_CONTENT_TYPES: readonly string[] = [
  'application/json',
  'application/x-www-form-urlencoded',
  'multipart/form-data',
]

/** Default token header name */
export const DEFAULT_HEADER_NAME = 'x-csrf-token'

/** Default one-shot token header name */
export const DEFAULT_ONESHOT_HEADER_NAME = 'x-csrf-one-shot-token'

/** Default JSON body field name for CSRF token */
export const DEFAULT_JSON_FIELD_NAME = 'csrf_token'

/** Default form body field name for CSRF token */
export const DEFAULT_FORM_FIELD_NAME = 'csrf_token'

/** Default grace period for medium-tier context binding (5 minutes) */
export const DEFAULT_CONTEXT_GRACE_PERIOD_MS = 5 * 60 * 1000
