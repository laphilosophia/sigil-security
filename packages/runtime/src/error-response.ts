// @sigil-security/runtime — Uniform error responses
// Reference: SPECIFICATION.md §5.8 — NEVER differentiate error types to client

/**
 * Uniform CSRF validation failure message.
 *
 * **CRITICAL:** This is the ONLY error message sent to the client.
 * Detailed failure reasons go to internal logs ONLY — never in HTTP response body.
 */
const CSRF_FAILURE_MESSAGE = 'CSRF validation failed'

/** HTTP header name indicating token expiry */
const EXPIRED_HEADER_NAME = 'X-CSRF-Token-Expired'

/**
 * Framework-agnostic error response structure.
 *
 * Used by all adapters to produce consistent 403 responses.
 */
export interface ErrorResponse {
  readonly status: number
  readonly body: { readonly error: string }
  readonly headers: Readonly<Record<string, string>>
}

/**
 * Creates a uniform client-facing error response.
 *
 * The body is intentionally generic regardless of the specific failure mode.
 * Status codes may still differ so adapters can preserve HTTP semantics.
 *
 * @param status - HTTP status code to return
 * @param expired - Whether the response should include the token-expired hint
 */
export function createClientErrorResponse(
  status: number,
  expired: boolean = false,
): ErrorResponse {
  const headers: Record<string, string> = {}
  if (expired) {
    headers[EXPIRED_HEADER_NAME] = 'true'
  }

  return {
    status,
    body: { error: CSRF_FAILURE_MESSAGE },
    headers,
  }
}

/**
 * Creates a uniform 403 error response.
 *
 * - Always returns `403 { error: "CSRF validation failed" }`
 * - If the token is expired, adds `X-CSRF-Token-Expired: true` header
 *   (allows client-side silent refresh without exposing failure reason)
 *
 * @param expired - Whether the failure is due to token expiry
 * @returns Framework-agnostic error response
 */
export function createErrorResponse(expired: boolean): ErrorResponse {
  return createClientErrorResponse(403, expired)
}

/**
 * Creates a framework-agnostic success response for token generation.
 *
 * @param token - Generated token string
 * @param expiresAt - Token expiration timestamp (milliseconds)
 */
export function createTokenResponse(
  token: string,
  expiresAt: number,
): { readonly status: number; readonly body: { readonly token: string; readonly expiresAt: number } } {
  return {
    status: 200,
    body: { token, expiresAt },
  }
}

/**
 * Creates a framework-agnostic success response for one-shot token generation.
 *
 * @param token - Generated one-shot token string
 * @param expiresAt - Token expiration timestamp (milliseconds)
 * @param action - The action the token is bound to
 */
export function createOneShotTokenResponse(
  token: string,
  expiresAt: number,
  action: string,
): {
  readonly status: number
  readonly body: { readonly token: string; readonly expiresAt: number; readonly action: string }
} {
  return {
    status: 200,
    body: { token, expiresAt, action },
  }
}
