// @sigil-security/runtime — Token endpoint handler
// Reference: SPECIFICATION.md §3 — Token generation endpoints

import type { SigilInstance, TokenEndpointResult } from './types.js'
import {
  createErrorResponse,
  createTokenResponse,
  createOneShotTokenResponse,
} from './error-response.js'

/**
 * Handles token generation requests.
 *
 * This is a framework-agnostic handler that processes token endpoint requests.
 * Each adapter calls this and maps the result to framework-specific responses.
 *
 * Supported endpoints:
 * - `GET {tokenEndpointPath}` → Generate a regular CSRF token
 * - `POST {oneShotEndpointPath}` → Generate a one-shot token (requires action binding)
 *
 * **Security (M2 fix):** The one-shot endpoint (POST) requires a valid regular
 * CSRF token in the request header. This prevents cross-origin one-shot token
 * generation and nonce cache exhaustion attacks.
 *
 * @param sigil - The Sigil instance
 * @param method - HTTP method (uppercase)
 * @param path - Request path
 * @param body - Parsed request body (for POST endpoints)
 * @param tokenEndpointPath - Token generation endpoint path
 * @param oneShotEndpointPath - One-shot token endpoint path
 * @param csrfTokenValue - CSRF token from request header (required for POST one-shot endpoint)
 * @returns TokenEndpointResult if the request was handled, or null if not a token endpoint
 */
export async function handleTokenEndpoint(
  sigil: SigilInstance,
  method: string,
  path: string,
  body: Record<string, unknown> | null | undefined,
  tokenEndpointPath: string,
  oneShotEndpointPath: string,
  csrfTokenValue?: string | null,
): Promise<TokenEndpointResult | null> {
  const upperMethod = method.toUpperCase()

  // GET /api/csrf/token → Generate regular CSRF token
  if (path === tokenEndpointPath && upperMethod === 'GET') {
    return handleRegularTokenGeneration(sigil)
  }

  // POST /api/csrf/one-shot → Generate one-shot token
  // Requires a valid regular CSRF token for defense-in-depth
  if (
    sigil.config.oneShotEnabled &&
    path === oneShotEndpointPath &&
    upperMethod === 'POST'
  ) {
    // Validate CSRF token before generating one-shot token
    if (csrfTokenValue === undefined || csrfTokenValue === null || csrfTokenValue === '') {
      const errorResponse = createErrorResponse(false)
      return {
        handled: true,
        status: errorResponse.status,
        body: errorResponse.body,
        headers: errorResponse.headers as Record<string, string>,
      }
    }

    const csrfResult = await sigil.validateToken(csrfTokenValue)
    if (!csrfResult.valid) {
      const errorResponse = createErrorResponse(false)
      return {
        handled: true,
        status: errorResponse.status,
        body: errorResponse.body,
        headers: errorResponse.headers as Record<string, string>,
      }
    }

    return handleOneShotTokenGeneration(sigil, body)
  }

  // Not a token endpoint request
  return null
}

/**
 * Generates a regular CSRF token.
 */
async function handleRegularTokenGeneration(
  sigil: SigilInstance,
): Promise<TokenEndpointResult> {
  const result = await sigil.generateToken()

  if (!result.success) {
    return {
      handled: true,
      status: 500,
      body: { error: 'Token generation failed' },
      headers: {},
    }
  }

  const response = createTokenResponse(result.token, result.expiresAt)
  return {
    handled: true,
    status: response.status,
    body: response.body,
    headers: {},
  }
}

/**
 * Generates a one-shot token with action binding.
 */
async function handleOneShotTokenGeneration(
  sigil: SigilInstance,
  body: Record<string, unknown> | null | undefined,
): Promise<TokenEndpointResult> {
  // Validate request body
  if (body === null || body === undefined || typeof body !== 'object') {
    return {
      handled: true,
      status: 400,
      body: { error: 'Request body required' },
      headers: {},
    }
  }

  const action = body['action']
  if (typeof action !== 'string' || action === '') {
    return {
      handled: true,
      status: 400,
      body: { error: 'Missing or invalid action parameter' },
      headers: {},
    }
  }

  // Optional context bindings
  let context: readonly string[] | undefined
  const rawContext = body['context']
  if (Array.isArray(rawContext)) {
    const isAllStrings = rawContext.every((item): item is string => typeof item === 'string')
    if (isAllStrings) {
      context = rawContext
    }
  }

  const result = await sigil.generateOneShotToken(action, context)

  if (!result.success) {
    return {
      handled: true,
      status: 500,
      body: { error: 'One-shot token generation failed' },
      headers: {},
    }
  }

  const response = createOneShotTokenResponse(result.token, result.expiresAt, action)
  return {
    handled: true,
    status: response.status,
    body: response.body,
    headers: {},
  }
}

/**
 * Creates a standardized error result for the token endpoint.
 * Used by adapters when they need to produce error responses.
 */
export function createTokenEndpointError(
  expired: boolean,
): TokenEndpointResult {
  const errorResponse = createErrorResponse(expired)
  return {
    handled: true,
    status: errorResponse.status,
    body: errorResponse.body,
    headers: errorResponse.headers as Record<string, string>,
  }
}
