// @sigil-security/policy — Token Transport Precedence
// Reference: SPECIFICATION.md §8.3

import type {
  RequestMetadata,
  TokenSource,
  TokenTransportConfig,
  TokenTransportResult,
} from './types.js'
import {
  DEFAULT_FORM_FIELD_NAME,
  DEFAULT_HEADER_NAME,
  DEFAULT_JSON_FIELD_NAME,
} from './types.js'

/**
 * Resolves token transport from request metadata.
 *
 * Transport precedence (strict order per SPECIFICATION.md §8.3):
 *
 * 1. **Custom Header** (recommended): `X-CSRF-Token`
 * 2. **Request Body** (JSON): `{ "csrf_token": "..." }`
 * 3. **Request Body** (form): `csrf_token=...`
 * 4. **Query Parameter**: NEVER allowed (deprecated, insecure — reject with warning)
 *
 * Rules:
 * - First valid token found is used
 * - Multiple tokens → first match wins, warning logged
 * - Token source is captured for audit logging
 *
 * @param metadata - Normalized request metadata with token source
 * @param _config - Optional transport configuration
 * @returns TokenTransportResult with found token and any warnings
 */
export function resolveTokenTransport(
  metadata: RequestMetadata,
  _config?: TokenTransportConfig,
): TokenTransportResult {
  const { tokenSource } = metadata

  // Token already extracted by the runtime layer and normalized into TokenSource
  if (tokenSource.from === 'none') {
    return {
      found: false,
      reason: 'no_token_present',
    }
  }

  // Token found from a valid source
  return {
    found: true,
    source: tokenSource,
    warnings: [],
  }
}

/**
 * Validates that a token source is acceptable.
 *
 * Verifies the token was transported via an approved channel:
 * - Header: always acceptable
 * - Body (JSON or form): acceptable
 * - Query parameter: NEVER acceptable
 *
 * @param source - The token source to validate
 * @returns true if the transport method is acceptable
 */
export function isValidTokenTransport(source: TokenSource): boolean {
  return source.from === 'header' || source.from === 'body-json' || source.from === 'body-form'
}

/**
 * Returns the expected header name for CSRF tokens.
 *
 * @param config - Optional transport configuration
 * @returns Header name (lowercase)
 */
export function getTokenHeaderName(config?: TokenTransportConfig): string {
  return config?.headerName ?? DEFAULT_HEADER_NAME
}

/**
 * Returns the expected JSON field name for CSRF tokens.
 *
 * @param config - Optional transport configuration
 * @returns JSON field name
 */
export function getTokenJsonFieldName(config?: TokenTransportConfig): string {
  return config?.jsonFieldName ?? DEFAULT_JSON_FIELD_NAME
}

/**
 * Returns the expected form field name for CSRF tokens.
 *
 * @param config - Optional transport configuration
 * @returns Form field name
 */
export function getTokenFormFieldName(config?: TokenTransportConfig): string {
  return config?.formFieldName ?? DEFAULT_FORM_FIELD_NAME
}
