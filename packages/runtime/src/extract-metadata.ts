// @sigil-security/runtime — Request metadata extraction helpers
// Reference: SPECIFICATION.md §8.3

import type { RequestMetadata, TokenSource } from '@sigil-security/policy'
import {
  DEFAULT_FORM_FIELD_NAME,
  DEFAULT_HEADER_NAME,
  DEFAULT_JSON_FIELD_NAME,
} from '@sigil-security/policy'

// ============================================================
// Path Normalization
// ============================================================

/**
 * Normalizes a URL path for consistent comparison.
 *
 * **Security (L3 fix):** Strips trailing slashes to prevent
 * protection bypass via `/health/` vs `/health` mismatch.
 * Does NOT lowercase (paths are case-sensitive per RFC 3986).
 *
 * @param path - URL path to normalize
 * @returns Normalized path (no trailing slash, except for root "/")
 */
export function normalizePath(path: string): string {
  if (path.length === 0 || path === '/') return '/'

  let end = path.length
  while (end > 0 && path.charCodeAt(end - 1) === 47) end--

  if (end === path.length) return path // no trailing slash → zero allocation
  if (end === 0) return '/'
  return path.slice(0, end)
}

/**
 * Creates a normalized Set from an array of paths for consistent matching.
 *
 * @param paths - Array of paths to normalize
 * @returns Set of normalized paths
 */
export function normalizePathSet(paths: readonly string[]): Set<string> {
  return new Set(paths.map(normalizePath))
}

// ============================================================
// Header Getter Abstraction
// ============================================================

/**
 * Generic header getter function.
 * Adapters implement this to bridge framework-specific header access.
 */
export type HeaderGetter = (name: string) => string | null

// ============================================================
// Request Metadata Assembly
// ============================================================

/**
 * Assembles normalized `RequestMetadata` from generic request components.
 *
 * This is the single point where framework-specific HTTP objects
 * are transformed into the policy layer's input format.
 *
 * @param method - HTTP method (will be uppercased)
 * @param getHeader - Framework-specific header getter
 * @param tokenSource - Pre-resolved token source
 * @returns Normalized RequestMetadata for the policy layer
 */
export function extractRequestMetadata(
  method: string,
  getHeader: HeaderGetter,
  tokenSource: TokenSource,
): RequestMetadata {
  return {
    method: method.toUpperCase(),
    origin: getHeader('origin'),
    referer: getHeader('referer'),
    secFetchSite: getHeader('sec-fetch-site'),
    secFetchMode: getHeader('sec-fetch-mode'),
    secFetchDest: getHeader('sec-fetch-dest'),
    contentType: parseContentType(getHeader('content-type')),
    tokenSource,
    clientType: getHeader('x-client-type') ?? undefined,
  }
}

// ============================================================
// Content-Type Parsing
// ============================================================

/**
 * Parses Content-Type header, stripping parameters (charset, boundary, etc.).
 *
 * @example
 * parseContentType("application/json; charset=utf-8") → "application/json"
 * parseContentType(null) → null
 */
export function parseContentType(contentType: string | null): string | null {
  if (contentType === null) return null
  const semicolonIdx = contentType.indexOf(';')
  const mimeType = semicolonIdx >= 0 ? contentType.substring(0, semicolonIdx) : contentType
  return mimeType.trim().toLowerCase()
}

// ============================================================
// Token Source Resolution
// ============================================================

/**
 * Extracts CSRF token from a custom header.
 *
 * @param getHeader - Header getter function
 * @param headerName - Header name to check (default: 'x-csrf-token')
 * @returns TokenSource from header, or { from: 'none' }
 */
export function extractTokenFromHeader(
  getHeader: HeaderGetter,
  headerName: string = DEFAULT_HEADER_NAME,
): TokenSource {
  const value = getHeader(headerName)
  if (value !== null && value !== '') {
    return { from: 'header', value }
  }
  return { from: 'none' }
}

/**
 * Extracts CSRF token from a parsed JSON body.
 *
 * @param body - Parsed request body (or null/undefined)
 * @param fieldName - JSON field name (default: 'csrf_token')
 * @returns TokenSource if found, or null
 */
export function extractTokenFromJsonBody(
  body: Record<string, unknown> | null | undefined,
  fieldName: string = DEFAULT_JSON_FIELD_NAME,
): TokenSource | null {
  if (body !== null && body !== undefined && typeof body === 'object') {
    const value = body[fieldName]
    if (typeof value === 'string' && value !== '') {
      return { from: 'body-json', value }
    }
  }
  return null
}

/**
 * Extracts CSRF token from a parsed form body.
 *
 * @param body - Parsed form body (or null/undefined)
 * @param fieldName - Form field name (default: 'csrf_token')
 * @returns TokenSource if found, or null
 */
export function extractTokenFromFormBody(
  body: Record<string, unknown> | null | undefined,
  fieldName: string = DEFAULT_FORM_FIELD_NAME,
): TokenSource | null {
  if (body !== null && body !== undefined && typeof body === 'object') {
    const value = body[fieldName]
    if (typeof value === 'string' && value !== '') {
      return { from: 'body-form', value }
    }
  }
  return null
}

/**
 * Resolves token source following the transport precedence from SPECIFICATION.md §8.3:
 *
 * 1. Custom header (highest priority): `X-CSRF-Token`
 * 2. Request body (JSON): `{ "csrf_token": "..." }`
 * 3. Request body (form): `csrf_token=...`
 * 4. Query parameter: NEVER (not supported)
 *
 * First valid token wins. Multiple tokens → first match wins.
 *
 * @param getHeader - Header getter function
 * @param body - Parsed request body (JSON or form-encoded)
 * @param contentType - Parsed Content-Type MIME (lowercase, no params)
 * @param headerName - Custom header name override
 * @param jsonFieldName - Custom JSON field name override
 * @param formFieldName - Custom form field name override
 * @returns Resolved TokenSource
 */
export function resolveTokenSource(
  getHeader: HeaderGetter,
  body: Record<string, unknown> | null | undefined,
  contentType: string | null,
  headerName?: string,
  jsonFieldName?: string,
  formFieldName?: string,
): TokenSource {
  // 1. Custom header (highest precedence)
  const headerToken = extractTokenFromHeader(getHeader, headerName)
  if (headerToken.from !== 'none') return headerToken

  // 2. JSON body
  if (contentType !== null && contentType.includes('application/json')) {
    const jsonToken = extractTokenFromJsonBody(body, jsonFieldName)
    if (jsonToken !== null) return jsonToken
  }

  // 3. Form body
  if (
    contentType !== null &&
    (contentType.includes('application/x-www-form-urlencoded') ||
      contentType.includes('multipart/form-data'))
  ) {
    const formToken = extractTokenFromFormBody(body, formFieldName)
    if (formToken !== null) return formToken
  }

  // No token found
  return { from: 'none' }
}
