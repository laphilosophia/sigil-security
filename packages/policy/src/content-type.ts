// @sigil-security/policy — Content-Type restriction
// Reference: SPECIFICATION.md §5.5

import type {
  ContentTypeConfig,
  PolicyResult,
  PolicyValidator,
  RequestMetadata,
} from './types.js'
import { DEFAULT_ALLOWED_CONTENT_TYPES, DEFAULT_PROTECTED_METHODS } from './types.js'

/**
 * Extracts the MIME type from a Content-Type header value,
 * stripping any parameters (charset, boundary, etc.).
 *
 * Example: "application/json; charset=utf-8" → "application/json"
 * Example: "multipart/form-data; boundary=---" → "multipart/form-data"
 *
 * @param contentType - Raw Content-Type header value
 * @returns Normalized MIME type (lowercase, no parameters)
 */
function extractMimeType(contentType: string): string {
  const semicolonIndex = contentType.indexOf(';')
  const mimeType = semicolonIndex >= 0 ? contentType.slice(0, semicolonIndex) : contentType
  return mimeType.trim().toLowerCase()
}

/**
 * Creates a Content-Type policy validator.
 *
 * Restricts requests to known-safe Content-Type values:
 * - `application/json` (default)
 * - `application/x-www-form-urlencoded` (default)
 * - `multipart/form-data` (default)
 *
 * **Security (L6 fix):** State-changing methods (POST, PUT, PATCH, DELETE)
 * WITHOUT a Content-Type header are now rejected. Safe methods (GET, HEAD,
 * OPTIONS) without Content-Type are still allowed (no body expected).
 *
 * Content-Type parameters (charset, boundary) are stripped before comparison.
 *
 * Per SPECIFICATION.md §8.3: Content-Type mismatch (e.g., claiming JSON but
 * sending form data) is handled by the runtime layer, not the policy layer.
 *
 * @param config - Optional configuration with custom allowed Content-Types
 * @returns PolicyValidator for Content-Type restriction
 */
export function createContentTypePolicy(config?: ContentTypeConfig): PolicyValidator {
  const allowedTypes = new Set(
    (config?.allowedContentTypes ?? DEFAULT_ALLOWED_CONTENT_TYPES).map((t) => t.toLowerCase()),
  )
  const stateChangingMethods = new Set(DEFAULT_PROTECTED_METHODS)

  return {
    name: 'content-type',

    validate(metadata: RequestMetadata): PolicyResult {
      const { contentType, method } = metadata

      // No Content-Type header
      if (contentType === null || contentType === '') {
        // State-changing methods MUST have a Content-Type (L6 fix)
        if (stateChangingMethods.has(method.toUpperCase())) {
          return {
            allowed: false,
            reason: 'content_type_missing_on_state_change',
          }
        }
        // Safe methods (GET, HEAD, OPTIONS) — allow without Content-Type
        return { allowed: true }
      }

      // Extract MIME type without parameters
      const mimeType = extractMimeType(contentType)

      if (allowedTypes.has(mimeType)) {
        return { allowed: true }
      }

      return {
        allowed: false,
        reason: `content_type_disallowed:${mimeType}`,
      }
    },
  }
}
