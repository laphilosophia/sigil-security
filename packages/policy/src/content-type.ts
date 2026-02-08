// @sigil-security/policy — Content-Type restriction
// Reference: SPECIFICATION.md §5.5

import type {
  ContentTypeConfig,
  PolicyResult,
  PolicyValidator,
  RequestMetadata,
} from './types.js'
import { DEFAULT_ALLOWED_CONTENT_TYPES } from './types.js'

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
 * Requests without a Content-Type header are allowed (e.g., GET requests).
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

  return {
    name: 'content-type',

    validate(metadata: RequestMetadata): PolicyResult {
      const { contentType } = metadata

      // No Content-Type header → allow (could be GET/HEAD with no body)
      if (contentType === null || contentType === '') {
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
