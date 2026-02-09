// @sigil-security/policy — Origin / Referer validation
// Reference: SPECIFICATION.md §5.2, RFC 6454

import type { OriginConfig, PolicyResult, PolicyValidator, RequestMetadata } from './types.js'

/**
 * Extracts origin from a Referer URL.
 *
 * Example: "https://example.com/path/page?q=1" → "https://example.com"
 *
 * Returns null if the Referer is not a valid URL.
 */
function extractOriginFromReferer(referer: string): string | null {
  try {
    const url = new URL(referer)
    return url.origin
  } catch {
    return null
  }
}

/**
 * Normalizes an origin string by removing trailing slashes and lowering the scheme/host.
 *
 * **Security (L5 fix):** Returns `null` on URL parse failure instead of a
 * fallback string comparison. A malformed origin can never match any entry
 * in `allowedOrigins`, eliminating unintentional string-level matches.
 *
 * @param origin - Origin string (e.g., "https://Example.COM/")
 * @returns Normalized origin (e.g., "https://example.com"), or null if invalid
 */
function normalizeOrigin(origin: string): string | null {
  try {
    const url = new URL(origin)
    return url.origin
  } catch {
    // Invalid origin — return null so it never matches any allowed origin
    return null
  }
}

/**
 * Creates an Origin/Referer policy validator.
 *
 * Validates request provenance using Origin and Referer headers:
 * - If Origin header present → strict match against allowed origins
 * - If Origin absent → Referer header fallback (extract origin from URL)
 * - Both absent → reject (no provenance signal)
 *
 * @param config - Configuration with list of allowed origins
 * @returns PolicyValidator for Origin/Referer
 */
export function createOriginPolicy(config: OriginConfig): PolicyValidator {
  // Pre-normalize allowed origins — filter out invalid entries (null from parse failure)
  const normalizedAllowed = new Set<string>()
  for (const o of config.allowedOrigins) {
    const normalized = normalizeOrigin(o)
    if (normalized !== null) {
      normalizedAllowed.add(normalized)
    }
  }

  return {
    name: 'origin',

    validate(metadata: RequestMetadata): PolicyResult {
      const { origin, referer } = metadata

      // Try Origin header first
      if (origin !== null && origin !== '') {
        const normalizedOrigin = normalizeOrigin(origin)

        // null = malformed origin → automatic mismatch (L5 fix)
        if (normalizedOrigin !== null && normalizedAllowed.has(normalizedOrigin)) {
          return { allowed: true }
        }

        return {
          allowed: false,
          reason: `origin_mismatch:${normalizedOrigin ?? origin}`,
        }
      }

      // Origin absent → fallback to Referer
      if (referer !== null && referer !== '') {
        const refererOrigin = extractOriginFromReferer(referer)

        if (refererOrigin === null) {
          return {
            allowed: false,
            reason: 'origin_referer_invalid',
          }
        }

        const normalizedRefererOrigin = normalizeOrigin(refererOrigin)

        // null = malformed → automatic mismatch
        if (normalizedRefererOrigin !== null && normalizedAllowed.has(normalizedRefererOrigin)) {
          return { allowed: true }
        }

        return {
          allowed: false,
          reason: `origin_referer_mismatch:${normalizedRefererOrigin ?? refererOrigin}`,
        }
      }

      // Both absent → reject (no provenance signal)
      return {
        allowed: false,
        reason: 'origin_missing',
      }
    },
  }
}
