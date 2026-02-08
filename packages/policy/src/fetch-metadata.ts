// @sigil-security/policy — Fetch Metadata validation
// Reference: SPECIFICATION.md §5.1, §8.4

import type {
  FetchMetadataConfig,
  LegacyBrowserMode,
  PolicyResult,
  PolicyValidator,
  RequestMetadata,
} from './types.js'

/** Valid Sec-Fetch-Site header values */
const VALID_FETCH_SITE_VALUES = new Set([
  'same-origin',
  'same-site',
  'cross-site',
  'none',
])

/**
 * Creates a Fetch Metadata policy validator.
 *
 * Validates requests using the `Sec-Fetch-Site` header (W3C Fetch Metadata):
 * - `same-origin` → allow
 * - `same-site` → allow (log warning for cross-origin subdomain)
 * - `cross-site` → reject (state-changing request from external origin)
 * - `none` → reject (browser extension or untrusted origin)
 * - Header absent → depends on `legacyBrowserMode`:
 *   - `'degraded'` (default) → allow (fallback to Origin + Token validation)
 *   - `'strict'` → reject (modern browser required)
 *
 * @param config - Optional configuration for legacy browser handling
 * @returns PolicyValidator for Fetch Metadata
 */
export function createFetchMetadataPolicy(config?: FetchMetadataConfig): PolicyValidator {
  const legacyMode: LegacyBrowserMode = config?.legacyBrowserMode ?? 'degraded'

  return {
    name: 'fetch-metadata',

    validate(metadata: RequestMetadata): PolicyResult {
      const secFetchSite = metadata.secFetchSite

      // Header absent → legacy browser or non-browser client
      if (secFetchSite === null || secFetchSite === '') {
        if (legacyMode === 'strict') {
          return {
            allowed: false,
            reason: 'fetch_metadata_missing_strict',
          }
        }
        // Degraded mode: allow, rely on other validation layers (Origin + Token)
        return { allowed: true }
      }

      // Normalize to lowercase for consistent comparison
      const normalized = secFetchSite.toLowerCase()

      // Unrecognized value → reject
      if (!VALID_FETCH_SITE_VALUES.has(normalized)) {
        return {
          allowed: false,
          reason: `fetch_metadata_invalid_value:${normalized}`,
        }
      }

      // same-origin → allow (trusted)
      if (normalized === 'same-origin') {
        return { allowed: true }
      }

      // same-site → allow (subdomain, cross-origin but same site)
      // Per SPECIFICATION.md §8.4: Allow but log (cross-origin)
      if (normalized === 'same-site') {
        return { allowed: true }
      }

      // cross-site → reject (external origin)
      if (normalized === 'cross-site') {
        return {
          allowed: false,
          reason: 'fetch_metadata_cross_site',
        }
      }

      // none → reject (browser extension or untrusted origin)
      // Per SPECIFICATION.md §8.4: Browser extension initiated requests are rejected
      // This is the last valid value in VALID_FETCH_SITE_VALUES, so no else needed
      return {
        allowed: false,
        reason: 'fetch_metadata_none',
      }
    },
  }
}
