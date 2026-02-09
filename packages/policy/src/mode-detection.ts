// @sigil-security/policy — Browser vs API Mode Detection
// Reference: SPECIFICATION.md §8.2

import type { ClientMode, RequestMetadata } from './types.js'

/**
 * Configuration for client mode detection.
 */
export interface ModeDetectionConfig {
  /**
   * When true, the `X-Client-Type: api` header override is disabled.
   * Clients cannot self-declare as API mode to bypass Fetch Metadata and
   * Origin validation. Mode is determined solely by `Sec-Fetch-Site` presence.
   *
   * **Security (M3 fix):** A server with permissive CORS configuration
   * (`Access-Control-Allow-Headers: *`) would allow cross-origin attackers
   * to set `X-Client-Type: api` and bypass browser-specific policies.
   * Set this to `true` if CORS cannot be tightly controlled.
   *
   * Default: `false` (override allowed for backward compatibility)
   */
  readonly disableClientModeOverride?: boolean | undefined
}

/**
 * Detects client mode (browser vs API) from request metadata.
 *
 * Mode detection logic (per SPECIFICATION.md §8.2):
 *
 * 1. Manual override: `X-Client-Type: api` → Force API Mode (unless disabled)
 * 2. `Sec-Fetch-Site` header present → Browser Mode
 *    (modern browsers always send Fetch Metadata headers)
 * 3. `Sec-Fetch-Site` header absent → API Mode
 *    (non-browser clients: mobile apps, CLI, services)
 *
 * **Browser Mode:**
 * - Full multi-layer validation: Fetch Metadata + Origin + Token
 * - All policies in the chain are enforced
 *
 * **API Mode:**
 * - Token-only validation (no Fetch Metadata enforcement)
 * - Context binding recommended (API key hash)
 * - Fetch Metadata and Origin policies are relaxed
 *
 * @param metadata - Normalized request metadata
 * @param config - Optional mode detection configuration
 * @returns 'browser' or 'api'
 */
export function detectClientMode(
  metadata: RequestMetadata,
  config?: ModeDetectionConfig,
): ClientMode {
  // Manual override via X-Client-Type header (unless disabled)
  if (
    config?.disableClientModeOverride !== true &&
    metadata.clientType !== undefined &&
    metadata.clientType.toLowerCase() === 'api'
  ) {
    return 'api'
  }

  // Sec-Fetch-Site present → Browser Mode
  // Modern browsers (Chrome 76+, Firefox 90+, Edge 79+, Safari 16.4+)
  // always send this header on navigation and subresource requests
  if (metadata.secFetchSite !== null && metadata.secFetchSite !== '') {
    return 'browser'
  }

  // No Fetch Metadata → API Mode (non-browser client)
  return 'api'
}
