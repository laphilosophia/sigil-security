// @sigil-security/runtime — Policy chain construction helpers

import {
  createContentTypePolicy,
  createFetchMetadataPolicy,
  createMethodPolicy,
  createOriginPolicy,
} from '@sigil-security/policy'
import type { PolicyValidator } from '@sigil-security/policy'
import type { ResolvedSigilConfig } from './types.js'

export interface PolicySet {
  readonly browser: readonly PolicyValidator[]
  readonly api: readonly PolicyValidator[]
}

/**
 * Builds the browser and API policy sets for a Sigil instance.
 */
export function createPolicySet(config: ResolvedSigilConfig): PolicySet {
  return {
    browser: [
      createMethodPolicy({ protectedMethods: [...config.protectedMethods] }),
      createFetchMetadataPolicy({ legacyBrowserMode: config.legacyBrowserMode }),
      createOriginPolicy({ allowedOrigins: [...config.allowedOrigins] }),
      createContentTypePolicy(),
    ],
    api: [
      createMethodPolicy({ protectedMethods: [...config.protectedMethods] }),
      createContentTypePolicy(),
    ],
  }
}
