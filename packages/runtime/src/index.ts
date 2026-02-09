// @sigil-security/runtime — Public API surface
// Framework adapters for request handling

// ============================================================
// Types
// ============================================================

export type {
  SigilConfig,
  ResolvedSigilConfig,
  SigilInstance,
  TokenGenerationResponse,
  TokenValidationResponse,
  ProtectResult,
  MetadataExtractor,
  TokenEndpointRequest,
  TokenEndpointResult,
  OneShotTokenRequestBody,
  ErrorResponseBody,
  MiddlewareOptions,
} from './types.js'

// ============================================================
// Constants
// ============================================================

export { DEFAULT_TOKEN_ENDPOINT_PATH, DEFAULT_ONESHOT_ENDPOINT_PATH } from './types.js'

// ============================================================
// Core Orchestration
// ============================================================

export { createSigil } from './sigil.js'

// ============================================================
// Error Responses
// ============================================================

export {
  createErrorResponse,
  createTokenResponse,
  createOneShotTokenResponse,
} from './error-response.js'
export type { ErrorResponse } from './error-response.js'

// ============================================================
// Request Metadata Extraction
// ============================================================

export {
  extractRequestMetadata,
  parseContentType,
  extractTokenFromHeader,
  extractTokenFromJsonBody,
  extractTokenFromFormBody,
  resolveTokenSource,
  normalizePath,
  normalizePathSet,
} from './extract-metadata.js'
export type { HeaderGetter } from './extract-metadata.js'

// ============================================================
// Token Endpoint Handler
// ============================================================

export { handleTokenEndpoint, createTokenEndpointError } from './token-endpoint.js'
