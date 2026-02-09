// @sigil-security/policy — Public API surface
// Validation policies for request metadata — Fetch Metadata, Origin, context binding

// ============================================================
// Types
// ============================================================

export type {
  RequestMetadata,
  TokenSource,
  PolicyResult,
  PolicyValidator,
  ClientMode,
  RiskTier,
  LegacyBrowserMode,
  FetchMetadataConfig,
  OriginConfig,
  MethodConfig,
  ContentTypeConfig,
  ContextBindingConfig,
  TokenTransportConfig,
  TokenTransportResult,
} from './types.js'

// ============================================================
// Constants
// ============================================================

export {
  DEFAULT_PROTECTED_METHODS,
  DEFAULT_ALLOWED_CONTENT_TYPES,
  DEFAULT_HEADER_NAME,
  DEFAULT_ONESHOT_HEADER_NAME,
  DEFAULT_JSON_FIELD_NAME,
  DEFAULT_FORM_FIELD_NAME,
  DEFAULT_CONTEXT_GRACE_PERIOD_MS,
} from './types.js'

// ============================================================
// Fetch Metadata Policy
// ============================================================

export { createFetchMetadataPolicy } from './fetch-metadata.js'

// ============================================================
// Origin / Referer Policy
// ============================================================

export { createOriginPolicy } from './origin.js'

// ============================================================
// HTTP Method Policy
// ============================================================

export { createMethodPolicy, isProtectedMethod } from './method.js'

// ============================================================
// Content-Type Policy
// ============================================================

export { createContentTypePolicy } from './content-type.js'

// ============================================================
// Browser vs API Mode Detection
// ============================================================

export { detectClientMode } from './mode-detection.js'
export type { ModeDetectionConfig } from './mode-detection.js'

// ============================================================
// Context Binding (Risk Tier Model)
// ============================================================

export { createContextBindingPolicy, evaluateContextBinding } from './context-binding.js'
export type { ContextBindingResult } from './context-binding.js'

// ============================================================
// Policy Composition
// ============================================================

export { createPolicyChain, evaluatePolicyChain } from './policy-chain.js'
export type { PolicyChainResult } from './policy-chain.js'

// ============================================================
// Token Transport
// ============================================================

export {
  resolveTokenTransport,
  isValidTokenTransport,
  getTokenHeaderName,
  getTokenJsonFieldName,
  getTokenFormFieldName,
} from './token-transport.js'
