// @sigil-security/policy — Context Binding (Risk Tier Model)
// Reference: SPECIFICATION.md §6.2, §6.3

import type {
  ContextBindingConfig,
  PolicyResult,
  PolicyValidator,
  RequestMetadata,
  RiskTier,
} from './types.js'
import { DEFAULT_CONTEXT_GRACE_PERIOD_MS } from './types.js'

/**
 * Result of context binding validation with tier-specific behavior.
 */
export interface ContextBindingResult {
  /** Whether the context matches */
  readonly matches: boolean

  /** Whether the result should be enforced (fail-closed) or logged (soft-fail) */
  readonly enforced: boolean

  /** Whether the request is within the grace period (medium tier only) */
  readonly inGracePeriod: boolean

  /** Risk tier that was applied */
  readonly tier: RiskTier
}

/**
 * Evaluates context binding based on risk tier.
 *
 * Risk Tier Model (per SPECIFICATION.md §6.2):
 *
 * | Tier   | Binding              | Failure Mode           | Use Case       |
 * |--------|----------------------|------------------------|----------------|
 * | Low    | Optional / soft-fail | Log only               | Read endpoints |
 * | Medium | Session ID hash      | Log + allow (grace)    | Settings       |
 * | High   | Session+User+Origin  | Reject + audit         | Transfers      |
 *
 * @param contextMatches - Whether the context hash matches
 * @param config - Context binding configuration with risk tier
 * @param sessionAge - Age of the current session in milliseconds (for grace period)
 * @returns ContextBindingResult with tier-specific behavior
 */
export function evaluateContextBinding(
  contextMatches: boolean,
  config: ContextBindingConfig,
  sessionAge?: number,
): ContextBindingResult {
  const { tier } = config
  const gracePeriodMs = config.gracePeriodMs ?? DEFAULT_CONTEXT_GRACE_PERIOD_MS

  if (contextMatches) {
    return {
      matches: true,
      enforced: false,
      inGracePeriod: false,
      tier,
    }
  }

  // Context does NOT match — behavior depends on tier
  switch (tier) {
    case 'low':
      // Low assurance: soft-fail, log only, allow the request
      return {
        matches: false,
        enforced: false,
        inGracePeriod: false,
        tier,
      }

    case 'medium': {
      // Medium assurance: soft-fail with grace period
      // If session was recently rotated, allow within grace period
      const inGrace =
        sessionAge !== undefined && sessionAge >= 0 && sessionAge < gracePeriodMs
      return {
        matches: false,
        enforced: !inGrace, // enforce only if NOT in grace period
        inGracePeriod: inGrace,
        tier,
      }
    }

    case 'high':
      // High assurance: fail-closed, no grace period
      return {
        matches: false,
        enforced: true,
        inGracePeriod: false,
        tier,
      }
  }
}

/**
 * Creates a context binding policy validator.
 *
 * This policy checks whether context binding validation should result in
 * a hard rejection. For low-tier endpoints, context mismatch is logged
 * but allowed. For high-tier, it's a hard reject.
 *
 * **Note:** The actual context hash comparison is performed by `@sigil-security/core`.
 * This policy determines the *enforcement behavior* based on the risk tier.
 *
 * Since the policy layer doesn't have access to token internals, this validator
 * works with pre-computed context match results passed via metadata extensions.
 *
 * @param config - Context binding configuration
 * @returns PolicyValidator for context binding enforcement
 */
export function createContextBindingPolicy(_config: ContextBindingConfig): PolicyValidator {
  return {
    name: 'context-binding',

    validate(_metadata: RequestMetadata): PolicyResult {
      // Context binding validation is tier-dependent and requires
      // context match information that comes from core token validation.
      //
      // The actual enforcement is done by `evaluateContextBinding()` at
      // the runtime layer after core validation provides the match result.
      //
      // This policy always allows — the runtime layer uses
      // `evaluateContextBinding()` for the actual decision.
      //
      // This exists in the policy chain primarily as a marker/placeholder
      // that context binding is configured for this endpoint.
      return { allowed: true }
    },
  }
}
