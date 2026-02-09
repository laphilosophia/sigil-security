// @sigil-security/policy — Policy Composition (no short-circuit)
// Reference: SPECIFICATION.md §5.8 (Deterministic Failure Model)

import type { PolicyResult, PolicyValidator, RequestMetadata } from './types.js'

/**
 * Result of a policy chain evaluation.
 *
 * Includes all PolicyResult fields plus metadata about which policies
 * were evaluated and which ones failed (for internal logging only).
 */
export type PolicyChainResult =
  | {
      readonly allowed: true
      readonly evaluated: readonly string[]
      readonly failures: readonly string[]
    }
  | {
      readonly allowed: false
      readonly reason: string
      readonly evaluated: readonly string[]
      readonly failures: readonly string[]
    }

/**
 * Creates a composite policy validator from multiple individual policies.
 *
 * **CRITICAL:** All policies in the chain are executed regardless of individual
 * results. There is NO short-circuit evaluation. This follows the Deterministic
 * Failure Model from SPECIFICATION.md §5.8:
 *
 * - Every policy runs, even if an earlier one fails
 * - First failure reason is captured (for internal logging)
 * - All failure names are collected (for metrics)
 * - Single exit point, deterministic execution path
 *
 * @param policies - Array of PolicyValidator instances to compose
 * @returns A composite PolicyValidator that runs all policies
 */
export function createPolicyChain(policies: readonly PolicyValidator[]): PolicyValidator {
  return {
    name: 'policy-chain',

    validate(metadata: RequestMetadata): PolicyResult {
      return evaluatePolicyChain(policies, metadata)
    },
  }
}

/**
 * Evaluates a chain of policies against request metadata.
 *
 * Returns a detailed result including all evaluated and failed policy names.
 * No short-circuit: ALL policies execute regardless of individual results.
 *
 * **Security (M4 fix):** An empty policy chain fails closed. A configuration
 * bug that produces an empty chain MUST NOT silently approve all requests.
 *
 * @param policies - Array of policies to evaluate
 * @param metadata - Normalized request metadata
 * @returns Detailed chain evaluation result
 */
export function evaluatePolicyChain(
  policies: readonly PolicyValidator[],
  metadata: RequestMetadata,
): PolicyChainResult {
  // Fail closed on empty policy chain — prevent accidental misconfiguration
  // from silently approving all requests
  if (policies.length === 0) {
    return {
      allowed: false,
      reason: 'empty_policy_chain',
      evaluated: [],
      failures: [],
    }
  }

  let allAllowed = true
  let firstReason = ''
  const evaluated: string[] = []
  const failures: string[] = []

  // Execute ALL policies — no short-circuit (deterministic timing)
  for (const policy of policies) {
    evaluated.push(policy.name)
    const result = policy.validate(metadata)

    if (!result.allowed) {
      failures.push(policy.name)

      if (allAllowed) {
        // Capture first failure reason (for internal logging)
        firstReason = result.reason
        allAllowed = false
      }
    }
  }

  if (allAllowed) {
    return {
      allowed: true,
      evaluated,
      failures,
    }
  }

  return {
    allowed: false,
    reason: firstReason,
    evaluated,
    failures,
  }
}
