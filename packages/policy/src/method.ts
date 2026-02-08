// @sigil-security/policy — HTTP Method filtering
// Reference: SPECIFICATION.md §5.4

import type { MethodConfig, PolicyResult, PolicyValidator, RequestMetadata } from './types.js'
import { DEFAULT_PROTECTED_METHODS } from './types.js'

/**
 * Pre-built Set of default protected methods for hot-path lookups.
 * Avoids creating a new Set on every `isProtectedMethod` call.
 */
const DEFAULT_PROTECTED_SET = new Set(
  DEFAULT_PROTECTED_METHODS.map((m) => m.toUpperCase()),
)

/**
 * Creates an HTTP Method policy validator.
 *
 * This policy acts as a **gate**: it determines whether the request's HTTP method
 * requires CSRF protection. Safe methods (GET, HEAD, OPTIONS) are allowed through
 * immediately. Protected methods (POST, PUT, PATCH, DELETE) pass the gate too —
 * the actual token validation is done by the runtime layer.
 *
 * **Usage in policy chains:** This policy never rejects. The runtime layer uses
 * `isProtectedMethod()` to decide whether to run the CSRF validation pipeline
 * at all. This policy is included in the chain for audit/metrics purposes
 * (knowing which policies were evaluated).
 *
 * @param config - Optional configuration with custom protected methods
 * @returns PolicyValidator for HTTP method classification
 */
export function createMethodPolicy(config?: MethodConfig): PolicyValidator {
  const _protectedMethods = config?.protectedMethods
    ? new Set(config.protectedMethods.map((m) => m.toUpperCase()))
    : DEFAULT_PROTECTED_SET

  return {
    name: 'method',

    validate(_metadata: RequestMetadata): PolicyResult {
      // This policy is a classifier, not a gatekeeper.
      // The runtime layer uses isProtectedMethod() to decide whether to
      // run the full validation pipeline. This always allows through.
      return { allowed: true }
    },
  }
}

/**
 * Checks whether an HTTP method requires CSRF protection.
 *
 * This is the primary utility used by the runtime layer to determine
 * whether to run the full policy chain + token validation for a request.
 *
 * Uses a pre-built Set for default methods to avoid per-call allocation.
 *
 * @param method - HTTP method string
 * @param protectedMethods - Custom protected methods list (default: POST, PUT, PATCH, DELETE)
 * @returns true if the method requires CSRF protection
 */
export function isProtectedMethod(
  method: string,
  protectedMethods?: readonly string[],
): boolean {
  const methods = protectedMethods
    ? new Set(protectedMethods.map((m) => m.toUpperCase()))
    : DEFAULT_PROTECTED_SET
  return methods.has(method.toUpperCase())
}
