// @sigil-security/policy — HTTP Method filtering
// Reference: SPECIFICATION.md §5.4

import type { MethodConfig, PolicyResult, PolicyValidator, RequestMetadata } from './types.js'
import { DEFAULT_PROTECTED_METHODS } from './types.js'

/**
 * Creates an HTTP Method policy validator.
 *
 * Determines whether a request's HTTP method requires CSRF protection.
 *
 * Default protected methods: POST, PUT, PATCH, DELETE
 * Default unprotected methods: GET, HEAD, OPTIONS (and any others)
 *
 * When a method is NOT protected, the policy returns `allowed: true`
 * (skipping further CSRF validation is the caller's responsibility).
 *
 * When a method IS protected, the policy returns `allowed: true` —
 * this policy only indicates "this method requires protection" vs "does not".
 * It does NOT perform token validation; it is used in policy chains to
 * skip CSRF checks for safe methods.
 *
 * @param config - Optional configuration with custom protected methods
 * @returns PolicyValidator for HTTP method filtering
 */
export function createMethodPolicy(config?: MethodConfig): PolicyValidator {
  const protectedMethods = new Set(
    (config?.protectedMethods ?? DEFAULT_PROTECTED_METHODS).map((m) => m.toUpperCase()),
  )

  return {
    name: 'method',

    validate(metadata: RequestMetadata): PolicyResult {
      const method = metadata.method.toUpperCase()

      // Safe methods (GET, HEAD, OPTIONS) → no CSRF protection needed
      if (!protectedMethods.has(method)) {
        return { allowed: true }
      }

      // Protected method → needs CSRF protection (validated by other policies + token)
      // This policy allows it through; token validation is done separately
      return { allowed: true }
    },
  }
}

/**
 * Checks whether an HTTP method requires CSRF protection.
 *
 * This is a utility function used by the runtime layer to determine
 * whether to run the full policy chain for a request.
 *
 * @param method - HTTP method string
 * @param protectedMethods - Set of protected methods (default: POST, PUT, PATCH, DELETE)
 * @returns true if the method requires CSRF protection
 */
export function isProtectedMethod(
  method: string,
  protectedMethods?: readonly string[],
): boolean {
  const methods = new Set(
    (protectedMethods ?? DEFAULT_PROTECTED_METHODS).map((m) => m.toUpperCase()),
  )
  return methods.has(method.toUpperCase())
}
