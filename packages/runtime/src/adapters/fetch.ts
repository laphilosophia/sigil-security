// @sigil-security/runtime — Native Fetch adapter (Edge runtime, Cloudflare Workers, etc.)
// Reference: SPECIFICATION.md §3

import type { SigilInstance, MiddlewareOptions, ProtectResult } from '../types.js'
import { DEFAULT_TOKEN_ENDPOINT_PATH, DEFAULT_ONESHOT_ENDPOINT_PATH } from '../types.js'
import { extractRequestMetadata, resolveTokenSource, parseContentType, normalizePath, normalizePathSet } from '../extract-metadata.js'
import type { HeaderGetter } from '../extract-metadata.js'
import { createErrorResponse } from '../error-response.js'
import { handleTokenEndpoint } from '../token-endpoint.js'

// ============================================================
// Types
// ============================================================

/** A handler that processes a Request and returns a Response */
export type FetchHandler = (request: Request) => Promise<Response> | Response

// ============================================================
// Header Getter for Fetch API
// ============================================================

function createFetchHeaderGetter(headers: Headers): HeaderGetter {
  return (name: string): string | null => {
    return headers.get(name.toLowerCase())
  }
}

/**
 * Extracts the pathname from a Request URL.
 */
function extractPathname(request: Request): string {
  try {
    return new URL(request.url).pathname
  } catch {
    // Fallback for relative URLs
    const qIndex = request.url.indexOf('?')
    return qIndex >= 0 ? request.url.slice(0, qIndex) : request.url
  }
}

// ============================================================
// Fetch Middleware Factory
// ============================================================

/**
 * Creates a Fetch API middleware wrapper for Sigil CSRF protection.
 *
 * Wraps a request handler and intercepts requests for CSRF validation
 * and token endpoint handling. Compatible with any platform using the
 * standard Fetch API: Cloudflare Workers, Deno Deploy, Bun, etc.
 *
 * @param sigil - Initialized SigilInstance
 * @param handler - The underlying request handler to protect
 * @param options - Middleware configuration options
 * @returns A new FetchHandler with Sigil protection
 *
 * @example
 * ```typescript
 * import { createSigil } from '@sigil-security/runtime'
 * import { createFetchMiddleware } from '@sigil-security/runtime/fetch'
 *
 * const sigil = await createSigil({ ... })
 *
 * const handler = (request: Request) => new Response('OK')
 * const protectedHandler = createFetchMiddleware(sigil, handler)
 *
 * // Cloudflare Workers
 * export default { fetch: protectedHandler }
 * ```
 */
export function createFetchMiddleware(
  sigil: SigilInstance,
  handler: FetchHandler,
  options?: MiddlewareOptions,
): FetchHandler {
  const excludePaths = normalizePathSet(options?.excludePaths ?? [])
  const tokenEndpointPath = normalizePath(options?.tokenEndpointPath ?? DEFAULT_TOKEN_ENDPOINT_PATH)
  const oneShotEndpointPath = normalizePath(options?.oneShotEndpointPath ?? DEFAULT_ONESHOT_ENDPOINT_PATH)

  return async (request: Request): Promise<Response> => {
    const path = normalizePath(extractPathname(request))
    const method = request.method.toUpperCase()

    // Skip excluded paths (normalized comparison)
    if (excludePaths.has(path)) {
      return handler(request)
    }

    // Step 1: Handle token endpoint requests
    let body: Record<string, unknown> | undefined
    if (method === 'POST' && path === oneShotEndpointPath) {
      try {
        body = (await request.clone().json()) as Record<string, unknown>
      } catch {
        // Body parsing failed
      }
    }

    const csrfTokenValue = request.headers.get(sigil.config.headerName)

    const tokenResult = await handleTokenEndpoint(
      sigil,
      method,
      path,
      body,
      tokenEndpointPath,
      oneShotEndpointPath,
      csrfTokenValue,
    )

    if (tokenResult !== null) {
      return new Response(JSON.stringify(tokenResult.body), {
        status: tokenResult.status,
        headers: {
          'content-type': 'application/json',
          ...tokenResult.headers,
        },
      })
    }

    // Step 2: Extract metadata for protection
    const getHeader = createFetchHeaderGetter(request.headers)
    const contentType = parseContentType(getHeader('content-type'))

    // Try to get body for token extraction (clone to preserve original).
    // Supports both JSON and form-encoded bodies via the Fetch API.
    let protectionBody: Record<string, unknown> | undefined
    if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
      if (contentType !== null && contentType.includes('application/json')) {
        try {
          protectionBody = (await request.clone().json()) as Record<string, unknown>
        } catch {
          // Body not valid JSON — token might be in header
        }
      } else if (
        contentType !== null &&
        contentType.includes('application/x-www-form-urlencoded')
      ) {
        try {
          const cloned = request.clone()
          const text = await cloned.text()
          const params = new URLSearchParams(text)
          const formObj: Record<string, unknown> = {}
          params.forEach((val, key) => {
            formObj[key] = val
          })
          protectionBody = formObj
        } catch {
          // Form body parsing failed — token might be in header
        }
      }
    }

    const tokenSource = resolveTokenSource(
      getHeader,
      protectionBody,
      contentType,
      sigil.config.headerName,
    )

    const metadata = extractRequestMetadata(method, getHeader, tokenSource)

    // Step 3: Run protection
    const result: ProtectResult = await sigil.protect(metadata)

    if (!result.allowed) {
      const errorResponse = createErrorResponse(result.expired)
      return new Response(JSON.stringify(errorResponse.body), {
        status: errorResponse.status,
        headers: {
          'content-type': 'application/json',
          ...errorResponse.headers,
        },
      })
    }

    // Step 4: Request allowed — forward to handler
    return handler(request)
  }
}

/**
 * Creates a standalone token endpoint handler using the Fetch API.
 *
 * Unlike `createFetchMiddleware`, this does NOT wrap another handler.
 * It only handles token generation requests and returns 404 for everything else.
 *
 * @param sigil - Initialized SigilInstance
 * @param options - Middleware configuration options
 * @returns FetchHandler for token endpoints only
 */
export function createFetchTokenEndpoint(
  sigil: SigilInstance,
  options?: MiddlewareOptions,
): FetchHandler {
  const tokenEndpointPath = normalizePath(options?.tokenEndpointPath ?? DEFAULT_TOKEN_ENDPOINT_PATH)
  const oneShotEndpointPath = normalizePath(options?.oneShotEndpointPath ?? DEFAULT_ONESHOT_ENDPOINT_PATH)

  return async (request: Request): Promise<Response> => {
    const path = normalizePath(extractPathname(request))
    const method = request.method.toUpperCase()

    let body: Record<string, unknown> | undefined
    if (method === 'POST') {
      try {
        body = (await request.json()) as Record<string, unknown>
      } catch {
        // Body parsing failed
      }
    }

    const csrfTokenValue = request.headers.get(sigil.config.headerName)

    const result = await handleTokenEndpoint(
      sigil,
      method,
      path,
      body,
      tokenEndpointPath,
      oneShotEndpointPath,
      csrfTokenValue,
    )

    if (result !== null) {
      return new Response(JSON.stringify(result.body), {
        status: result.status,
        headers: {
          'content-type': 'application/json',
          ...result.headers,
        },
      })
    }

    return new Response(JSON.stringify({ error: 'Not found' }), {
      status: 404,
      headers: { 'content-type': 'application/json' },
    })
  }
}
