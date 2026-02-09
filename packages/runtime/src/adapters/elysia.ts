// @sigil-security/runtime — Elysia plugin adapter (Bun)
// Reference: SPECIFICATION.md §3

import type { SigilInstance, MiddlewareOptions } from '../types.js'
import { DEFAULT_TOKEN_ENDPOINT_PATH, DEFAULT_ONESHOT_ENDPOINT_PATH } from '../types.js'
import { extractRequestMetadata, resolveTokenSource, parseContentType, normalizePath, normalizePathSet } from '../extract-metadata.js'
import type { HeaderGetter } from '../extract-metadata.js'
import { createErrorResponse } from '../error-response.js'
import { handleTokenEndpoint } from '../token-endpoint.js'

// ============================================================
// Minimal Elysia-Compatible Types
// ============================================================

/** Minimal Elysia-compatible context */
export interface ElysiaLikeContext {
  readonly request: Request
  readonly path: string
  body?: unknown
  set: {
    status?: number | undefined
    headers: Record<string, string>
  }
}

/** Elysia plugin builder (minimal, chainable) */
export interface ElysiaLikeApp {
  onBeforeHandle(
    handler: (context: ElysiaLikeContext) => Promise<unknown>,
  ): ElysiaLikeApp
  get(
    path: string,
    handler: (context: ElysiaLikeContext) => Promise<unknown>,
  ): ElysiaLikeApp
  post(
    path: string,
    handler: (context: ElysiaLikeContext) => Promise<unknown>,
  ): ElysiaLikeApp
}

// ============================================================
// Header Getter for Elysia
// ============================================================

function createElysiaHeaderGetter(request: Request): HeaderGetter {
  return (name: string): string | null => {
    return request.headers.get(name.toLowerCase())
  }
}

// ============================================================
// Elysia Plugin Factory
// ============================================================

/**
 * Creates an Elysia plugin for Sigil CSRF protection (Bun).
 *
 * @param sigil - Initialized SigilInstance
 * @param options - Middleware configuration options
 * @returns Function that accepts an Elysia instance and configures it
 *
 * @example
 * ```typescript
 * import { Elysia } from 'elysia'
 * import { createSigil } from '@sigil-security/runtime'
 * import { createElysiaPlugin } from '@sigil-security/runtime/elysia'
 *
 * const sigil = await createSigil({ ... })
 * const app = new Elysia()
 *   .use(createElysiaPlugin(sigil))
 * ```
 */
export function createElysiaPlugin(
  sigil: SigilInstance,
  options?: MiddlewareOptions,
): (app: ElysiaLikeApp) => ElysiaLikeApp {
  const excludePaths = normalizePathSet(options?.excludePaths ?? [])
  const tokenEndpointPath = normalizePath(options?.tokenEndpointPath ?? DEFAULT_TOKEN_ENDPOINT_PATH)
  const oneShotEndpointPath = normalizePath(options?.oneShotEndpointPath ?? DEFAULT_ONESHOT_ENDPOINT_PATH)

  return (app) => {
    // Register token generation routes
    app.get(tokenEndpointPath, async (context) => {
      const result = await handleTokenEndpoint(
        sigil,
        'GET',
        tokenEndpointPath,
        undefined,
        tokenEndpointPath,
        oneShotEndpointPath,
      )

      if (result !== null) {
        context.set.status = result.status
        Object.assign(context.set.headers, result.headers)
        return result.body
      }

      // Should never reach here — route matches token endpoint path
      context.set.status = 404
      return { error: 'Not found' }
    })

    if (sigil.config.oneShotEnabled) {
      app.post(oneShotEndpointPath, async (context) => {
        const body = typeof context.body === 'object' && context.body !== null
          ? (context.body as Record<string, unknown>)
          : undefined

        const getHeader = createElysiaHeaderGetter(context.request)
        const csrfTokenValue = getHeader(sigil.config.headerName)

        const result = await handleTokenEndpoint(
          sigil,
          'POST',
          oneShotEndpointPath,
          body,
          tokenEndpointPath,
          oneShotEndpointPath,
          csrfTokenValue,
        )

        if (result !== null) {
          context.set.status = result.status
          Object.assign(context.set.headers, result.headers)
          return result.body
        }

        // Should never reach here — route matches one-shot endpoint path
        context.set.status = 404
        return { error: 'Not found' }
      })
    }

    // Register beforeHandle hook for CSRF validation
    app.onBeforeHandle(async (context) => {
      const path = normalizePath(context.path)

      // Skip excluded paths (normalized comparison)
      if (excludePaths.has(path)) return undefined

      // Skip token endpoints (handled by routes above)
      if (path === tokenEndpointPath) return undefined
      if (sigil.config.oneShotEnabled && path === oneShotEndpointPath) return undefined

      // Extract metadata
      const getHeader = createElysiaHeaderGetter(context.request)
      const contentType = parseContentType(getHeader('content-type'))

      const body = typeof context.body === 'object' && context.body !== null
        ? (context.body as Record<string, unknown>)
        : undefined

      const tokenSource = resolveTokenSource(
        getHeader,
        body,
        contentType,
        sigil.config.headerName,
      )

      const metadata = extractRequestMetadata(
        context.request.method,
        getHeader,
        tokenSource,
      )

      // Run protection
      const result = await sigil.protect(metadata)

      if (!result.allowed) {
        const errorResponse = createErrorResponse(result.expired)
        context.set.status = errorResponse.status
        Object.assign(context.set.headers, errorResponse.headers)
        return errorResponse.body
      }

      // Allowed — continue to handler
      return undefined
    })

    return app
  }
}
