// @sigil-security/runtime — Oak middleware adapter (Deno)
// Reference: SPECIFICATION.md §3

import type { SigilInstance, MiddlewareOptions } from '../types.js'
import { DEFAULT_TOKEN_ENDPOINT_PATH, DEFAULT_ONESHOT_ENDPOINT_PATH } from '../types.js'
import { extractRequestMetadata, resolveTokenSource, parseContentType, normalizePath, normalizePathSet } from '../extract-metadata.js'
import type { HeaderGetter } from '../extract-metadata.js'
import { createErrorResponse } from '../error-response.js'
import { handleTokenEndpoint } from '../token-endpoint.js'

// ============================================================
// Minimal Oak-Compatible Types
// ============================================================

/** Minimal Oak-compatible context */
export interface OakLikeContext {
  readonly request: {
    readonly method: string
    readonly url: URL
    readonly headers: Headers
    body: () => OakBody
  }
  response: {
    status: number
    body: unknown
    headers: Headers
  }
}

/** Oak body reader */
export interface OakBody {
  readonly type: string | undefined
  value: Promise<unknown>
}

/** Oak next function */
export type OakNext = () => Promise<unknown>

/** Oak middleware signature */
export type OakMiddleware = (ctx: OakLikeContext, next: OakNext) => Promise<void>

// ============================================================
// Header Getter for Oak
// ============================================================

function createOakHeaderGetter(headers: Headers): HeaderGetter {
  return (name: string): string | null => {
    return headers.get(name.toLowerCase())
  }
}

// ============================================================
// Oak Middleware Factory
// ============================================================

/**
 * Creates Oak middleware for Sigil CSRF protection (Deno).
 *
 * @param sigil - Initialized SigilInstance
 * @param options - Middleware configuration options
 * @returns Oak middleware function
 *
 * @example
 * ```typescript
 * import { Application } from '@oak/oak'
 * import { createSigil } from '@sigil-security/runtime'
 * import { createOakMiddleware } from '@sigil-security/runtime/oak'
 *
 * const sigil = await createSigil({ ... })
 * const app = new Application()
 * app.use(createOakMiddleware(sigil))
 * ```
 */
export function createOakMiddleware(
  sigil: SigilInstance,
  options?: MiddlewareOptions,
): OakMiddleware {
  const excludePaths = normalizePathSet(options?.excludePaths ?? [])
  const tokenEndpointPath = normalizePath(options?.tokenEndpointPath ?? DEFAULT_TOKEN_ENDPOINT_PATH)
  const oneShotEndpointPath = normalizePath(options?.oneShotEndpointPath ?? DEFAULT_ONESHOT_ENDPOINT_PATH)

  return async (ctx, next) => {
    const path = normalizePath(ctx.request.url.pathname)

    // Skip excluded paths (normalized comparison)
    if (excludePaths.has(path)) {
      await next()
      return
    }

    // Step 1: Handle token endpoint requests
    let body: Record<string, unknown> | undefined
    const method = ctx.request.method.toUpperCase()

    if (method === 'POST' && path === oneShotEndpointPath) {
      try {
        const bodyReader = ctx.request.body()
        if (bodyReader.type === 'json') {
          const value = await bodyReader.value
          if (typeof value === 'object' && value !== null) {
            body = value as Record<string, unknown>
          }
        }
      } catch {
        // Body parsing failed
      }
    }

    const getHeaderForToken = createOakHeaderGetter(ctx.request.headers)
    const csrfTokenValue = getHeaderForToken(sigil.config.headerName)

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
      ctx.response.status = tokenResult.status
      ctx.response.body = tokenResult.body
      for (const [key, value] of Object.entries(tokenResult.headers)) {
        ctx.response.headers.set(key, value)
      }
      return
    }

    // Step 2: Extract metadata for protection
    const getHeader = createOakHeaderGetter(ctx.request.headers)
    const contentType = parseContentType(getHeader('content-type'))

    // Try to extract body for token resolution.
    // Supports both JSON and form-encoded bodies via Oak's body reader.
    let protectionBody: Record<string, unknown> | undefined
    if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS' && body === undefined) {
      try {
        const bodyReader = ctx.request.body()
        if (bodyReader.type === 'json') {
          const value = await bodyReader.value
          if (typeof value === 'object' && value !== null) {
            protectionBody = value as Record<string, unknown>
          }
        } else if (bodyReader.type === 'form') {
          const formData = await bodyReader.value as URLSearchParams
          const formObj: Record<string, unknown> = {}
          formData.forEach((val, key) => {
            formObj[key] = val
          })
          protectionBody = formObj
        }
      } catch {
        // Body not available or parsing failed — token might be in header
      }
    } else {
      protectionBody = body
    }

    const tokenSource = resolveTokenSource(
      getHeader,
      protectionBody,
      contentType,
      sigil.config.headerName,
    )

    const metadata = extractRequestMetadata(method, getHeader, tokenSource)

    // Step 3: Run protection
    const result = await sigil.protect(metadata)

    if (!result.allowed) {
      const errorResponse = createErrorResponse(result.expired)
      ctx.response.status = errorResponse.status
      ctx.response.body = errorResponse.body
      for (const [key, value] of Object.entries(errorResponse.headers)) {
        ctx.response.headers.set(key, value)
      }
      return
    }

    // Step 4: Request allowed — continue
    await next()
  }
}
