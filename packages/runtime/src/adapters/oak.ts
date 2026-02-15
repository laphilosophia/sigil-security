// @sigil-security/runtime — Oak middleware adapter (Deno)
// Reference: SPECIFICATION.md §3
//
// CVE-2024-49770 (Oak Context.send): This adapter does NOT use Context.send.
// See docs/SECURITY_ADVISORIES.md for exposure and upgrade guidance.

import { createErrorResponse } from '../error-response.js'
import type { HeaderGetter } from '../extract-metadata.js'
import {
  extractRequestMetadata,
  normalizePath,
  normalizePathSet,
  parseContentType,
  resolveTokenSource,
} from '../extract-metadata.js'
import { handleTokenEndpoint } from '../token-endpoint.js'
import type { MiddlewareOptions, ProtectResult, SigilInstance } from '../types.js'
import { DEFAULT_ONESHOT_ENDPOINT_PATH, DEFAULT_TOKEN_ENDPOINT_PATH } from '../types.js'

// ============================================================
// Minimal Oak-Compatible Types
// ============================================================

/** Minimal Oak-compatible context */
export interface OakLikeContext {
  readonly request: {
    readonly method: string
    readonly url: URL
    readonly source?: Request
    readonly originalRequest?: {
      readonly url?: string
      readonly rawUrl?: string
    }
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

function getOakPathname(request: OakLikeContext['request']): string {
  const sourceUrl = request.source?.url
  if (sourceUrl) {
    return new URL(sourceUrl).pathname
  }

  const rawUrl = request.originalRequest?.rawUrl ?? request.originalRequest?.url
  if (typeof rawUrl === 'string' && rawUrl.length > 0) {
    try {
      return new URL(rawUrl, 'http://localhost').pathname
    } catch {
      // ignore malformed URLs and fallback to oak's parsed URL
    }
  }

  return request.url.pathname
}

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
  const oneShotEndpointPath = normalizePath(
    options?.oneShotEndpointPath ?? DEFAULT_ONESHOT_ENDPOINT_PATH,
  )

  return async (ctx, next) => {
    const path = normalizePath(getOakPathname(ctx.request))

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
          const formData = (await bodyReader.value) as URLSearchParams
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
    const result: ProtectResult = await sigil.protect(metadata)

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
