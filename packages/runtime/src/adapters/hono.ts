// @sigil-security/runtime — Hono middleware adapter
// Reference: SPECIFICATION.md §3

import type { SigilInstance, MiddlewareOptions } from '../types.js'
import { DEFAULT_TOKEN_ENDPOINT_PATH, DEFAULT_ONESHOT_ENDPOINT_PATH } from '../types.js'
import { extractRequestMetadata, resolveTokenSource, parseContentType, normalizePath, normalizePathSet } from '../extract-metadata.js'
import type { HeaderGetter } from '../extract-metadata.js'
import { createErrorResponse } from '../error-response.js'
import { handleTokenEndpoint } from '../token-endpoint.js'

// ============================================================
// Minimal Hono-Compatible Types
// ============================================================

/** Minimal Hono-compatible context */
export interface HonoLikeContext {
  readonly req: {
    readonly method: string
    readonly path: string
    header(name: string): string | undefined
    json(): Promise<Record<string, unknown>>
    parseBody(): Promise<Record<string, unknown>>
  }
  json(body: unknown, status?: number): Response
  header(name: string, value: string): void
}

/** Hono next function */
export type HonoNext = () => Promise<void>

/** Hono middleware handler */
export type HonoMiddleware = (c: HonoLikeContext, next: HonoNext) => Promise<Response | undefined>

// ============================================================
// Header Getter for Hono
// ============================================================

function createHonoHeaderGetter(
  req: HonoLikeContext['req'],
): HeaderGetter {
  return (name: string): string | null => {
    return req.header(name.toLowerCase()) ?? null
  }
}

// ============================================================
// Hono Middleware Factory
// ============================================================

/**
 * Creates Hono middleware for Sigil CSRF protection.
 *
 * @param sigil - Initialized SigilInstance
 * @param options - Middleware configuration options
 * @returns Hono middleware handler
 *
 * @example
 * ```typescript
 * import { Hono } from 'hono'
 * import { createSigil } from '@sigil-security/runtime'
 * import { createHonoMiddleware } from '@sigil-security/runtime/hono'
 *
 * const sigil = await createSigil({ ... })
 * const app = new Hono()
 * app.use('*', createHonoMiddleware(sigil))
 * ```
 */
export function createHonoMiddleware(
  sigil: SigilInstance,
  options?: MiddlewareOptions,
): HonoMiddleware {
  const excludePaths = normalizePathSet(options?.excludePaths ?? [])
  const tokenEndpointPath = normalizePath(options?.tokenEndpointPath ?? DEFAULT_TOKEN_ENDPOINT_PATH)
  const oneShotEndpointPath = normalizePath(options?.oneShotEndpointPath ?? DEFAULT_ONESHOT_ENDPOINT_PATH)

  return async (c, next) => {
    const path = normalizePath(c.req.path)

    // Skip excluded paths (normalized comparison)
    if (excludePaths.has(path)) {
      await next()
      return
    }

    // Step 1: Handle token endpoint requests
    let body: Record<string, unknown> | undefined
    if (c.req.method === 'POST' && path === oneShotEndpointPath) {
      try {
        body = await c.req.json()
      } catch {
        // Body parsing failed — will be handled by endpoint handler
      }
    }

    const getHeaderForToken = createHonoHeaderGetter(c.req)
    const csrfTokenValue = getHeaderForToken(sigil.config.headerName)

    const tokenResult = await handleTokenEndpoint(
      sigil,
      c.req.method,
      path,
      body,
      tokenEndpointPath,
      oneShotEndpointPath,
      csrfTokenValue,
    )

    if (tokenResult !== null) {
      for (const [key, value] of Object.entries(tokenResult.headers)) {
        c.header(key, value)
      }
      return c.json(tokenResult.body, tokenResult.status)
    }

    // Step 2: Extract metadata for protection
    const getHeader = createHonoHeaderGetter(c.req)
    const contentType = parseContentType(getHeader('content-type'))

    // For protection, try to get body for token extraction.
    // Supports both JSON and form-encoded bodies via Hono's parseBody().
    let protectionBody: Record<string, unknown> | undefined
    if (c.req.method !== 'GET' && c.req.method !== 'HEAD' && c.req.method !== 'OPTIONS') {
      if (contentType !== null && contentType.includes('application/json')) {
        try {
          protectionBody = await c.req.json()
        } catch {
          // Body not valid JSON — token might be in header
        }
      } else if (
        contentType !== null &&
        (contentType.includes('application/x-www-form-urlencoded') ||
          contentType.includes('multipart/form-data'))
      ) {
        try {
          protectionBody = await c.req.parseBody() as Record<string, unknown>
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

    const metadata = extractRequestMetadata(c.req.method, getHeader, tokenSource)

    // Step 3: Run protection
    const result = await sigil.protect(metadata)

    if (!result.allowed) {
      const errorResponse = createErrorResponse(result.expired)
      for (const [key, value] of Object.entries(errorResponse.headers)) {
        c.header(key, value)
      }
      return c.json(errorResponse.body, errorResponse.status)
    }

    // Step 4: Request allowed — continue
    await next()
    return undefined
  }
}
