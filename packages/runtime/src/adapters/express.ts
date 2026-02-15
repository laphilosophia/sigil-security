// @sigil-security/runtime — Express middleware adapter
// Reference: SPECIFICATION.md §3

import type { SigilInstance, MiddlewareOptions, ProtectResult } from '../types.js'
import { DEFAULT_TOKEN_ENDPOINT_PATH, DEFAULT_ONESHOT_ENDPOINT_PATH } from '../types.js'
import { extractRequestMetadata, resolveTokenSource, parseContentType, normalizePath, normalizePathSet } from '../extract-metadata.js'
import type { HeaderGetter } from '../extract-metadata.js'
import { createErrorResponse } from '../error-response.js'
import { handleTokenEndpoint } from '../token-endpoint.js'

// ============================================================
// Minimal Express-Compatible Types
// ============================================================

/**
 * Minimal Express-compatible request interface.
 * Structurally compatible with `express.Request`.
 */
export interface ExpressLikeRequest {
  readonly method: string
  readonly path: string
  readonly headers: Readonly<Record<string, string | string[] | undefined>>
  body?: Record<string, unknown> | undefined
}

/**
 * Minimal Express-compatible response interface.
 * Structurally compatible with `express.Response`.
 */
export interface ExpressLikeResponse {
  status(code: number): ExpressLikeResponse
  json(body: unknown): ExpressLikeResponse
  setHeader(name: string, value: string): ExpressLikeResponse
  readonly headersSent: boolean
}

/** Express-compatible next function */
export type ExpressNextFunction = (err?: unknown) => void

/** Express middleware signature */
export type ExpressMiddleware = (
  req: ExpressLikeRequest,
  res: ExpressLikeResponse,
  next: ExpressNextFunction,
) => void

// ============================================================
// Header Getter for Express
// ============================================================

function createExpressHeaderGetter(
  headers: Readonly<Record<string, string | string[] | undefined>>,
): HeaderGetter {
  return (name: string): string | null => {
    const value = headers[name.toLowerCase()]
    if (typeof value === 'string') return value
    if (Array.isArray(value)) return value[0] ?? null
    return null
  }
}

// ============================================================
// Express Middleware Factory
// ============================================================

/**
 * Creates Express middleware for Sigil CSRF protection.
 *
 * This middleware:
 * 1. Handles token generation endpoints (GET /api/csrf/token, POST /api/csrf/one-shot)
 * 2. Validates CSRF tokens on protected methods (POST, PUT, PATCH, DELETE)
 * 3. Passes through safe methods (GET, HEAD, OPTIONS) without validation
 * 4. Returns uniform 403 responses on validation failure
 *
 * @param sigil - Initialized SigilInstance
 * @param options - Middleware configuration options
 * @returns Express middleware function
 *
 * @example
 * ```typescript
 * import express from 'express'
 * import { createSigil } from '@sigil-security/runtime'
 * import { createExpressMiddleware } from '@sigil-security/runtime/express'
 *
 * const sigil = await createSigil({
 *   masterSecret: process.env.CSRF_SECRET!,
 *   allowedOrigins: ['https://example.com'],
 * })
 *
 * const app = express()
 * app.use(createExpressMiddleware(sigil))
 * ```
 */
export function createExpressMiddleware(
  sigil: SigilInstance,
  options?: MiddlewareOptions,
): ExpressMiddleware {
  const excludePaths = normalizePathSet(options?.excludePaths ?? [])
  const tokenEndpointPath = normalizePath(options?.tokenEndpointPath ?? DEFAULT_TOKEN_ENDPOINT_PATH)
  const oneShotEndpointPath = normalizePath(options?.oneShotEndpointPath ?? DEFAULT_ONESHOT_ENDPOINT_PATH)

  // Express middleware must NOT be async — errors are caught and forwarded to next()
  return (req, res, next) => {
    // Skip excluded paths (normalized comparison)
    if (excludePaths.has(normalizePath(req.path))) {
      next()
      return
    }

    // Handle async operations with proper error forwarding
    handleRequest(sigil, req, res, next, tokenEndpointPath, oneShotEndpointPath).catch(next)
  }
}

/**
 * Internal async handler for Express requests.
 */
async function handleRequest(
  sigil: SigilInstance,
  req: ExpressLikeRequest,
  res: ExpressLikeResponse,
  next: ExpressNextFunction,
  tokenEndpointPath: string,
  oneShotEndpointPath: string,
): Promise<void> {
  // Step 1: Check if this is a token endpoint request
  const reqPath = normalizePath(req.path)
  const getHeaderForToken = createExpressHeaderGetter(req.headers)
  const csrfTokenValue = getHeaderForToken(sigil.config.headerName)

  const tokenResult = await handleTokenEndpoint(
    sigil,
    req.method,
    reqPath,
    req.body,
    tokenEndpointPath,
    oneShotEndpointPath,
    csrfTokenValue,
  )

  if (tokenResult !== null) {
    for (const [key, value] of Object.entries(tokenResult.headers)) {
      res.setHeader(key, value)
    }
    res.status(tokenResult.status).json(tokenResult.body)
    return
  }

  // Step 2: Extract metadata for protection
  const getHeader = createExpressHeaderGetter(req.headers)
  const contentType = parseContentType(getHeader('content-type'))

  const tokenSource = resolveTokenSource(
    getHeader,
    req.body,
    contentType,
    sigil.config.headerName,
  )

  const metadata = extractRequestMetadata(req.method, getHeader, tokenSource)

  // Step 3: Run protection
  const result: ProtectResult = await sigil.protect(metadata)

  if (!result.allowed) {
    const errorResponse = createErrorResponse(result.expired)
    for (const [key, value] of Object.entries(errorResponse.headers)) {
      res.setHeader(key, value)
    }
    res.status(errorResponse.status).json(errorResponse.body)
    return
  }

  // Step 4: Request allowed — continue
  next()
}
