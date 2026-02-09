// @sigil-security/runtime — Fastify plugin adapter
// Reference: SPECIFICATION.md §3

import type { SigilInstance, MiddlewareOptions } from '../types.js'
import { DEFAULT_TOKEN_ENDPOINT_PATH, DEFAULT_ONESHOT_ENDPOINT_PATH } from '../types.js'
import { extractRequestMetadata, resolveTokenSource, parseContentType, normalizePath, normalizePathSet } from '../extract-metadata.js'
import type { HeaderGetter } from '../extract-metadata.js'
import { createErrorResponse } from '../error-response.js'
import { handleTokenEndpoint } from '../token-endpoint.js'

// ============================================================
// Minimal Fastify-Compatible Types
// ============================================================

/** Minimal Fastify-compatible request */
export interface FastifyLikeRequest {
  readonly method: string
  readonly url: string
  readonly headers: Readonly<Record<string, string | string[] | undefined>>
  body?: unknown
}

/** Minimal Fastify-compatible reply */
export interface FastifyLikeReply {
  status(code: number): FastifyLikeReply
  code(code: number): FastifyLikeReply
  send(payload?: unknown): FastifyLikeReply
  header(name: string, value: string): FastifyLikeReply
  readonly sent: boolean
}

/** Minimal Fastify-compatible instance */
export interface FastifyLikeInstance {
  addHook(
    name: 'preHandler',
    handler: (
      request: FastifyLikeRequest,
      reply: FastifyLikeReply,
    ) => Promise<void>,
  ): void
  get(
    path: string,
    handler: (request: FastifyLikeRequest, reply: FastifyLikeReply) => Promise<void>,
  ): void
  post(
    path: string,
    handler: (request: FastifyLikeRequest, reply: FastifyLikeReply) => Promise<void>,
  ): void
}

/** Fastify plugin done callback */
export type FastifyPluginDone = (err?: Error) => void

/** Fastify plugin signature */
export type FastifyPlugin = (
  fastify: FastifyLikeInstance,
  options: MiddlewareOptions | undefined,
  done: FastifyPluginDone,
) => void

// ============================================================
// Header Getter for Fastify
// ============================================================

function createFastifyHeaderGetter(
  headers: Readonly<Record<string, string | string[] | undefined>>,
): HeaderGetter {
  return (name: string): string | null => {
    const value = headers[name.toLowerCase()]
    if (typeof value === 'string') return value
    if (Array.isArray(value)) return value[0] ?? null
    return null
  }
}

/**
 * Extracts the path portion from a Fastify URL (which may include query strings).
 */
function extractPath(url: string): string {
  const qIndex = url.indexOf('?')
  return qIndex >= 0 ? url.slice(0, qIndex) : url
}

// ============================================================
// Fastify Plugin Factory
// ============================================================

/**
 * Creates a Fastify plugin for Sigil CSRF protection.
 *
 * Registers:
 * - Token generation routes (GET /api/csrf/token, POST /api/csrf/one-shot)
 * - `preHandler` hook for CSRF validation on protected methods (runs after body parsing)
 *
 * @param sigil - Initialized SigilInstance
 * @param options - Middleware configuration options
 * @returns Fastify plugin function
 *
 * @example
 * ```typescript
 * import Fastify from 'fastify'
 * import { createSigil } from '@sigil-security/runtime'
 * import { createFastifyPlugin } from '@sigil-security/runtime/fastify'
 *
 * const sigil = await createSigil({ ... })
 * const fastify = Fastify()
 * fastify.register(createFastifyPlugin(sigil))
 * ```
 */
export function createFastifyPlugin(
  sigil: SigilInstance,
  options?: MiddlewareOptions,
): FastifyPlugin {
  const excludePaths = normalizePathSet(options?.excludePaths ?? [])
  const tokenEndpointPath = normalizePath(options?.tokenEndpointPath ?? DEFAULT_TOKEN_ENDPOINT_PATH)
  const oneShotEndpointPath = normalizePath(options?.oneShotEndpointPath ?? DEFAULT_ONESHOT_ENDPOINT_PATH)

  return (fastify, _opts, done) => {
    // Register token generation routes
    fastify.get(tokenEndpointPath, async (request, reply) => {
      const result = await handleTokenEndpoint(
        sigil,
        request.method,
        tokenEndpointPath,
        undefined,
        tokenEndpointPath,
        oneShotEndpointPath,
      )

      if (result !== null) {
        for (const [key, value] of Object.entries(result.headers)) {
          reply.header(key, value)
        }
        reply.code(result.status).send(result.body)
      }
    })

    if (sigil.config.oneShotEnabled) {
      fastify.post(oneShotEndpointPath, async (request, reply) => {
        const body = typeof request.body === 'object' && request.body !== null
          ? (request.body as Record<string, unknown>)
          : undefined

        const getHeader = createFastifyHeaderGetter(request.headers)
        const csrfTokenValue = getHeader(sigil.config.headerName)

        const result = await handleTokenEndpoint(
          sigil,
          request.method,
          oneShotEndpointPath,
          body,
          tokenEndpointPath,
          oneShotEndpointPath,
          csrfTokenValue,
        )

        if (result !== null) {
          for (const [key, value] of Object.entries(result.headers)) {
            reply.header(key, value)
          }
          reply.code(result.status).send(result.body)
        }
      })
    }

    // Register preHandler hook for CSRF validation
    // NOTE: preHandler runs AFTER body parsing, so request.body is available.
    // onRequest would run BEFORE body parsing — body-based tokens would never work.
    fastify.addHook('preHandler', async (request, reply) => {
      const path = normalizePath(extractPath(request.url))

      // Skip excluded paths (normalized comparison)
      if (excludePaths.has(path)) return

      // Skip token endpoints (handled by routes above)
      if (path === tokenEndpointPath) return
      if (sigil.config.oneShotEnabled && path === oneShotEndpointPath) return

      // Extract metadata
      const getHeader = createFastifyHeaderGetter(request.headers)
      const contentType = parseContentType(getHeader('content-type'))

      const body = typeof request.body === 'object' && request.body !== null
        ? (request.body as Record<string, unknown>)
        : undefined

      const tokenSource = resolveTokenSource(
        getHeader,
        body,
        contentType,
        sigil.config.headerName,
      )

      const metadata = extractRequestMetadata(request.method, getHeader, tokenSource)

      // Run protection
      const result = await sigil.protect(metadata)

      if (!result.allowed) {
        const errorResponse = createErrorResponse(result.expired)
        for (const [key, value] of Object.entries(errorResponse.headers)) {
          reply.header(key, value)
        }
        reply.code(errorResponse.status).send(errorResponse.body)
      }
    })

    done()
  }
}
