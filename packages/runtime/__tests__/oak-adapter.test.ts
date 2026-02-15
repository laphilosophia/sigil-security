import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { OakLikeContext } from '../src/adapters/oak.js'
import { createOakMiddleware } from '../src/adapters/oak.js'
import { createSigil } from '../src/sigil.js'
import type { SigilInstance } from '../src/types.js'

// ============================================================
// Mock Oak Helpers
// ============================================================

function mockOakContext(
  overrides: {
    method?: string
    pathname?: string
    headers?: Record<string, string>
    bodyType?: string
    bodyValue?: unknown
    sourceUrl?: string
    originalRequestUrl?: string
    requestUrl?: URL
  } = {},
): OakLikeContext & {
  _responseStatus: number
  _responseBody: unknown
  _responseHeaders: Headers
} {
  const requestHeaders = new Headers(overrides.headers ?? {})
  const responseHeaders = new Headers()

  const ctx = {
    _responseStatus: 200,
    _responseBody: undefined as unknown,
    _responseHeaders: responseHeaders,
    request: {
      method: overrides.method ?? 'GET',
      url: overrides.requestUrl ?? new URL(`https://example.com${overrides.pathname ?? '/'}`),
      ...(overrides.sourceUrl ? { source: new Request(overrides.sourceUrl) } : {}),
      ...(overrides.originalRequestUrl
        ? { originalRequest: { url: overrides.originalRequestUrl } }
        : {}),
      headers: requestHeaders,
      body: () => ({
        type: overrides.bodyType,
        value: Promise.resolve(overrides.bodyValue),
      }),
    },
    response: {
      get status() {
        return ctx._responseStatus
      },
      set status(val: number) {
        ctx._responseStatus = val
      },
      get body() {
        return ctx._responseBody
      },
      set body(val: unknown) {
        ctx._responseBody = val
      },
      headers: responseHeaders,
    },
  }
  return ctx as unknown as typeof ctx
}

// ============================================================
// Tests
// ============================================================

describe('oak-adapter', () => {
  const masterSecret = 'test-master-secret-at-least-32-bytes-long!'
  let sigil: SigilInstance

  beforeEach(async () => {
    sigil = await createSigil({
      masterSecret,
      allowedOrigins: ['https://example.com'],
    })
  })

  describe('createOakMiddleware', () => {
    it('should pass through GET requests', async () => {
      const middleware = createOakMiddleware(sigil)
      const ctx = mockOakContext({ method: 'GET', pathname: '/page' })
      const next = vi.fn().mockResolvedValue(undefined)

      await middleware(ctx, next)

      expect(next).toHaveBeenCalled()
    })

    it('should handle token generation endpoint', async () => {
      const middleware = createOakMiddleware(sigil)
      const ctx = mockOakContext({
        method: 'GET',
        pathname: '/api/csrf/token',
      })
      const next = vi.fn().mockResolvedValue(undefined)

      await middleware(ctx, next)

      expect(next).not.toHaveBeenCalled()
      expect(ctx._responseStatus).toBe(200)
      const body = ctx._responseBody as Record<string, unknown>
      expect(body).toHaveProperty('token')
      expect(body).toHaveProperty('expiresAt')
    })

    it('should reject POST without token', async () => {
      const middleware = createOakMiddleware(sigil)
      const ctx = mockOakContext({
        method: 'POST',
        pathname: '/api/data',
        headers: {
          origin: 'https://example.com',
          'sec-fetch-site': 'same-origin',
          'content-type': 'application/json',
        },
      })
      const next = vi.fn().mockResolvedValue(undefined)

      await middleware(ctx, next)

      expect(next).not.toHaveBeenCalled()
      expect(ctx._responseStatus).toBe(403)
      expect(ctx._responseBody).toEqual({ error: 'CSRF validation failed' })
    })

    it('should allow POST with valid token in header', async () => {
      const gen = await sigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const middleware = createOakMiddleware(sigil)
      const ctx = mockOakContext({
        method: 'POST',
        pathname: '/api/data',
        headers: {
          origin: 'https://example.com',
          'sec-fetch-site': 'same-origin',
          'content-type': 'application/json',
          'x-csrf-token': gen.token,
        },
      })
      const next = vi.fn().mockResolvedValue(undefined)

      await middleware(ctx, next)

      expect(next).toHaveBeenCalled()
    })

    it('should extract token from JSON body', async () => {
      const gen = await sigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const middleware = createOakMiddleware(sigil)
      const ctx = mockOakContext({
        method: 'POST',
        pathname: '/api/data',
        headers: {
          origin: 'https://example.com',
          'sec-fetch-site': 'same-origin',
          'content-type': 'application/json',
        },
        bodyType: 'json',
        bodyValue: { csrf_token: gen.token },
      })
      const next = vi.fn().mockResolvedValue(undefined)

      await middleware(ctx, next)

      expect(next).toHaveBeenCalled()
    })

    it('should extract token from form body', async () => {
      const gen = await sigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      // Oak returns URLSearchParams for 'form' body type
      const formParams = new URLSearchParams()
      formParams.set('csrf_token', gen.token)

      const middleware = createOakMiddleware(sigil)
      const ctx = mockOakContext({
        method: 'POST',
        pathname: '/api/data',
        headers: {
          origin: 'https://example.com',
          'sec-fetch-site': 'same-origin',
          'content-type': 'application/x-www-form-urlencoded',
        },
        bodyType: 'form',
        bodyValue: formParams,
      })
      const next = vi.fn().mockResolvedValue(undefined)

      await middleware(ctx, next)

      expect(next).toHaveBeenCalled()
    })

    it('should skip excluded paths', async () => {
      const middleware = createOakMiddleware(sigil, {
        excludePaths: ['/health'],
      })
      const ctx = mockOakContext({ method: 'POST', pathname: '/health' })
      const next = vi.fn().mockResolvedValue(undefined)

      await middleware(ctx, next)

      expect(next).toHaveBeenCalled()
    })

    it('should set X-CSRF-Token-Expired header for expired tokens', async () => {
      const shortSigil = await createSigil({
        masterSecret,
        allowedOrigins: ['https://example.com'],
        tokenTTL: 1,
        graceWindow: 0,
      })

      const gen = await shortSigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      await new Promise((resolve) => setTimeout(resolve, 10))

      const middleware = createOakMiddleware(shortSigil)
      const ctx = mockOakContext({
        method: 'POST',
        pathname: '/api/data',
        headers: {
          origin: 'https://example.com',
          'sec-fetch-site': 'same-origin',
          'content-type': 'application/json',
          'x-csrf-token': gen.token,
        },
      })
      const next = vi.fn().mockResolvedValue(undefined)

      await middleware(ctx, next)

      expect(ctx._responseStatus).toBe(403)
      expect(ctx._responseHeaders.get('X-CSRF-Token-Expired')).toBe('true')
    })

    it('should avoid request.url getter when source URL is available', async () => {
      const middleware = createOakMiddleware(sigil)
      const ctx = mockOakContext({
        method: 'GET',
        sourceUrl: 'https://example.com/page',
      })
      Object.defineProperty(ctx.request, 'url', {
        get() {
          throw new Error('request.url should not be accessed')
        },
      })
      const next = vi.fn().mockResolvedValue(undefined)

      await middleware(ctx, next)

      expect(next).toHaveBeenCalled()
    })
  })
})
