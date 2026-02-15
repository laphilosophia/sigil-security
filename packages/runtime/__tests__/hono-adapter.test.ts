import { describe, it, expect, beforeEach, vi } from 'vitest'
import { createSigil } from '../src/sigil.js'
import { createHonoMiddleware } from '../src/adapters/hono.js'
import type { HonoLikeContext } from '../src/adapters/hono.js'
import type { SigilInstance } from '../src/types.js'

// ============================================================
// Mock Hono Helpers
// ============================================================

function mockHonoContext(overrides: {
  method?: string
  path?: string
  headers?: Record<string, string>
  jsonBody?: Record<string, unknown>
  formBody?: Record<string, unknown>
} = {}): HonoLikeContext & { _response: { status: number; body: unknown; headers: Record<string, string> } } {
  const headers = overrides.headers ?? {}
  const ctx = {
    _response: {
      status: 0 as number,
      body: undefined as unknown,
      headers: {} as Record<string, string>,
    },
    req: {
      method: overrides.method ?? 'GET',
      path: overrides.path ?? '/',
      header(name: string): string | undefined {
        return headers[name.toLowerCase()]
      },
      async json(): Promise<Record<string, unknown>> {
        await Promise.resolve()
        if (overrides.jsonBody !== undefined) return overrides.jsonBody
        throw new Error('No JSON body')
      },
      async parseBody(): Promise<Record<string, unknown>> {
        await Promise.resolve()
        if (overrides.formBody !== undefined) return overrides.formBody
        throw new Error('No form body')
      },
    },
    json(body: unknown, status?: number): Response {
      ctx._response.body = body
      ctx._response.status = status ?? 200
      return new Response(JSON.stringify(body), { status: status ?? 200 })
    },
    header(name: string, value: string): void {
      ctx._response.headers[name] = value
    },
  }
  return ctx
}

// ============================================================
// Tests
// ============================================================

describe('hono-adapter', () => {
  const masterSecret = 'test-master-secret-at-least-32-bytes-long!'
  let sigil: SigilInstance

  beforeEach(async () => {
    sigil = await createSigil({
      masterSecret,
      allowedOrigins: ['https://example.com'],
    })
  })

  describe('createHonoMiddleware', () => {
    it('should pass through GET requests', async () => {
      const middleware = createHonoMiddleware(sigil)
      const ctx = mockHonoContext({ method: 'GET', path: '/page' })
      const next = vi.fn().mockResolvedValue(undefined)

      await middleware(ctx, next)

      expect(next).toHaveBeenCalled()
    })

    it('should handle token generation endpoint', async () => {
      const middleware = createHonoMiddleware(sigil)
      const ctx = mockHonoContext({
        method: 'GET',
        path: '/api/csrf/token',
      })
      const next = vi.fn().mockResolvedValue(undefined)

      await middleware(ctx, next)

      expect(next).not.toHaveBeenCalled()
      expect(ctx._response.status).toBe(200)
      expect(ctx._response.body).toHaveProperty('token')
      expect(ctx._response.body).toHaveProperty('expiresAt')
    })

    it('should reject POST without token', async () => {
      const middleware = createHonoMiddleware(sigil)
      const ctx = mockHonoContext({
        method: 'POST',
        path: '/api/data',
        headers: {
          origin: 'https://example.com',
          'sec-fetch-site': 'same-origin',
          'content-type': 'application/json',
        },
      })
      const next = vi.fn().mockResolvedValue(undefined)

      await middleware(ctx, next)

      expect(next).not.toHaveBeenCalled()
      expect(ctx._response.status).toBe(403)
      expect(ctx._response.body).toEqual({ error: 'CSRF validation failed' })
    })

    it('should allow POST with valid token in header', async () => {
      const gen = await sigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const middleware = createHonoMiddleware(sigil)
      const ctx = mockHonoContext({
        method: 'POST',
        path: '/api/data',
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

      const middleware = createHonoMiddleware(sigil)
      const ctx = mockHonoContext({
        method: 'POST',
        path: '/api/data',
        headers: {
          origin: 'https://example.com',
          'sec-fetch-site': 'same-origin',
          'content-type': 'application/json',
        },
        jsonBody: { csrf_token: gen.token },
      })
      const next = vi.fn().mockResolvedValue(undefined)

      await middleware(ctx, next)

      expect(next).toHaveBeenCalled()
    })

    it('should extract token from form body via parseBody', async () => {
      const gen = await sigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const middleware = createHonoMiddleware(sigil)
      const ctx = mockHonoContext({
        method: 'POST',
        path: '/api/data',
        headers: {
          origin: 'https://example.com',
          'sec-fetch-site': 'same-origin',
          'content-type': 'application/x-www-form-urlencoded',
        },
        formBody: { csrf_token: gen.token },
      })
      const next = vi.fn().mockResolvedValue(undefined)

      await middleware(ctx, next)

      expect(next).toHaveBeenCalled()
    })

    it('should skip excluded paths', async () => {
      const middleware = createHonoMiddleware(sigil, {
        excludePaths: ['/health'],
      })
      const ctx = mockHonoContext({ method: 'POST', path: '/health' })
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

      const middleware = createHonoMiddleware(shortSigil)
      const ctx = mockHonoContext({
        method: 'POST',
        path: '/api/data',
        headers: {
          origin: 'https://example.com',
          'sec-fetch-site': 'same-origin',
          'content-type': 'application/json',
          'x-csrf-token': gen.token,
        },
      })
      const next = vi.fn().mockResolvedValue(undefined)

      await middleware(ctx, next)

      expect(ctx._response.status).toBe(403)
      expect(ctx._response.headers['X-CSRF-Token-Expired']).toBe('true')
    })
  })
})
