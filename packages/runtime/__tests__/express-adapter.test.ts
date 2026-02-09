import { describe, it, expect, beforeEach, vi } from 'vitest'
import { createSigil } from '../src/sigil.js'
import { createExpressMiddleware } from '../src/adapters/express.js'
import type { ExpressLikeRequest, ExpressLikeResponse } from '../src/adapters/express.js'
import type { SigilInstance } from '../src/types.js'

/** Creates a mock Express request */
function mockRequest(overrides: Partial<ExpressLikeRequest> = {}): ExpressLikeRequest {
  return {
    method: 'GET',
    path: '/',
    headers: {},
    ...overrides,
  }
}

/**
 * Creates a mock Express response with chainable methods.
 * Returns a promise that resolves when `json()` is called (response sent).
 */
function mockResponse(): ExpressLikeResponse & {
  _status: number
  _body: unknown
  _headers: Record<string, string>
  _settled: Promise<void>
} {
  let resolve: () => void
  const settled = new Promise<void>((r) => {
    resolve = r
  })

  const res = {
    _status: 200,
    _body: null as unknown,
    _headers: {} as Record<string, string>,
    _settled: settled,
    headersSent: false,
    status(code: number) {
      res._status = code
      return res
    },
    json(body: unknown) {
      res._body = body
      resolve()
      return res
    },
    setHeader(name: string, value: string) {
      res._headers[name] = value
      return res
    },
  }
  return res
}

/**
 * Helper: invokes Express middleware and waits for completion.
 * Returns a promise that resolves when either:
 * - next() is called (request passed through), or
 * - res.json() is called (response sent)
 */
function invokeMiddleware(
  middleware: ReturnType<typeof createExpressMiddleware>,
  req: ExpressLikeRequest,
  res: ReturnType<typeof mockResponse>,
): Promise<{ nextCalled: boolean; nextError?: unknown }> {
  return new Promise((resolve) => {
    const next = (err?: unknown) => {
      resolve({ nextCalled: true, nextError: err })
    }

    // Also resolve when response is sent
    res._settled.then(() => {
      resolve({ nextCalled: false })
    })

    middleware(req, res, next)
  })
}

describe('express-adapter', () => {
  const masterSecret = 'test-master-secret-at-least-32-bytes-long!'
  let sigil: SigilInstance

  beforeEach(async () => {
    sigil = await createSigil({
      masterSecret,
      allowedOrigins: ['https://example.com'],
    })
  })

  describe('createExpressMiddleware', () => {
    it('should pass through GET requests', async () => {
      const middleware = createExpressMiddleware(sigil)
      const req = mockRequest({ method: 'GET', path: '/page' })
      const res = mockResponse()

      const result = await invokeMiddleware(middleware, req, res)

      expect(result.nextCalled).toBe(true)
    })

    it('should reject POST requests without token', async () => {
      const middleware = createExpressMiddleware(sigil)
      const req = mockRequest({
        method: 'POST',
        path: '/api/data',
        headers: {
          origin: 'https://example.com',
          'sec-fetch-site': 'same-origin',
          'content-type': 'application/json',
        },
      })
      const res = mockResponse()

      const result = await invokeMiddleware(middleware, req, res)

      expect(result.nextCalled).toBe(false)
      expect(res._status).toBe(403)
      expect(res._body).toEqual({ error: 'CSRF validation failed' })
    })

    it('should allow POST with valid token', async () => {
      const gen = await sigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const middleware = createExpressMiddleware(sigil)
      const req = mockRequest({
        method: 'POST',
        path: '/api/data',
        headers: {
          origin: 'https://example.com',
          'sec-fetch-site': 'same-origin',
          'content-type': 'application/json',
          'x-csrf-token': gen.token,
        },
      })
      const res = mockResponse()

      const result = await invokeMiddleware(middleware, req, res)

      expect(result.nextCalled).toBe(true)
    })

    it('should handle token generation endpoint', async () => {
      const middleware = createExpressMiddleware(sigil)
      const req = mockRequest({
        method: 'GET',
        path: '/api/csrf/token',
        headers: {},
      })
      const res = mockResponse()

      const result = await invokeMiddleware(middleware, req, res)

      expect(result.nextCalled).toBe(false) // Should not pass through
      expect(res._status).toBe(200)
      expect(res._body).toHaveProperty('token')
      expect(res._body).toHaveProperty('expiresAt')
    })

    it('should skip excluded paths', async () => {
      const middleware = createExpressMiddleware(sigil, {
        excludePaths: ['/health', '/metrics'],
      })
      const req = mockRequest({ method: 'POST', path: '/health' })
      const res = mockResponse()

      const result = await invokeMiddleware(middleware, req, res)

      expect(result.nextCalled).toBe(true)
    })

    it('should handle custom token endpoint path', async () => {
      const middleware = createExpressMiddleware(sigil, {
        tokenEndpointPath: '/custom/token',
      })
      const req = mockRequest({
        method: 'GET',
        path: '/custom/token',
      })
      const res = mockResponse()

      const result = await invokeMiddleware(middleware, req, res)

      expect(result.nextCalled).toBe(false)
      expect(res._status).toBe(200)
      expect(res._body).toHaveProperty('token')
    })

    it('should extract token from request body (JSON)', async () => {
      const gen = await sigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const middleware = createExpressMiddleware(sigil)
      const req = mockRequest({
        method: 'POST',
        path: '/api/data',
        headers: {
          origin: 'https://example.com',
          'sec-fetch-site': 'same-origin',
          'content-type': 'application/json',
        },
        body: { csrf_token: gen.token },
      })
      const res = mockResponse()

      const result = await invokeMiddleware(middleware, req, res)

      expect(result.nextCalled).toBe(true)
    })

    it('should return uniform 403 for expired tokens', async () => {
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

      const middleware = createExpressMiddleware(shortSigil)
      const req = mockRequest({
        method: 'POST',
        path: '/api/data',
        headers: {
          origin: 'https://example.com',
          'sec-fetch-site': 'same-origin',
          'content-type': 'application/json',
          'x-csrf-token': gen.token,
        },
      })
      const res = mockResponse()

      const result = await invokeMiddleware(middleware, req, res)

      expect(result.nextCalled).toBe(false)
      expect(res._status).toBe(403)
      expect(res._body).toEqual({ error: 'CSRF validation failed' })
      expect(res._headers['X-CSRF-Token-Expired']).toBe('true')
    })

    it('should forward errors to next()', async () => {
      const middleware = createExpressMiddleware(sigil)
      const req = mockRequest({
        method: 'GET',
        path: '/api/csrf/token',
      })
      const res = mockResponse()

      const result = await invokeMiddleware(middleware, req, res)

      // Should work normally (no error)
      expect(res._status).toBe(200)
    })
  })
})
