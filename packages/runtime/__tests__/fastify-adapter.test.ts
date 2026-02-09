import { describe, it, expect, beforeEach, vi } from 'vitest'
import { createSigil } from '../src/sigil.js'
import { createFastifyPlugin } from '../src/adapters/fastify.js'
import type { FastifyLikeRequest, FastifyLikeReply, FastifyLikeInstance } from '../src/adapters/fastify.js'
import type { SigilInstance } from '../src/types.js'

// ============================================================
// Mock Fastify Helpers
// ============================================================

function mockRequest(overrides: Partial<FastifyLikeRequest> = {}): FastifyLikeRequest {
  return {
    method: 'GET',
    url: '/',
    headers: {},
    body: undefined,
    ...overrides,
  }
}

function mockReply(): FastifyLikeReply & {
  _status: number
  _body: unknown
  _headers: Record<string, string>
} {
  const reply = {
    _status: 200,
    _body: null as unknown,
    _headers: {} as Record<string, string>,
    sent: false,
    status(code: number) {
      reply._status = code
      return reply
    },
    code(code: number) {
      reply._status = code
      return reply
    },
    send(payload?: unknown) {
      reply._body = payload
      reply.sent = true
      return reply
    },
    header(name: string, value: string) {
      reply._headers[name] = value
      return reply
    },
  }
  return reply
}

/**
 * Creates a minimal mock Fastify instance that captures registered hooks and routes.
 */
function mockFastifyInstance(): FastifyLikeInstance & {
  _hooks: { name: string; handler: Function }[]
  _routes: { method: string; path: string; handler: Function }[]
  runPreHandler: (req: FastifyLikeRequest, reply: FastifyLikeReply) => Promise<void>
  callRoute: (method: string, path: string, req: FastifyLikeRequest, reply: FastifyLikeReply) => Promise<void>
} {
  const instance = {
    _hooks: [] as { name: string; handler: Function }[],
    _routes: [] as { method: string; path: string; handler: Function }[],
    addHook(name: string, handler: Function) {
      instance._hooks.push({ name, handler })
    },
    get(path: string, handler: Function) {
      instance._routes.push({ method: 'GET', path, handler })
    },
    post(path: string, handler: Function) {
      instance._routes.push({ method: 'POST', path, handler })
    },
    async runPreHandler(req: FastifyLikeRequest, reply: FastifyLikeReply) {
      for (const hook of instance._hooks) {
        if (hook.name === 'preHandler') {
          await hook.handler(req, reply)
          if (reply.sent) break
        }
      }
    },
    async callRoute(method: string, path: string, req: FastifyLikeRequest, reply: FastifyLikeReply) {
      const route = instance._routes.find(
        (r) => r.method === method && r.path === path,
      )
      if (route) {
        await route.handler(req, reply)
      }
    },
  }
  return instance as unknown as typeof instance
}

// ============================================================
// Tests
// ============================================================

describe('fastify-adapter', () => {
  const masterSecret = 'test-master-secret-at-least-32-bytes-long!'
  let sigil: SigilInstance

  beforeEach(async () => {
    sigil = await createSigil({
      masterSecret,
      allowedOrigins: ['https://example.com'],
    })
  })

  describe('createFastifyPlugin', () => {
    it('should register token endpoint route', () => {
      const plugin = createFastifyPlugin(sigil)
      const fastify = mockFastifyInstance()
      const done = vi.fn()

      plugin(fastify, undefined, done)

      expect(done).toHaveBeenCalled()
      const tokenRoute = fastify._routes.find(
        (r) => r.method === 'GET' && r.path === '/api/csrf/token',
      )
      expect(tokenRoute).toBeDefined()
    })

    it('should register one-shot route when enabled', async () => {
      const oneShotSigil = await createSigil({
        masterSecret,
        allowedOrigins: ['https://example.com'],
        oneShotEnabled: true,
      })

      const plugin = createFastifyPlugin(oneShotSigil)
      const fastify = mockFastifyInstance()
      const done = vi.fn()

      plugin(fastify, undefined, done)

      const oneShotRoute = fastify._routes.find(
        (r) => r.method === 'POST' && r.path === '/api/csrf/one-shot',
      )
      expect(oneShotRoute).toBeDefined()
    })

    it('should NOT register one-shot route when disabled', () => {
      const plugin = createFastifyPlugin(sigil)
      const fastify = mockFastifyInstance()
      const done = vi.fn()

      plugin(fastify, undefined, done)

      const oneShotRoute = fastify._routes.find(
        (r) => r.method === 'POST' && r.path === '/api/csrf/one-shot',
      )
      expect(oneShotRoute).toBeUndefined()
    })

    it('should register preHandler hook (not onRequest)', () => {
      const plugin = createFastifyPlugin(sigil)
      const fastify = mockFastifyInstance()
      const done = vi.fn()

      plugin(fastify, undefined, done)

      const preHandlerHook = fastify._hooks.find((h) => h.name === 'preHandler')
      expect(preHandlerHook).toBeDefined()

      const onRequestHook = fastify._hooks.find((h) => h.name === 'onRequest')
      expect(onRequestHook).toBeUndefined()
    })

    it('should generate token via registered GET route', async () => {
      const plugin = createFastifyPlugin(sigil)
      const fastify = mockFastifyInstance()
      const done = vi.fn()

      plugin(fastify, undefined, done)

      const req = mockRequest({ method: 'GET', url: '/api/csrf/token' })
      const reply = mockReply()

      await fastify.callRoute('GET', '/api/csrf/token', req, reply)

      expect(reply._status).toBe(200)
      expect(reply._body).toHaveProperty('token')
      expect(reply._body).toHaveProperty('expiresAt')
    })

    it('should allow GET requests through preHandler hook', async () => {
      const plugin = createFastifyPlugin(sigil)
      const fastify = mockFastifyInstance()
      const done = vi.fn()

      plugin(fastify, undefined, done)

      const req = mockRequest({ method: 'GET', url: '/page' })
      const reply = mockReply()

      await fastify.runPreHandler(req, reply)

      // Should not have sent a response (allowed through)
      expect(reply.sent).toBe(false)
    })

    it('should reject POST without token via preHandler hook', async () => {
      const plugin = createFastifyPlugin(sigil)
      const fastify = mockFastifyInstance()
      const done = vi.fn()

      plugin(fastify, undefined, done)

      const req = mockRequest({
        method: 'POST',
        url: '/api/data',
        headers: {
          origin: 'https://example.com',
          'sec-fetch-site': 'same-origin',
          'content-type': 'application/json',
        },
      })
      const reply = mockReply()

      await fastify.runPreHandler(req, reply)

      expect(reply.sent).toBe(true)
      expect(reply._status).toBe(403)
      expect(reply._body).toEqual({ error: 'CSRF validation failed' })
    })

    it('should allow POST with valid token in header', async () => {
      const gen = await sigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const plugin = createFastifyPlugin(sigil)
      const fastify = mockFastifyInstance()
      const done = vi.fn()

      plugin(fastify, undefined, done)

      const req = mockRequest({
        method: 'POST',
        url: '/api/data',
        headers: {
          origin: 'https://example.com',
          'sec-fetch-site': 'same-origin',
          'content-type': 'application/json',
          'x-csrf-token': gen.token,
        },
      })
      const reply = mockReply()

      await fastify.runPreHandler(req, reply)

      expect(reply.sent).toBe(false)
    })

    it('should allow POST with valid token in body (preHandler has access)', async () => {
      const gen = await sigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const plugin = createFastifyPlugin(sigil)
      const fastify = mockFastifyInstance()
      const done = vi.fn()

      plugin(fastify, undefined, done)

      const req = mockRequest({
        method: 'POST',
        url: '/api/data',
        headers: {
          origin: 'https://example.com',
          'sec-fetch-site': 'same-origin',
          'content-type': 'application/json',
        },
        body: { csrf_token: gen.token },
      })
      const reply = mockReply()

      await fastify.runPreHandler(req, reply)

      // preHandler hook runs after body parsing — body token should work
      expect(reply.sent).toBe(false)
    })

    it('should skip excluded paths', async () => {
      const plugin = createFastifyPlugin(sigil, {
        excludePaths: ['/health'],
      })
      const fastify = mockFastifyInstance()
      const done = vi.fn()

      plugin(fastify, undefined, done)

      const req = mockRequest({ method: 'POST', url: '/health' })
      const reply = mockReply()

      await fastify.runPreHandler(req, reply)

      expect(reply.sent).toBe(false)
    })

    it('should skip token endpoint paths in preHandler hook', async () => {
      const plugin = createFastifyPlugin(sigil)
      const fastify = mockFastifyInstance()
      const done = vi.fn()

      plugin(fastify, undefined, done)

      const req = mockRequest({ method: 'GET', url: '/api/csrf/token' })
      const reply = mockReply()

      await fastify.runPreHandler(req, reply)

      // Token endpoint skipped in hook (handled by route)
      expect(reply.sent).toBe(false)
    })

    it('should strip query string from URL for path matching', async () => {
      const plugin = createFastifyPlugin(sigil, {
        excludePaths: ['/health'],
      })
      const fastify = mockFastifyInstance()
      const done = vi.fn()

      plugin(fastify, undefined, done)

      const req = mockRequest({ method: 'POST', url: '/health?check=true' })
      const reply = mockReply()

      await fastify.runPreHandler(req, reply)

      expect(reply.sent).toBe(false)
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

      const plugin = createFastifyPlugin(shortSigil)
      const fastify = mockFastifyInstance()
      const done = vi.fn()

      plugin(fastify, undefined, done)

      const req = mockRequest({
        method: 'POST',
        url: '/api/data',
        headers: {
          origin: 'https://example.com',
          'sec-fetch-site': 'same-origin',
          'content-type': 'application/json',
          'x-csrf-token': gen.token,
        },
      })
      const reply = mockReply()

      await fastify.runPreHandler(req, reply)

      expect(reply.sent).toBe(true)
      expect(reply._status).toBe(403)
      expect(reply._headers['X-CSRF-Token-Expired']).toBe('true')
    })
  })
})
