import { describe, it, expect, beforeEach, vi } from 'vitest'
import { createSigil } from '../src/sigil.js'
import { createElysiaPlugin } from '../src/adapters/elysia.js'
import type { ElysiaLikeContext, ElysiaLikeApp } from '../src/adapters/elysia.js'
import type { SigilInstance } from '../src/types.js'

// ============================================================
// Mock Elysia Helpers
// ============================================================

function mockElysiaContext(overrides: {
  method?: string
  path?: string
  headers?: Record<string, string>
  body?: unknown
} = {}): ElysiaLikeContext {
  const method = overrides.method ?? 'GET'
  const path = overrides.path ?? '/'
  const headers = new Headers(overrides.headers ?? {})

  return {
    request: new Request(`https://example.com${path}`, {
      method,
      headers,
    }),
    path,
    body: overrides.body,
    set: {
      status: undefined,
      headers: {},
    },
  }
}

/**
 * Creates a mock Elysia-like app that captures hooks and routes.
 */
function mockElysiaApp(): ElysiaLikeApp & {
  _hooks: { handler: Function }[]
  _routes: { method: string; path: string; handler: Function }[]
  runBeforeHandle: (ctx: ElysiaLikeContext) => Promise<unknown>
  callRoute: (method: string, path: string, ctx: ElysiaLikeContext) => Promise<unknown>
} {
  const app = {
    _hooks: [] as { handler: Function }[],
    _routes: [] as { method: string; path: string; handler: Function }[],
    onBeforeHandle(handler: Function) {
      app._hooks.push({ handler })
      return app
    },
    get(path: string, handler: Function) {
      app._routes.push({ method: 'GET', path, handler })
      return app
    },
    post(path: string, handler: Function) {
      app._routes.push({ method: 'POST', path, handler })
      return app
    },
    async runBeforeHandle(ctx: ElysiaLikeContext) {
      for (const hook of app._hooks) {
        const result = await hook.handler(ctx)
        if (result !== undefined) return result
      }
      return undefined
    },
    async callRoute(method: string, path: string, ctx: ElysiaLikeContext) {
      const route = app._routes.find(
        (r) => r.method === method && r.path === path,
      )
      if (route) {
        return route.handler(ctx)
      }
      return undefined
    },
  }
  return app as unknown as typeof app
}

// ============================================================
// Tests
// ============================================================

describe('elysia-adapter', () => {
  const masterSecret = 'test-master-secret-at-least-32-bytes-long!'
  let sigil: SigilInstance

  beforeEach(async () => {
    sigil = await createSigil({
      masterSecret,
      allowedOrigins: ['https://example.com'],
    })
  })

  describe('createElysiaPlugin', () => {
    it('should register token endpoint route', () => {
      const plugin = createElysiaPlugin(sigil)
      const app = mockElysiaApp()

      plugin(app)

      const tokenRoute = app._routes.find(
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

      const plugin = createElysiaPlugin(oneShotSigil)
      const app = mockElysiaApp()

      plugin(app)

      const oneShotRoute = app._routes.find(
        (r) => r.method === 'POST' && r.path === '/api/csrf/one-shot',
      )
      expect(oneShotRoute).toBeDefined()
    })

    it('should register beforeHandle hook', () => {
      const plugin = createElysiaPlugin(sigil)
      const app = mockElysiaApp()

      plugin(app)

      expect(app._hooks.length).toBeGreaterThan(0)
    })

    it('should generate token via GET route', async () => {
      const plugin = createElysiaPlugin(sigil)
      const app = mockElysiaApp()

      plugin(app)

      const ctx = mockElysiaContext({
        method: 'GET',
        path: '/api/csrf/token',
      })

      const result = await app.callRoute('GET', '/api/csrf/token', ctx) as Record<string, unknown>

      expect(ctx.set.status).toBe(200)
      expect(result).toHaveProperty('token')
      expect(result).toHaveProperty('expiresAt')
    })

    it('should allow GET requests through beforeHandle', async () => {
      const plugin = createElysiaPlugin(sigil)
      const app = mockElysiaApp()

      plugin(app)

      const ctx = mockElysiaContext({ method: 'GET', path: '/page' })
      const result = await app.runBeforeHandle(ctx)

      // Should return undefined (allow through)
      expect(result).toBeUndefined()
    })

    it('should reject POST without token', async () => {
      const plugin = createElysiaPlugin(sigil)
      const app = mockElysiaApp()

      plugin(app)

      const ctx = mockElysiaContext({
        method: 'POST',
        path: '/api/data',
        headers: {
          origin: 'https://example.com',
          'sec-fetch-site': 'same-origin',
          'content-type': 'application/json',
        },
      })

      const result = await app.runBeforeHandle(ctx)

      expect(ctx.set.status).toBe(403)
      expect(result).toEqual({ error: 'CSRF validation failed' })
    })

    it('should allow POST with valid token in header', async () => {
      const gen = await sigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const plugin = createElysiaPlugin(sigil)
      const app = mockElysiaApp()

      plugin(app)

      const ctx = mockElysiaContext({
        method: 'POST',
        path: '/api/data',
        headers: {
          origin: 'https://example.com',
          'sec-fetch-site': 'same-origin',
          'content-type': 'application/json',
          'x-csrf-token': gen.token,
        },
      })

      const result = await app.runBeforeHandle(ctx)

      expect(result).toBeUndefined()
    })

    it('should allow POST with valid token in body', async () => {
      const gen = await sigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const plugin = createElysiaPlugin(sigil)
      const app = mockElysiaApp()

      plugin(app)

      const ctx = mockElysiaContext({
        method: 'POST',
        path: '/api/data',
        headers: {
          origin: 'https://example.com',
          'sec-fetch-site': 'same-origin',
          'content-type': 'application/json',
        },
        body: { csrf_token: gen.token },
      })

      const result = await app.runBeforeHandle(ctx)

      expect(result).toBeUndefined()
    })

    it('should skip excluded paths', async () => {
      const plugin = createElysiaPlugin(sigil, {
        excludePaths: ['/health'],
      })
      const app = mockElysiaApp()

      plugin(app)

      const ctx = mockElysiaContext({ method: 'POST', path: '/health' })
      const result = await app.runBeforeHandle(ctx)

      expect(result).toBeUndefined()
    })

    it('should skip token endpoint paths in beforeHandle', async () => {
      const plugin = createElysiaPlugin(sigil)
      const app = mockElysiaApp()

      plugin(app)

      const ctx = mockElysiaContext({
        method: 'GET',
        path: '/api/csrf/token',
      })

      const result = await app.runBeforeHandle(ctx)

      expect(result).toBeUndefined()
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

      const plugin = createElysiaPlugin(shortSigil)
      const app = mockElysiaApp()

      plugin(app)

      const ctx = mockElysiaContext({
        method: 'POST',
        path: '/api/data',
        headers: {
          origin: 'https://example.com',
          'sec-fetch-site': 'same-origin',
          'content-type': 'application/json',
          'x-csrf-token': gen.token,
        },
      })

      const result = await app.runBeforeHandle(ctx)

      expect(ctx.set.status).toBe(403)
      expect(ctx.set.headers['X-CSRF-Token-Expired']).toBe('true')
    })
  })
})
