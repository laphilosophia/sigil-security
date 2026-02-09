import { describe, it, expect, beforeEach } from 'vitest'
import { createSigil } from '../src/sigil.js'
import { createFetchMiddleware, createFetchTokenEndpoint } from '../src/adapters/fetch.js'
import type { SigilInstance } from '../src/types.js'

describe('fetch-adapter', () => {
  const masterSecret = 'test-master-secret-at-least-32-bytes-long!'
  let sigil: SigilInstance

  beforeEach(async () => {
    sigil = await createSigil({
      masterSecret,
      allowedOrigins: ['https://example.com'],
    })
  })

  describe('createFetchMiddleware', () => {
    const baseHandler = (): Response =>
      new Response(JSON.stringify({ ok: true }), {
        headers: { 'content-type': 'application/json' },
      })

    it('should pass through GET requests', async () => {
      const handler = createFetchMiddleware(sigil, baseHandler)
      const request = new Request('https://example.com/page', { method: 'GET' })

      const response = await handler(request)
      expect(response.status).toBe(200)

      const body = (await response.json()) as Record<string, unknown>
      expect(body).toEqual({ ok: true })
    })

    it('should handle token generation endpoint', async () => {
      const handler = createFetchMiddleware(sigil, baseHandler)
      const request = new Request('https://example.com/api/csrf/token', {
        method: 'GET',
      })

      const response = await handler(request)
      expect(response.status).toBe(200)

      const body = (await response.json()) as Record<string, unknown>
      expect(body).toHaveProperty('token')
      expect(body).toHaveProperty('expiresAt')
    })

    it('should reject POST without token', async () => {
      const handler = createFetchMiddleware(sigil, baseHandler)
      const request = new Request('https://example.com/api/data', {
        method: 'POST',
        headers: {
          'origin': 'https://example.com',
          'sec-fetch-site': 'same-origin',
          'content-type': 'application/json',
        },
        body: JSON.stringify({ data: 'test' }),
      })

      const response = await handler(request)
      expect(response.status).toBe(403)

      const body = (await response.json()) as Record<string, unknown>
      expect(body).toEqual({ error: 'CSRF validation failed' })
    })

    it('should allow POST with valid token in header', async () => {
      const gen = await sigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const handler = createFetchMiddleware(sigil, baseHandler)
      const request = new Request('https://example.com/api/data', {
        method: 'POST',
        headers: {
          'origin': 'https://example.com',
          'sec-fetch-site': 'same-origin',
          'content-type': 'application/json',
          'x-csrf-token': gen.token,
        },
        body: JSON.stringify({ data: 'test' }),
      })

      const response = await handler(request)
      expect(response.status).toBe(200)

      const body = (await response.json()) as Record<string, unknown>
      expect(body).toEqual({ ok: true })
    })

    it('should skip excluded paths', async () => {
      const handler = createFetchMiddleware(sigil, baseHandler, {
        excludePaths: ['/health'],
      })
      const request = new Request('https://example.com/health', {
        method: 'POST',
        body: JSON.stringify({}),
      })

      const response = await handler(request)
      expect(response.status).toBe(200)

      const body = (await response.json()) as Record<string, unknown>
      expect(body).toEqual({ ok: true })
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

      const handler = createFetchMiddleware(shortSigil, baseHandler)
      const request = new Request('https://example.com/api/data', {
        method: 'POST',
        headers: {
          'origin': 'https://example.com',
          'sec-fetch-site': 'same-origin',
          'content-type': 'application/json',
          'x-csrf-token': gen.token,
        },
        body: JSON.stringify({}),
      })

      const response = await handler(request)
      expect(response.status).toBe(403)
      expect(response.headers.get('X-CSRF-Token-Expired')).toBe('true')
    })
  })

  describe('createFetchTokenEndpoint', () => {
    it('should handle token generation', async () => {
      const handler = createFetchTokenEndpoint(sigil)
      const request = new Request('https://example.com/api/csrf/token', {
        method: 'GET',
      })

      const response = await handler(request)
      expect(response.status).toBe(200)

      const body = (await response.json()) as Record<string, unknown>
      expect(body).toHaveProperty('token')
    })

    it('should return 404 for non-token paths', async () => {
      const handler = createFetchTokenEndpoint(sigil)
      const request = new Request('https://example.com/other', {
        method: 'GET',
      })

      const response = await handler(request)
      expect(response.status).toBe(404)
    })
  })
})
