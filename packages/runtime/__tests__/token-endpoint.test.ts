import { describe, it, expect, beforeEach } from 'vitest'
import { createSigil } from '../src/sigil.js'
import { handleTokenEndpoint } from '../src/token-endpoint.js'
import type { SigilInstance } from '../src/types.js'

describe('token-endpoint', () => {
  const masterSecret = 'test-master-secret-at-least-32-bytes-long!'
  let sigil: SigilInstance

  beforeEach(async () => {
    sigil = await createSigil({
      masterSecret,
      allowedOrigins: ['https://example.com'],
      oneShotEnabled: true,
    })
  })

  describe('regular token generation', () => {
    it('should generate token on GET /api/csrf/token', async () => {
      const result = await handleTokenEndpoint(
        sigil,
        'GET',
        '/api/csrf/token',
        undefined,
        '/api/csrf/token',
        '/api/csrf/one-shot',
      )

      expect(result).not.toBeNull()
      expect(result!.handled).toBe(true)
      expect(result!.status).toBe(200)
      expect(result!.body).toHaveProperty('token')
      expect(result!.body).toHaveProperty('expiresAt')
    })

    it('should return null for non-matching paths', async () => {
      const result = await handleTokenEndpoint(
        sigil,
        'GET',
        '/api/other',
        undefined,
        '/api/csrf/token',
        '/api/csrf/one-shot',
      )

      expect(result).toBeNull()
    })

    it('should return null for POST to token path', async () => {
      const result = await handleTokenEndpoint(
        sigil,
        'POST',
        '/api/csrf/token',
        undefined,
        '/api/csrf/token',
        '/api/csrf/one-shot',
      )

      expect(result).toBeNull()
    })
  })

  describe('one-shot token generation', () => {
    it('should generate one-shot token when CSRF token is provided (M2 fix)', async () => {
      // First generate a valid CSRF token
      const gen = await sigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const result = await handleTokenEndpoint(
        sigil,
        'POST',
        '/api/csrf/one-shot',
        { action: 'POST:/api/delete' },
        '/api/csrf/token',
        '/api/csrf/one-shot',
        gen.token, // Pass valid CSRF token
      )

      expect(result).not.toBeNull()
      expect(result!.handled).toBe(true)
      expect(result!.status).toBe(200)
      expect(result!.body).toHaveProperty('token')
      expect(result!.body).toHaveProperty('expiresAt')
      expect(result!.body).toHaveProperty('action')
    })

    it('should reject one-shot request without CSRF token (M2 fix)', async () => {
      const result = await handleTokenEndpoint(
        sigil,
        'POST',
        '/api/csrf/one-shot',
        { action: 'POST:/api/delete' },
        '/api/csrf/token',
        '/api/csrf/one-shot',
        // No CSRF token provided
      )

      expect(result).not.toBeNull()
      expect(result!.handled).toBe(true)
      expect(result!.status).toBe(403)
      expect(result!.body).toEqual({ error: 'CSRF validation failed' })
    })

    it('should reject one-shot request with invalid CSRF token (M2 fix)', async () => {
      const result = await handleTokenEndpoint(
        sigil,
        'POST',
        '/api/csrf/one-shot',
        { action: 'POST:/api/delete' },
        '/api/csrf/token',
        '/api/csrf/one-shot',
        'invalid-csrf-token',
      )

      expect(result).not.toBeNull()
      expect(result!.handled).toBe(true)
      expect(result!.status).toBe(403)
      expect(result!.body).toEqual({ error: 'CSRF validation failed' })
    })

    it('should reject one-shot request with empty CSRF token (M2 fix)', async () => {
      const result = await handleTokenEndpoint(
        sigil,
        'POST',
        '/api/csrf/one-shot',
        { action: 'POST:/api/delete' },
        '/api/csrf/token',
        '/api/csrf/one-shot',
        '',
      )

      expect(result).not.toBeNull()
      expect(result!.handled).toBe(true)
      expect(result!.status).toBe(403)
    })

    it('should reject missing action parameter', async () => {
      const gen = await sigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const result = await handleTokenEndpoint(
        sigil,
        'POST',
        '/api/csrf/one-shot',
        {},
        '/api/csrf/token',
        '/api/csrf/one-shot',
        gen.token,
      )

      expect(result).not.toBeNull()
      expect(result!.status).toBe(400)
    })

    it('should reject empty action parameter', async () => {
      const gen = await sigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const result = await handleTokenEndpoint(
        sigil,
        'POST',
        '/api/csrf/one-shot',
        { action: '' },
        '/api/csrf/token',
        '/api/csrf/one-shot',
        gen.token,
      )

      expect(result).not.toBeNull()
      expect(result!.status).toBe(400)
    })

    it('should reject non-string action parameter', async () => {
      const gen = await sigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const result = await handleTokenEndpoint(
        sigil,
        'POST',
        '/api/csrf/one-shot',
        { action: 123 },
        '/api/csrf/token',
        '/api/csrf/one-shot',
        gen.token,
      )

      expect(result).not.toBeNull()
      expect(result!.status).toBe(400)
    })

    it('should reject null body', async () => {
      const gen = await sigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const result = await handleTokenEndpoint(
        sigil,
        'POST',
        '/api/csrf/one-shot',
        null,
        '/api/csrf/token',
        '/api/csrf/one-shot',
        gen.token,
      )

      expect(result).not.toBeNull()
      expect(result!.status).toBe(400)
    })

    it('should pass optional context bindings', async () => {
      const gen = await sigil.generateToken()
      expect(gen.success).toBe(true)
      if (!gen.success) return

      const result = await handleTokenEndpoint(
        sigil,
        'POST',
        '/api/csrf/one-shot',
        { action: 'POST:/api/delete', context: ['session-123'] },
        '/api/csrf/token',
        '/api/csrf/one-shot',
        gen.token,
      )

      expect(result).not.toBeNull()
      expect(result!.status).toBe(200)
    })
  })

  describe('one-shot disabled', () => {
    it('should return null for one-shot endpoint when disabled', async () => {
      const noOneShotSigil = await createSigil({
        masterSecret,
        allowedOrigins: ['https://example.com'],
        oneShotEnabled: false,
      })

      const result = await handleTokenEndpoint(
        noOneShotSigil,
        'POST',
        '/api/csrf/one-shot',
        { action: 'test' },
        '/api/csrf/token',
        '/api/csrf/one-shot',
      )

      // Should be null because one-shot is disabled
      expect(result).toBeNull()
    })
  })
})
