import { describe, it, expect } from 'vitest'
import { createOriginPolicy } from '../src/origin.js'
import type { RequestMetadata } from '../src/types.js'

/** Helper to create minimal RequestMetadata with overrides */
function makeMetadata(overrides: Partial<RequestMetadata> = {}): RequestMetadata {
  return {
    method: 'POST',
    origin: null,
    referer: null,
    secFetchSite: null,
    secFetchMode: null,
    secFetchDest: null,
    contentType: null,
    tokenSource: { from: 'none' },
    ...overrides,
  }
}

describe('createOriginPolicy', () => {
  const allowedOrigins = ['https://example.com', 'https://api.example.com']

  describe('Origin header matching', () => {
    it('should allow matching origin', () => {
      const policy = createOriginPolicy({ allowedOrigins })
      const result = policy.validate(makeMetadata({ origin: 'https://example.com' }))
      expect(result.allowed).toBe(true)
    })

    it('should allow matching origin (with trailing slash)', () => {
      const policy = createOriginPolicy({ allowedOrigins })
      const result = policy.validate(makeMetadata({ origin: 'https://example.com/' }))
      expect(result.allowed).toBe(true)
    })

    it('should allow matching origin (case-insensitive)', () => {
      const policy = createOriginPolicy({ allowedOrigins })
      const result = policy.validate(makeMetadata({ origin: 'https://Example.COM' }))
      expect(result.allowed).toBe(true)
    })

    it('should allow secondary allowed origin', () => {
      const policy = createOriginPolicy({ allowedOrigins })
      const result = policy.validate(makeMetadata({ origin: 'https://api.example.com' }))
      expect(result.allowed).toBe(true)
    })

    it('should reject non-matching origin', () => {
      const policy = createOriginPolicy({ allowedOrigins })
      const result = policy.validate(makeMetadata({ origin: 'https://evil.com' }))
      expect(result.allowed).toBe(false)
      if (!result.allowed) {
        expect(result.reason).toContain('origin_mismatch')
      }
    })

    it('should reject subdomain that is not in allowed list', () => {
      const policy = createOriginPolicy({ allowedOrigins })
      const result = policy.validate(makeMetadata({ origin: 'https://sub.example.com' }))
      expect(result.allowed).toBe(false)
    })

    it('should reject different port', () => {
      const policy = createOriginPolicy({ allowedOrigins })
      const result = policy.validate(makeMetadata({ origin: 'https://example.com:8443' }))
      expect(result.allowed).toBe(false)
    })

    it('should reject different scheme', () => {
      const policy = createOriginPolicy({ allowedOrigins })
      const result = policy.validate(makeMetadata({ origin: 'http://example.com' }))
      expect(result.allowed).toBe(false)
    })
  })

  describe('Referer header fallback', () => {
    it('should allow matching Referer origin when Origin is absent', () => {
      const policy = createOriginPolicy({ allowedOrigins })
      const result = policy.validate(
        makeMetadata({ origin: null, referer: 'https://example.com/some/page?q=1' }),
      )
      expect(result.allowed).toBe(true)
    })

    it('should allow matching Referer origin (secondary)', () => {
      const policy = createOriginPolicy({ allowedOrigins })
      const result = policy.validate(
        makeMetadata({ origin: null, referer: 'https://api.example.com/endpoint' }),
      )
      expect(result.allowed).toBe(true)
    })

    it('should reject non-matching Referer origin', () => {
      const policy = createOriginPolicy({ allowedOrigins })
      const result = policy.validate(
        makeMetadata({ origin: null, referer: 'https://evil.com/phishing' }),
      )
      expect(result.allowed).toBe(false)
      if (!result.allowed) {
        expect(result.reason).toContain('origin_referer_mismatch')
      }
    })

    it('should reject invalid Referer URL', () => {
      const policy = createOriginPolicy({ allowedOrigins })
      const result = policy.validate(
        makeMetadata({ origin: null, referer: 'not-a-valid-url' }),
      )
      expect(result.allowed).toBe(false)
      if (!result.allowed) {
        expect(result.reason).toBe('origin_referer_invalid')
      }
    })
  })

  describe('both absent', () => {
    it('should reject when both Origin and Referer are absent', () => {
      const policy = createOriginPolicy({ allowedOrigins })
      const result = policy.validate(makeMetadata({ origin: null, referer: null }))
      expect(result.allowed).toBe(false)
      if (!result.allowed) {
        expect(result.reason).toBe('origin_missing')
      }
    })

    it('should reject when both Origin and Referer are empty strings', () => {
      const policy = createOriginPolicy({ allowedOrigins })
      const result = policy.validate(makeMetadata({ origin: '', referer: '' }))
      expect(result.allowed).toBe(false)
      if (!result.allowed) {
        expect(result.reason).toBe('origin_missing')
      }
    })
  })

  describe('Origin takes precedence over Referer', () => {
    it('should use Origin when both are present', () => {
      const policy = createOriginPolicy({ allowedOrigins })
      // Origin matches, Referer does not
      const result = policy.validate(
        makeMetadata({ origin: 'https://example.com', referer: 'https://evil.com/page' }),
      )
      expect(result.allowed).toBe(true)
    })

    it('should reject on Origin mismatch even if Referer matches', () => {
      const policy = createOriginPolicy({ allowedOrigins })
      // Origin does not match, Referer matches
      const result = policy.validate(
        makeMetadata({
          origin: 'https://evil.com',
          referer: 'https://example.com/page',
        }),
      )
      expect(result.allowed).toBe(false)
    })
  })

  describe('edge cases', () => {
    it('should handle localhost origins', () => {
      const policy = createOriginPolicy({
        allowedOrigins: ['http://localhost:3000'],
      })
      const result = policy.validate(makeMetadata({ origin: 'http://localhost:3000' }))
      expect(result.allowed).toBe(true)
    })

    it('should handle IP-based origins', () => {
      const policy = createOriginPolicy({
        allowedOrigins: ['http://192.168.1.1:8080'],
      })
      const result = policy.validate(makeMetadata({ origin: 'http://192.168.1.1:8080' }))
      expect(result.allowed).toBe(true)
    })

    it('should handle empty allowed origins list', () => {
      const policy = createOriginPolicy({ allowedOrigins: [] })
      const result = policy.validate(makeMetadata({ origin: 'https://example.com' }))
      expect(result.allowed).toBe(false)
    })

    it('should reject literal "null" origin (privacy-sandboxed iframe)', () => {
      // Browsers send Origin: null (literal string) for sandboxed iframes,
      // data: URIs, and privacy redirects. This must be rejected.
      const policy = createOriginPolicy({ allowedOrigins })
      const result = policy.validate(makeMetadata({ origin: 'null' }))
      expect(result.allowed).toBe(false)
    })

    it('should handle malformed origin string gracefully', () => {
      // Non-URL origin strings fall through to lowercase + strip trailing slash
      const policy = createOriginPolicy({ allowedOrigins: ['custom-scheme'] })
      const result = policy.validate(makeMetadata({ origin: 'custom-scheme' }))
      expect(result.allowed).toBe(true)
    })

    it('should handle allowed origin configured as non-URL', () => {
      // If allowedOrigins contains non-URL strings, normalizeOrigin falls back
      const policy = createOriginPolicy({ allowedOrigins: ['not-a-url'] })
      const result = policy.validate(makeMetadata({ origin: 'not-a-url' }))
      expect(result.allowed).toBe(true)
    })

    it('should handle Referer with fragment', () => {
      const policy = createOriginPolicy({ allowedOrigins })
      const result = policy.validate(
        makeMetadata({
          origin: null,
          referer: 'https://example.com/page#section',
        }),
      )
      expect(result.allowed).toBe(true)
    })

    it('should handle Referer with credentials (user:pass@host)', () => {
      const policy = createOriginPolicy({ allowedOrigins })
      const result = policy.validate(
        makeMetadata({
          origin: null,
          referer: 'https://user:pass@example.com/page',
        }),
      )
      expect(result.allowed).toBe(true)
    })
  })

  describe('policy name', () => {
    it('should have correct policy name', () => {
      const policy = createOriginPolicy({ allowedOrigins })
      expect(policy.name).toBe('origin')
    })
  })
})
