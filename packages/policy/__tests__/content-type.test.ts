import { describe, it, expect } from 'vitest'
import { createContentTypePolicy } from '../src/content-type.js'
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

describe('createContentTypePolicy', () => {
  describe('default allowed content types', () => {
    it('should allow application/json', () => {
      const policy = createContentTypePolicy()
      const result = policy.validate(makeMetadata({ contentType: 'application/json' }))
      expect(result.allowed).toBe(true)
    })

    it('should allow application/x-www-form-urlencoded', () => {
      const policy = createContentTypePolicy()
      const result = policy.validate(
        makeMetadata({ contentType: 'application/x-www-form-urlencoded' }),
      )
      expect(result.allowed).toBe(true)
    })

    it('should allow multipart/form-data', () => {
      const policy = createContentTypePolicy()
      const result = policy.validate(makeMetadata({ contentType: 'multipart/form-data' }))
      expect(result.allowed).toBe(true)
    })
  })

  describe('content-type with parameters', () => {
    it('should strip charset parameter', () => {
      const policy = createContentTypePolicy()
      const result = policy.validate(
        makeMetadata({ contentType: 'application/json; charset=utf-8' }),
      )
      expect(result.allowed).toBe(true)
    })

    it('should strip boundary parameter from multipart', () => {
      const policy = createContentTypePolicy()
      const result = policy.validate(
        makeMetadata({
          contentType: 'multipart/form-data; boundary=----WebKitFormBoundary',
        }),
      )
      expect(result.allowed).toBe(true)
    })

    it('should handle extra whitespace', () => {
      const policy = createContentTypePolicy()
      const result = policy.validate(
        makeMetadata({ contentType: '  application/json  ; charset=utf-8' }),
      )
      expect(result.allowed).toBe(true)
    })

    it('should handle content-type with only semicolon prefix', () => {
      const policy = createContentTypePolicy()
      const result = policy.validate(
        makeMetadata({ contentType: ';charset=utf-8' }),
      )
      // Empty MIME type after stripping → not in allowed list → reject
      expect(result.allowed).toBe(false)
    })
  })

  describe('case insensitivity', () => {
    it('should handle uppercase content type', () => {
      const policy = createContentTypePolicy()
      const result = policy.validate(makeMetadata({ contentType: 'Application/JSON' }))
      expect(result.allowed).toBe(true)
    })

    it('should handle mixed case', () => {
      const policy = createContentTypePolicy()
      const result = policy.validate(
        makeMetadata({ contentType: 'Multipart/Form-Data' }),
      )
      expect(result.allowed).toBe(true)
    })
  })

  describe('disallowed content types', () => {
    it('should reject text/plain', () => {
      const policy = createContentTypePolicy()
      const result = policy.validate(makeMetadata({ contentType: 'text/plain' }))
      expect(result.allowed).toBe(false)
      if (!result.allowed) {
        expect(result.reason).toContain('content_type_disallowed')
        expect(result.reason).toContain('text/plain')
      }
    })

    it('should reject text/xml', () => {
      const policy = createContentTypePolicy()
      const result = policy.validate(makeMetadata({ contentType: 'text/xml' }))
      expect(result.allowed).toBe(false)
    })

    it('should reject application/xml', () => {
      const policy = createContentTypePolicy()
      const result = policy.validate(makeMetadata({ contentType: 'application/xml' }))
      expect(result.allowed).toBe(false)
    })

    it('should reject unknown content types', () => {
      const policy = createContentTypePolicy()
      const result = policy.validate(makeMetadata({ contentType: 'application/octet-stream' }))
      expect(result.allowed).toBe(false)
    })
  })

  describe('absent content type', () => {
    it('should allow null content type on safe methods (GET)', () => {
      const policy = createContentTypePolicy()
      const result = policy.validate(makeMetadata({ method: 'GET', contentType: null }))
      expect(result.allowed).toBe(true)
    })

    it('should allow empty content type on safe methods (HEAD)', () => {
      const policy = createContentTypePolicy()
      const result = policy.validate(makeMetadata({ method: 'HEAD', contentType: '' }))
      expect(result.allowed).toBe(true)
    })

    it('should reject null content type on POST (L6 fix)', () => {
      const policy = createContentTypePolicy()
      const result = policy.validate(makeMetadata({ method: 'POST', contentType: null }))
      expect(result.allowed).toBe(false)
      if (!result.allowed) {
        expect(result.reason).toBe('content_type_missing_on_state_change')
      }
    })

    it('should reject empty content type on PUT (L6 fix)', () => {
      const policy = createContentTypePolicy()
      const result = policy.validate(makeMetadata({ method: 'PUT', contentType: '' }))
      expect(result.allowed).toBe(false)
    })

    it('should reject missing content type on PATCH (L6 fix)', () => {
      const policy = createContentTypePolicy()
      const result = policy.validate(makeMetadata({ method: 'PATCH', contentType: null }))
      expect(result.allowed).toBe(false)
    })

    it('should reject missing content type on DELETE (L6 fix)', () => {
      const policy = createContentTypePolicy()
      const result = policy.validate(makeMetadata({ method: 'DELETE', contentType: null }))
      expect(result.allowed).toBe(false)
    })

    it('should allow null content type on OPTIONS', () => {
      const policy = createContentTypePolicy()
      const result = policy.validate(makeMetadata({ method: 'OPTIONS', contentType: null }))
      expect(result.allowed).toBe(true)
    })
  })

  describe('custom allowed content types', () => {
    it('should allow custom content types', () => {
      const policy = createContentTypePolicy({
        allowedContentTypes: ['application/json', 'text/plain'],
      })
      const result = policy.validate(makeMetadata({ contentType: 'text/plain' }))
      expect(result.allowed).toBe(true)
    })

    it('should reject non-custom content types', () => {
      const policy = createContentTypePolicy({
        allowedContentTypes: ['text/plain'],
      })
      const result = policy.validate(makeMetadata({ contentType: 'application/json' }))
      expect(result.allowed).toBe(false)
    })
  })

  describe('policy name', () => {
    it('should have correct policy name', () => {
      const policy = createContentTypePolicy()
      expect(policy.name).toBe('content-type')
    })
  })
})
