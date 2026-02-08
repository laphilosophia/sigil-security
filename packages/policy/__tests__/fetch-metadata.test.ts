import { describe, it, expect } from 'vitest'
import { createFetchMetadataPolicy } from '../src/fetch-metadata.js'
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

describe('createFetchMetadataPolicy', () => {
  describe('same-origin', () => {
    it('should allow same-origin requests', () => {
      const policy = createFetchMetadataPolicy()
      const result = policy.validate(makeMetadata({ secFetchSite: 'same-origin' }))
      expect(result.allowed).toBe(true)
    })

    it('should allow same-origin (case-insensitive)', () => {
      const policy = createFetchMetadataPolicy()
      const result = policy.validate(makeMetadata({ secFetchSite: 'Same-Origin' }))
      expect(result.allowed).toBe(true)
    })
  })

  describe('same-site', () => {
    it('should allow same-site requests', () => {
      const policy = createFetchMetadataPolicy()
      const result = policy.validate(makeMetadata({ secFetchSite: 'same-site' }))
      expect(result.allowed).toBe(true)
    })

    it('should allow same-site (case-insensitive)', () => {
      const policy = createFetchMetadataPolicy()
      const result = policy.validate(makeMetadata({ secFetchSite: 'Same-Site' }))
      expect(result.allowed).toBe(true)
    })
  })

  describe('cross-site', () => {
    it('should reject cross-site requests', () => {
      const policy = createFetchMetadataPolicy()
      const result = policy.validate(makeMetadata({ secFetchSite: 'cross-site' }))
      expect(result.allowed).toBe(false)
      if (!result.allowed) {
        expect(result.reason).toBe('fetch_metadata_cross_site')
      }
    })

    it('should reject cross-site (case-insensitive)', () => {
      const policy = createFetchMetadataPolicy()
      const result = policy.validate(makeMetadata({ secFetchSite: 'Cross-Site' }))
      expect(result.allowed).toBe(false)
    })
  })

  describe('none (browser extension)', () => {
    it('should reject none (browser extension / untrusted)', () => {
      const policy = createFetchMetadataPolicy()
      const result = policy.validate(makeMetadata({ secFetchSite: 'none' }))
      expect(result.allowed).toBe(false)
      if (!result.allowed) {
        expect(result.reason).toBe('fetch_metadata_none')
      }
    })
  })

  describe('header absent — degraded mode (default)', () => {
    it('should allow when Sec-Fetch-Site is null (degraded mode)', () => {
      const policy = createFetchMetadataPolicy()
      const result = policy.validate(makeMetadata({ secFetchSite: null }))
      expect(result.allowed).toBe(true)
    })

    it('should allow when Sec-Fetch-Site is empty string (degraded mode)', () => {
      const policy = createFetchMetadataPolicy()
      const result = policy.validate(makeMetadata({ secFetchSite: '' }))
      expect(result.allowed).toBe(true)
    })

    it('should allow with explicit degraded mode config', () => {
      const policy = createFetchMetadataPolicy({ legacyBrowserMode: 'degraded' })
      const result = policy.validate(makeMetadata({ secFetchSite: null }))
      expect(result.allowed).toBe(true)
    })
  })

  describe('header absent — strict mode', () => {
    it('should reject when Sec-Fetch-Site is null (strict mode)', () => {
      const policy = createFetchMetadataPolicy({ legacyBrowserMode: 'strict' })
      const result = policy.validate(makeMetadata({ secFetchSite: null }))
      expect(result.allowed).toBe(false)
      if (!result.allowed) {
        expect(result.reason).toBe('fetch_metadata_missing_strict')
      }
    })

    it('should reject when Sec-Fetch-Site is empty string (strict mode)', () => {
      const policy = createFetchMetadataPolicy({ legacyBrowserMode: 'strict' })
      const result = policy.validate(makeMetadata({ secFetchSite: '' }))
      expect(result.allowed).toBe(false)
    })
  })

  describe('invalid values', () => {
    it('should reject unrecognized Sec-Fetch-Site values', () => {
      const policy = createFetchMetadataPolicy()
      const result = policy.validate(makeMetadata({ secFetchSite: 'invalid-value' }))
      expect(result.allowed).toBe(false)
      if (!result.allowed) {
        expect(result.reason).toContain('fetch_metadata_invalid_value')
      }
    })

    it('should reject random string values', () => {
      const policy = createFetchMetadataPolicy()
      const result = policy.validate(makeMetadata({ secFetchSite: 'foobar' }))
      expect(result.allowed).toBe(false)
    })
  })

  describe('policy name', () => {
    it('should have correct policy name', () => {
      const policy = createFetchMetadataPolicy()
      expect(policy.name).toBe('fetch-metadata')
    })
  })
})
