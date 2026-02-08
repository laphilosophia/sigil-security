import { describe, it, expect } from 'vitest'
import { createFetchMetadataPolicy } from '../src/fetch-metadata.js'
import { createOriginPolicy } from '../src/origin.js'
import { createContentTypePolicy } from '../src/content-type.js'
import { createPolicyChain, evaluatePolicyChain } from '../src/policy-chain.js'
import { detectClientMode } from '../src/mode-detection.js'
import { isProtectedMethod } from '../src/method.js'
import type { RequestMetadata } from '../src/types.js'

/** Helper to create realistic RequestMetadata */
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

describe('Integration: Full Policy Chain', () => {
  const browserPolicies = [
    createFetchMetadataPolicy({ legacyBrowserMode: 'degraded' }),
    createOriginPolicy({ allowedOrigins: ['https://example.com'] }),
    createContentTypePolicy(),
  ]

  describe('Browser Mode — legitimate request', () => {
    it('should allow same-origin JSON POST from browser', () => {
      const metadata = makeMetadata({
        method: 'POST',
        origin: 'https://example.com',
        secFetchSite: 'same-origin',
        secFetchMode: 'cors',
        secFetchDest: 'empty',
        contentType: 'application/json',
        tokenSource: { from: 'header', value: 'valid-token' },
      })

      expect(detectClientMode(metadata)).toBe('browser')
      expect(isProtectedMethod(metadata.method)).toBe(true)

      const chain = createPolicyChain(browserPolicies)
      const result = chain.validate(metadata)
      expect(result.allowed).toBe(true)
    })

    it('should allow same-origin form POST from browser', () => {
      const metadata = makeMetadata({
        method: 'POST',
        origin: 'https://example.com',
        secFetchSite: 'same-origin',
        contentType: 'application/x-www-form-urlencoded',
        tokenSource: { from: 'body-form', value: 'valid-token' },
      })

      const chain = createPolicyChain(browserPolicies)
      const result = chain.validate(metadata)
      expect(result.allowed).toBe(true)
    })
  })

  describe('Browser Mode — cross-site attack', () => {
    it('should reject cross-site POST', () => {
      const metadata = makeMetadata({
        method: 'POST',
        origin: 'https://evil.com',
        secFetchSite: 'cross-site',
        contentType: 'application/json',
        tokenSource: { from: 'header', value: 'stolen-token' },
      })

      const result = evaluatePolicyChain(browserPolicies, metadata)
      expect(result.allowed).toBe(false)
      // Both fetch-metadata and origin should fail
      expect(result.failures).toContain('fetch-metadata')
      expect(result.failures).toContain('origin')
      // But ALL policies still executed (no short-circuit)
      expect(result.evaluated).toHaveLength(3)
    })
  })

  describe('Browser Mode — browser extension attack', () => {
    it('should reject extension request (Sec-Fetch-Site: none)', () => {
      const metadata = makeMetadata({
        method: 'POST',
        origin: 'https://example.com', // extension can spoof origin
        secFetchSite: 'none',
        contentType: 'application/json',
      })

      const chain = createPolicyChain(browserPolicies)
      const result = chain.validate(metadata)
      expect(result.allowed).toBe(false)
    })
  })

  describe('Browser Mode — subdomain (same-site, cross-origin)', () => {
    it('should allow same-site request from subdomain with matching origin config', () => {
      const policies = [
        createFetchMetadataPolicy(),
        createOriginPolicy({
          allowedOrigins: ['https://example.com', 'https://app.example.com'],
        }),
        createContentTypePolicy(),
      ]

      const metadata = makeMetadata({
        method: 'POST',
        origin: 'https://app.example.com',
        secFetchSite: 'same-site',
        contentType: 'application/json',
      })

      const chain = createPolicyChain(policies)
      const result = chain.validate(metadata)
      expect(result.allowed).toBe(true)
    })
  })

  describe('API Mode — non-browser client', () => {
    it('should detect API mode and skip Fetch Metadata', () => {
      const metadata = makeMetadata({
        method: 'POST',
        origin: null, // mobile app, no Origin
        secFetchSite: null, // no Fetch Metadata
        contentType: 'application/json',
        tokenSource: { from: 'header', value: 'api-token' },
      })

      expect(detectClientMode(metadata)).toBe('api')

      // In API mode, only token validation matters
      // Fetch Metadata policy in degraded mode allows absent headers
      const chain = createPolicyChain([
        createFetchMetadataPolicy({ legacyBrowserMode: 'degraded' }),
        createContentTypePolicy(),
      ])
      const result = chain.validate(metadata)
      expect(result.allowed).toBe(true)
    })
  })

  describe('Legacy Browser — degraded mode', () => {
    it('should allow request with Origin but no Fetch Metadata', () => {
      const metadata = makeMetadata({
        method: 'POST',
        origin: 'https://example.com',
        secFetchSite: null, // legacy browser
        contentType: 'application/json',
        tokenSource: { from: 'header', value: 'valid-token' },
      })

      const chain = createPolicyChain(browserPolicies)
      const result = chain.validate(metadata)
      expect(result.allowed).toBe(true)
    })
  })

  describe('Legacy Browser — strict mode', () => {
    it('should reject request without Fetch Metadata in strict mode', () => {
      const strictPolicies = [
        createFetchMetadataPolicy({ legacyBrowserMode: 'strict' }),
        createOriginPolicy({ allowedOrigins: ['https://example.com'] }),
        createContentTypePolicy(),
      ]

      const metadata = makeMetadata({
        method: 'POST',
        origin: 'https://example.com',
        secFetchSite: null,
        contentType: 'application/json',
        tokenSource: { from: 'header', value: 'valid-token' },
      })

      const result = evaluatePolicyChain(strictPolicies, metadata)
      expect(result.allowed).toBe(false)
      expect(result.failures).toContain('fetch-metadata')
      // Origin passes even though fetch-metadata failed
      expect(result.failures).not.toContain('origin')
      // ALL policies still evaluated
      expect(result.evaluated).toHaveLength(3)
    })
  })

  describe('Content-Type attack', () => {
    it('should reject text/plain content type (CORS-simple bypass)', () => {
      const metadata = makeMetadata({
        method: 'POST',
        origin: 'https://example.com',
        secFetchSite: 'same-origin',
        contentType: 'text/plain', // CORS-simple, bypasses preflight
      })

      const chain = createPolicyChain(browserPolicies)
      const result = chain.validate(metadata)
      expect(result.allowed).toBe(false)
    })
  })

  describe('GET request — no protection needed', () => {
    it('should identify GET as unprotected', () => {
      const metadata = makeMetadata({ method: 'GET' })
      expect(isProtectedMethod(metadata.method)).toBe(false)
    })

    it('should identify HEAD as unprotected', () => {
      expect(isProtectedMethod('HEAD')).toBe(false)
    })

    it('should identify OPTIONS as unprotected', () => {
      expect(isProtectedMethod('OPTIONS')).toBe(false)
    })
  })

  describe('Service Worker edge case', () => {
    it('should handle service worker request with Origin fallback', () => {
      const metadata = makeMetadata({
        method: 'POST',
        origin: 'https://example.com',
        secFetchSite: 'same-origin', // SW may vary
        secFetchMode: 'same-origin',
        contentType: 'application/json',
      })

      const chain = createPolicyChain(browserPolicies)
      const result = chain.validate(metadata)
      expect(result.allowed).toBe(true)
    })
  })

  describe('Missing Origin + Referer fallback', () => {
    it('should allow via Referer when Origin is absent', () => {
      const metadata = makeMetadata({
        method: 'POST',
        origin: null,
        referer: 'https://example.com/form',
        secFetchSite: 'same-origin',
        contentType: 'application/json',
      })

      const chain = createPolicyChain(browserPolicies)
      const result = chain.validate(metadata)
      expect(result.allowed).toBe(true)
    })

    it('should reject when both Origin and Referer are absent', () => {
      const metadata = makeMetadata({
        method: 'POST',
        origin: null,
        referer: null,
        secFetchSite: 'same-origin',
        contentType: 'application/json',
      })

      const result = evaluatePolicyChain(browserPolicies, metadata)
      expect(result.allowed).toBe(false)
      expect(result.failures).toContain('origin')
    })
  })
})
