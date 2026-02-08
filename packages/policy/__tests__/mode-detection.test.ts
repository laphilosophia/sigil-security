import { describe, it, expect } from 'vitest'
import { detectClientMode } from '../src/mode-detection.js'
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

describe('detectClientMode', () => {
  describe('browser mode detection', () => {
    it('should detect browser mode when Sec-Fetch-Site is same-origin', () => {
      const mode = detectClientMode(makeMetadata({ secFetchSite: 'same-origin' }))
      expect(mode).toBe('browser')
    })

    it('should detect browser mode when Sec-Fetch-Site is same-site', () => {
      const mode = detectClientMode(makeMetadata({ secFetchSite: 'same-site' }))
      expect(mode).toBe('browser')
    })

    it('should detect browser mode when Sec-Fetch-Site is cross-site', () => {
      const mode = detectClientMode(makeMetadata({ secFetchSite: 'cross-site' }))
      expect(mode).toBe('browser')
    })

    it('should detect browser mode when Sec-Fetch-Site is none', () => {
      const mode = detectClientMode(makeMetadata({ secFetchSite: 'none' }))
      expect(mode).toBe('browser')
    })
  })

  describe('API mode detection', () => {
    it('should detect API mode when Sec-Fetch-Site is absent (null)', () => {
      const mode = detectClientMode(makeMetadata({ secFetchSite: null }))
      expect(mode).toBe('api')
    })

    it('should detect API mode when Sec-Fetch-Site is empty string', () => {
      const mode = detectClientMode(makeMetadata({ secFetchSite: '' }))
      expect(mode).toBe('api')
    })
  })

  describe('manual override', () => {
    it('should force API mode with X-Client-Type: api', () => {
      const mode = detectClientMode(
        makeMetadata({ secFetchSite: 'same-origin', clientType: 'api' }),
      )
      expect(mode).toBe('api')
    })

    it('should force API mode (case-insensitive)', () => {
      const mode = detectClientMode(
        makeMetadata({ secFetchSite: 'same-origin', clientType: 'API' }),
      )
      expect(mode).toBe('api')
    })

    it('should not force API mode for non-api client type', () => {
      const mode = detectClientMode(
        makeMetadata({ secFetchSite: 'same-origin', clientType: 'browser' }),
      )
      expect(mode).toBe('browser')
    })

    it('should detect based on Sec-Fetch-Site when clientType is undefined', () => {
      const mode = detectClientMode(
        makeMetadata({ secFetchSite: 'same-origin', clientType: undefined }),
      )
      expect(mode).toBe('browser')
    })
  })

  describe('real-world scenarios', () => {
    it('should detect browser for modern browser request', () => {
      const mode = detectClientMode(
        makeMetadata({
          secFetchSite: 'same-origin',
          secFetchMode: 'cors',
          secFetchDest: 'empty',
          origin: 'https://example.com',
        }),
      )
      expect(mode).toBe('browser')
    })

    it('should detect API for mobile app request', () => {
      const mode = detectClientMode(
        makeMetadata({
          secFetchSite: null,
          secFetchMode: null,
          secFetchDest: null,
          origin: null,
        }),
      )
      expect(mode).toBe('api')
    })

    it('should detect API for curl request', () => {
      const mode = detectClientMode(
        makeMetadata({
          secFetchSite: null,
          origin: null,
          referer: null,
        }),
      )
      expect(mode).toBe('api')
    })

    it('should detect API for internal service with explicit header', () => {
      const mode = detectClientMode(
        makeMetadata({
          secFetchSite: null,
          clientType: 'api',
        }),
      )
      expect(mode).toBe('api')
    })
  })
})
