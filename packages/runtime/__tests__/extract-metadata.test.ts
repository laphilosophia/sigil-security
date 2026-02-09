import { describe, it, expect } from 'vitest'
import {
  extractRequestMetadata,
  parseContentType,
  extractTokenFromHeader,
  extractTokenFromJsonBody,
  extractTokenFromFormBody,
  resolveTokenSource,
  normalizePath,
  normalizePathSet,
} from '../src/extract-metadata.js'
import type { HeaderGetter } from '../src/extract-metadata.js'

describe('extract-metadata', () => {
  describe('parseContentType', () => {
    it('should return null for null input', () => {
      expect(parseContentType(null)).toBeNull()
    })

    it('should strip parameters from content-type', () => {
      expect(parseContentType('application/json; charset=utf-8')).toBe('application/json')
    })

    it('should lowercase the MIME type', () => {
      expect(parseContentType('Application/JSON')).toBe('application/json')
    })

    it('should handle content-type without parameters', () => {
      expect(parseContentType('application/json')).toBe('application/json')
    })

    it('should handle multipart with boundary', () => {
      expect(parseContentType('multipart/form-data; boundary=----WebKitFormBoundary')).toBe(
        'multipart/form-data',
      )
    })
  })

  describe('extractTokenFromHeader', () => {
    it('should extract token from header', () => {
      const getHeader: HeaderGetter = (name) =>
        name === 'x-csrf-token' ? 'my-token' : null

      const source = extractTokenFromHeader(getHeader)
      expect(source).toEqual({ from: 'header', value: 'my-token' })
    })

    it('should return none when header is absent', () => {
      const getHeader: HeaderGetter = () => null
      const source = extractTokenFromHeader(getHeader)
      expect(source).toEqual({ from: 'none' })
    })

    it('should return none when header is empty', () => {
      const getHeader: HeaderGetter = () => ''
      const source = extractTokenFromHeader(getHeader)
      expect(source).toEqual({ from: 'none' })
    })

    it('should use custom header name', () => {
      const getHeader: HeaderGetter = (name) =>
        name === 'x-my-token' ? 'custom-token' : null

      const source = extractTokenFromHeader(getHeader, 'x-my-token')
      expect(source).toEqual({ from: 'header', value: 'custom-token' })
    })
  })

  describe('extractTokenFromJsonBody', () => {
    it('should extract token from JSON body', () => {
      const body = { csrf_token: 'body-token' }
      const source = extractTokenFromJsonBody(body)
      expect(source).toEqual({ from: 'body-json', value: 'body-token' })
    })

    it('should return null when field is missing', () => {
      const body = { other_field: 'value' }
      const source = extractTokenFromJsonBody(body)
      expect(source).toBeNull()
    })

    it('should return null for null body', () => {
      expect(extractTokenFromJsonBody(null)).toBeNull()
    })

    it('should return null for undefined body', () => {
      expect(extractTokenFromJsonBody(undefined)).toBeNull()
    })

    it('should return null when field is not a string', () => {
      const body = { csrf_token: 123 }
      expect(extractTokenFromJsonBody(body)).toBeNull()
    })

    it('should return null when field is empty string', () => {
      const body = { csrf_token: '' }
      expect(extractTokenFromJsonBody(body)).toBeNull()
    })

    it('should use custom field name', () => {
      const body = { my_token: 'custom-body-token' }
      const source = extractTokenFromJsonBody(body, 'my_token')
      expect(source).toEqual({ from: 'body-json', value: 'custom-body-token' })
    })
  })

  describe('extractTokenFromFormBody', () => {
    it('should extract token from form body', () => {
      const body = { csrf_token: 'form-token' }
      const source = extractTokenFromFormBody(body)
      expect(source).toEqual({ from: 'body-form', value: 'form-token' })
    })

    it('should return null when field is missing', () => {
      const body = { other: 'value' }
      expect(extractTokenFromFormBody(body)).toBeNull()
    })

    it('should return null for null body', () => {
      expect(extractTokenFromFormBody(null)).toBeNull()
    })
  })

  describe('resolveTokenSource', () => {
    it('should prioritize header over body (precedence rule)', () => {
      const getHeader: HeaderGetter = (name) =>
        name === 'x-csrf-token' ? 'header-token' : null
      const body = { csrf_token: 'body-token' }

      const source = resolveTokenSource(getHeader, body, 'application/json')
      expect(source).toEqual({ from: 'header', value: 'header-token' })
    })

    it('should fall back to JSON body when header absent', () => {
      const getHeader: HeaderGetter = () => null
      const body = { csrf_token: 'json-token' }

      const source = resolveTokenSource(getHeader, body, 'application/json')
      expect(source).toEqual({ from: 'body-json', value: 'json-token' })
    })

    it('should fall back to form body when header and JSON absent', () => {
      const getHeader: HeaderGetter = () => null
      const body = { csrf_token: 'form-token' }

      const source = resolveTokenSource(
        getHeader,
        body,
        'application/x-www-form-urlencoded',
      )
      expect(source).toEqual({ from: 'body-form', value: 'form-token' })
    })

    it('should return none when no token found', () => {
      const getHeader: HeaderGetter = () => null
      const source = resolveTokenSource(getHeader, undefined, null)
      expect(source).toEqual({ from: 'none' })
    })

    it('should not check JSON body when content-type is not JSON', () => {
      const getHeader: HeaderGetter = () => null
      const body = { csrf_token: 'json-token' }

      const source = resolveTokenSource(
        getHeader,
        body,
        'application/x-www-form-urlencoded',
      )
      // Should find form token, not JSON token
      expect(source.from).toBe('body-form')
    })

    it('should handle multipart/form-data content type', () => {
      const getHeader: HeaderGetter = () => null
      const body = { csrf_token: 'multipart-token' }

      const source = resolveTokenSource(getHeader, body, 'multipart/form-data')
      expect(source).toEqual({ from: 'body-form', value: 'multipart-token' })
    })
  })

  describe('extractRequestMetadata', () => {
    it('should extract all security headers', () => {
      const headers: Record<string, string> = {
        origin: 'https://example.com',
        referer: 'https://example.com/page',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'content-type': 'application/json; charset=utf-8',
        'x-client-type': 'api',
      }

      const getHeader: HeaderGetter = (name) => headers[name.toLowerCase()] ?? null
      const tokenSource = { from: 'header' as const, value: 'test-token' }

      const metadata = extractRequestMetadata('POST', getHeader, tokenSource)

      expect(metadata.method).toBe('POST')
      expect(metadata.origin).toBe('https://example.com')
      expect(metadata.referer).toBe('https://example.com/page')
      expect(metadata.secFetchSite).toBe('same-origin')
      expect(metadata.secFetchMode).toBe('cors')
      expect(metadata.secFetchDest).toBe('empty')
      expect(metadata.contentType).toBe('application/json')
      expect(metadata.clientType).toBe('api')
      expect(metadata.tokenSource).toEqual({ from: 'header', value: 'test-token' })
    })

    it('should uppercase the HTTP method', () => {
      const getHeader: HeaderGetter = () => null
      const tokenSource = { from: 'none' as const }

      const metadata = extractRequestMetadata('post', getHeader, tokenSource)
      expect(metadata.method).toBe('POST')
    })

    it('should handle missing headers as null', () => {
      const getHeader: HeaderGetter = () => null
      const tokenSource = { from: 'none' as const }

      const metadata = extractRequestMetadata('GET', getHeader, tokenSource)

      expect(metadata.origin).toBeNull()
      expect(metadata.referer).toBeNull()
      expect(metadata.secFetchSite).toBeNull()
      expect(metadata.secFetchMode).toBeNull()
      expect(metadata.secFetchDest).toBeNull()
      expect(metadata.contentType).toBeNull()
      expect(metadata.clientType).toBeUndefined()
    })
  })

  describe('normalizePath (L3 fix)', () => {
    it('should strip trailing slash', () => {
      expect(normalizePath('/health/')).toBe('/health')
    })

    it('should strip multiple trailing slashes', () => {
      expect(normalizePath('/health///')).toBe('/health')
    })

    it('should preserve root path', () => {
      expect(normalizePath('/')).toBe('/')
    })

    it('should preserve empty path as root', () => {
      expect(normalizePath('')).toBe('/')
    })

    it('should not modify paths without trailing slash', () => {
      expect(normalizePath('/api/csrf/token')).toBe('/api/csrf/token')
    })

    it('should handle nested paths with trailing slash', () => {
      expect(normalizePath('/api/v1/health/')).toBe('/api/v1/health')
    })
  })

  describe('normalizePathSet (L3 fix)', () => {
    it('should create a set with normalized paths', () => {
      const set = normalizePathSet(['/health/', '/metrics/', '/ready'])
      expect(set.has('/health')).toBe(true)
      expect(set.has('/metrics')).toBe(true)
      expect(set.has('/ready')).toBe(true)
      // Original trailing-slash versions should NOT be in the set
      expect(set.has('/health/')).toBe(false)
    })
  })
})
