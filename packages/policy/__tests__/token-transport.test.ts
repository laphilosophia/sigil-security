import { describe, it, expect } from 'vitest'
import {
  resolveTokenTransport,
  isValidTokenTransport,
  getTokenHeaderName,
  getTokenJsonFieldName,
  getTokenFormFieldName,
} from '../src/token-transport.js'
import type { RequestMetadata, TokenSource } from '../src/types.js'

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

describe('resolveTokenTransport', () => {
  describe('token present', () => {
    it('should resolve header token', () => {
      const result = resolveTokenTransport(
        makeMetadata({
          tokenSource: { from: 'header', value: 'token123' },
        }),
      )
      expect(result.found).toBe(true)
      if (result.found) {
        expect(result.source.from).toBe('header')
        if (result.source.from === 'header') {
          expect(result.source.value).toBe('token123')
        }
      }
    })

    it('should resolve JSON body token', () => {
      const result = resolveTokenTransport(
        makeMetadata({
          tokenSource: { from: 'body-json', value: 'token456' },
        }),
      )
      expect(result.found).toBe(true)
      if (result.found) {
        expect(result.source.from).toBe('body-json')
      }
    })

    it('should resolve form body token', () => {
      const result = resolveTokenTransport(
        makeMetadata({
          tokenSource: { from: 'body-form', value: 'token789' },
        }),
      )
      expect(result.found).toBe(true)
      if (result.found) {
        expect(result.source.from).toBe('body-form')
      }
    })
  })

  describe('token absent', () => {
    it('should return not found when no token', () => {
      const result = resolveTokenTransport(
        makeMetadata({
          tokenSource: { from: 'none' },
        }),
      )
      expect(result.found).toBe(false)
      if (!result.found) {
        expect(result.reason).toBe('no_token_present')
      }
    })
  })
})

describe('isValidTokenTransport', () => {
  it('should accept header transport', () => {
    const source: TokenSource = { from: 'header', value: 'token' }
    expect(isValidTokenTransport(source)).toBe(true)
  })

  it('should accept body-json transport', () => {
    const source: TokenSource = { from: 'body-json', value: 'token' }
    expect(isValidTokenTransport(source)).toBe(true)
  })

  it('should accept body-form transport', () => {
    const source: TokenSource = { from: 'body-form', value: 'token' }
    expect(isValidTokenTransport(source)).toBe(true)
  })

  it('should reject none transport', () => {
    const source: TokenSource = { from: 'none' }
    expect(isValidTokenTransport(source)).toBe(false)
  })
})

describe('getTokenHeaderName', () => {
  it('should return default header name', () => {
    expect(getTokenHeaderName()).toBe('x-csrf-token')
  })

  it('should return custom header name', () => {
    expect(getTokenHeaderName({ headerName: 'x-custom-token' })).toBe('x-custom-token')
  })
})

describe('getTokenJsonFieldName', () => {
  it('should return default JSON field name', () => {
    expect(getTokenJsonFieldName()).toBe('csrf_token')
  })

  it('should return custom JSON field name', () => {
    expect(getTokenJsonFieldName({ jsonFieldName: 'custom_token' })).toBe('custom_token')
  })
})

describe('getTokenFormFieldName', () => {
  it('should return default form field name', () => {
    expect(getTokenFormFieldName()).toBe('csrf_token')
  })

  it('should return custom form field name', () => {
    expect(getTokenFormFieldName({ formFieldName: 'my_csrf' })).toBe('my_csrf')
  })
})
