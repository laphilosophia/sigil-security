import { describe, it, expect } from 'vitest'
import { createMethodPolicy, isProtectedMethod } from '../src/method.js'
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

describe('createMethodPolicy', () => {
  describe('default protected methods (POST, PUT, PATCH, DELETE)', () => {
    it('should allow GET requests', () => {
      const policy = createMethodPolicy()
      const result = policy.validate(makeMetadata({ method: 'GET' }))
      expect(result.allowed).toBe(true)
    })

    it('should allow HEAD requests', () => {
      const policy = createMethodPolicy()
      const result = policy.validate(makeMetadata({ method: 'HEAD' }))
      expect(result.allowed).toBe(true)
    })

    it('should allow OPTIONS requests', () => {
      const policy = createMethodPolicy()
      const result = policy.validate(makeMetadata({ method: 'OPTIONS' }))
      expect(result.allowed).toBe(true)
    })

    it('should allow POST requests (protected but passes through)', () => {
      const policy = createMethodPolicy()
      const result = policy.validate(makeMetadata({ method: 'POST' }))
      expect(result.allowed).toBe(true)
    })

    it('should allow PUT requests (protected but passes through)', () => {
      const policy = createMethodPolicy()
      const result = policy.validate(makeMetadata({ method: 'PUT' }))
      expect(result.allowed).toBe(true)
    })

    it('should allow PATCH requests (protected but passes through)', () => {
      const policy = createMethodPolicy()
      const result = policy.validate(makeMetadata({ method: 'PATCH' }))
      expect(result.allowed).toBe(true)
    })

    it('should allow DELETE requests (protected but passes through)', () => {
      const policy = createMethodPolicy()
      const result = policy.validate(makeMetadata({ method: 'DELETE' }))
      expect(result.allowed).toBe(true)
    })
  })

  describe('case insensitivity', () => {
    it('should handle lowercase method', () => {
      const policy = createMethodPolicy()
      const result = policy.validate(makeMetadata({ method: 'get' }))
      expect(result.allowed).toBe(true)
    })

    it('should handle mixed case method', () => {
      const policy = createMethodPolicy()
      const result = policy.validate(makeMetadata({ method: 'Post' }))
      expect(result.allowed).toBe(true)
    })
  })

  describe('custom protected methods', () => {
    it('should respect custom protected method list', () => {
      const policy = createMethodPolicy({ protectedMethods: ['POST'] })
      const result = policy.validate(makeMetadata({ method: 'PUT' }))
      expect(result.allowed).toBe(true)
    })
  })

  describe('policy name', () => {
    it('should have correct policy name', () => {
      const policy = createMethodPolicy()
      expect(policy.name).toBe('method')
    })
  })
})

describe('isProtectedMethod', () => {
  it('should identify POST as protected', () => {
    expect(isProtectedMethod('POST')).toBe(true)
  })

  it('should identify PUT as protected', () => {
    expect(isProtectedMethod('PUT')).toBe(true)
  })

  it('should identify PATCH as protected', () => {
    expect(isProtectedMethod('PATCH')).toBe(true)
  })

  it('should identify DELETE as protected', () => {
    expect(isProtectedMethod('DELETE')).toBe(true)
  })

  it('should not identify GET as protected', () => {
    expect(isProtectedMethod('GET')).toBe(false)
  })

  it('should not identify HEAD as protected', () => {
    expect(isProtectedMethod('HEAD')).toBe(false)
  })

  it('should not identify OPTIONS as protected', () => {
    expect(isProtectedMethod('OPTIONS')).toBe(false)
  })

  it('should handle case-insensitivity', () => {
    expect(isProtectedMethod('post')).toBe(true)
    expect(isProtectedMethod('get')).toBe(false)
  })

  it('should respect custom protected methods', () => {
    expect(isProtectedMethod('GET', ['GET', 'POST'])).toBe(true)
    expect(isProtectedMethod('DELETE', ['GET', 'POST'])).toBe(false)
  })
})
