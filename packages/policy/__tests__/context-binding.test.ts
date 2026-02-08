import { describe, it, expect } from 'vitest'
import {
  evaluateContextBinding,
  createContextBindingPolicy,
} from '../src/context-binding.js'
import type { RequestMetadata } from '../src/types.js'

/** Helper to create minimal RequestMetadata */
function makeMetadata(): RequestMetadata {
  return {
    method: 'POST',
    origin: null,
    referer: null,
    secFetchSite: null,
    secFetchMode: null,
    secFetchDest: null,
    contentType: null,
    tokenSource: { from: 'none' },
  }
}

describe('evaluateContextBinding', () => {
  describe('context matches', () => {
    it('should return matches=true for low tier', () => {
      const result = evaluateContextBinding(true, { tier: 'low' })
      expect(result.matches).toBe(true)
      expect(result.enforced).toBe(false)
      expect(result.inGracePeriod).toBe(false)
      expect(result.tier).toBe('low')
    })

    it('should return matches=true for medium tier', () => {
      const result = evaluateContextBinding(true, { tier: 'medium' })
      expect(result.matches).toBe(true)
      expect(result.enforced).toBe(false)
    })

    it('should return matches=true for high tier', () => {
      const result = evaluateContextBinding(true, { tier: 'high' })
      expect(result.matches).toBe(true)
      expect(result.enforced).toBe(false)
    })
  })

  describe('low tier — soft-fail, log only', () => {
    it('should not enforce on mismatch', () => {
      const result = evaluateContextBinding(false, { tier: 'low' })
      expect(result.matches).toBe(false)
      expect(result.enforced).toBe(false)
      expect(result.inGracePeriod).toBe(false)
      expect(result.tier).toBe('low')
    })
  })

  describe('medium tier — soft-fail with grace period', () => {
    it('should not enforce when in grace period', () => {
      // Session age < 5 minutes (default grace period)
      const result = evaluateContextBinding(false, { tier: 'medium' }, 60_000) // 1 min
      expect(result.matches).toBe(false)
      expect(result.enforced).toBe(false)
      expect(result.inGracePeriod).toBe(true)
      expect(result.tier).toBe('medium')
    })

    it('should enforce when grace period expired', () => {
      // Session age > 5 minutes (default grace period)
      const result = evaluateContextBinding(false, { tier: 'medium' }, 600_000) // 10 min
      expect(result.matches).toBe(false)
      expect(result.enforced).toBe(true)
      expect(result.inGracePeriod).toBe(false)
    })

    it('should enforce when session age is exactly at grace period boundary', () => {
      // Session age === 5 minutes (exact boundary)
      const result = evaluateContextBinding(false, { tier: 'medium' }, 300_000) // 5 min
      expect(result.matches).toBe(false)
      expect(result.enforced).toBe(true)
      expect(result.inGracePeriod).toBe(false)
    })

    it('should enforce when session age is undefined', () => {
      // No session age provided → no grace period
      const result = evaluateContextBinding(false, { tier: 'medium' })
      expect(result.matches).toBe(false)
      expect(result.enforced).toBe(true)
      expect(result.inGracePeriod).toBe(false)
    })

    it('should respect custom grace period', () => {
      // Custom grace period: 10 minutes
      const result = evaluateContextBinding(
        false,
        { tier: 'medium', gracePeriodMs: 600_000 },
        300_000, // 5 min < 10 min grace
      )
      expect(result.matches).toBe(false)
      expect(result.enforced).toBe(false)
      expect(result.inGracePeriod).toBe(true)
    })

    it('should handle zero session age (just rotated)', () => {
      const result = evaluateContextBinding(false, { tier: 'medium' }, 0)
      expect(result.matches).toBe(false)
      expect(result.enforced).toBe(false)
      expect(result.inGracePeriod).toBe(true)
    })

    it('should enforce when session age is negative (clock skew)', () => {
      const result = evaluateContextBinding(false, { tier: 'medium' }, -1000)
      expect(result.matches).toBe(false)
      expect(result.enforced).toBe(true)
      expect(result.inGracePeriod).toBe(false)
    })
  })

  describe('high tier — fail-closed', () => {
    it('should enforce on mismatch', () => {
      const result = evaluateContextBinding(false, { tier: 'high' })
      expect(result.matches).toBe(false)
      expect(result.enforced).toBe(true)
      expect(result.inGracePeriod).toBe(false)
      expect(result.tier).toBe('high')
    })

    it('should enforce even with recent session (no grace period)', () => {
      const result = evaluateContextBinding(false, { tier: 'high' }, 0)
      expect(result.matches).toBe(false)
      expect(result.enforced).toBe(true)
      expect(result.inGracePeriod).toBe(false)
    })
  })
})

describe('createContextBindingPolicy', () => {
  it('should have correct policy name', () => {
    const policy = createContextBindingPolicy({ tier: 'high' })
    expect(policy.name).toBe('context-binding')
  })

  it('should always allow (actual enforcement is at runtime layer)', () => {
    const policy = createContextBindingPolicy({ tier: 'high' })
    const result = policy.validate(makeMetadata())
    expect(result.allowed).toBe(true)
  })
})
