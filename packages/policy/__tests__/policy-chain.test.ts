import { describe, it, expect } from 'vitest'
import { createPolicyChain, evaluatePolicyChain } from '../src/policy-chain.js'
import type { PolicyValidator, RequestMetadata, PolicyResult } from '../src/types.js'

/** Helper to create minimal RequestMetadata */
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

/** Helper to create a simple allow policy */
function allowPolicy(name: string): PolicyValidator {
  return {
    name,
    validate: (): PolicyResult => ({ allowed: true }),
  }
}

/** Helper to create a simple reject policy */
function rejectPolicy(name: string, reason: string): PolicyValidator {
  return {
    name,
    validate: (): PolicyResult => ({ allowed: false, reason }),
  }
}

/** Helper to create a policy that tracks execution */
function trackingPolicy(
  name: string,
  result: PolicyResult,
  tracker: string[],
): PolicyValidator {
  return {
    name,
    validate: (): PolicyResult => {
      tracker.push(name)
      return result
    },
  }
}

describe('createPolicyChain', () => {
  describe('all pass', () => {
    it('should allow when all policies pass', () => {
      const chain = createPolicyChain([
        allowPolicy('policy-a'),
        allowPolicy('policy-b'),
        allowPolicy('policy-c'),
      ])
      const result = chain.validate(makeMetadata())
      expect(result.allowed).toBe(true)
    })

    it('should allow with empty policy list', () => {
      const chain = createPolicyChain([])
      const result = chain.validate(makeMetadata())
      expect(result.allowed).toBe(true)
    })

    it('should have correct policy name', () => {
      const chain = createPolicyChain([])
      expect(chain.name).toBe('policy-chain')
    })
  })

  describe('any fail', () => {
    it('should reject when one policy fails', () => {
      const chain = createPolicyChain([
        allowPolicy('policy-a'),
        rejectPolicy('policy-b', 'reason_b'),
        allowPolicy('policy-c'),
      ])
      const result = chain.validate(makeMetadata())
      expect(result.allowed).toBe(false)
      if (!result.allowed) {
        expect(result.reason).toBe('reason_b')
      }
    })

    it('should capture first failure reason when multiple fail', () => {
      const chain = createPolicyChain([
        rejectPolicy('policy-a', 'reason_a'),
        rejectPolicy('policy-b', 'reason_b'),
      ])
      const result = chain.validate(makeMetadata())
      expect(result.allowed).toBe(false)
      if (!result.allowed) {
        expect(result.reason).toBe('reason_a')
      }
    })
  })

  describe('no short-circuit — ALL policies execute', () => {
    it('should execute all policies even when first fails', () => {
      const tracker: string[] = []
      const chain = createPolicyChain([
        trackingPolicy('policy-a', { allowed: false, reason: 'fail_a' }, tracker),
        trackingPolicy('policy-b', { allowed: true }, tracker),
        trackingPolicy('policy-c', { allowed: true }, tracker),
      ])
      chain.validate(makeMetadata())

      // ALL policies must have executed
      expect(tracker).toEqual(['policy-a', 'policy-b', 'policy-c'])
    })

    it('should execute all policies even when multiple fail', () => {
      const tracker: string[] = []
      const chain = createPolicyChain([
        trackingPolicy('policy-a', { allowed: false, reason: 'fail_a' }, tracker),
        trackingPolicy('policy-b', { allowed: false, reason: 'fail_b' }, tracker),
        trackingPolicy('policy-c', { allowed: false, reason: 'fail_c' }, tracker),
      ])
      chain.validate(makeMetadata())

      expect(tracker).toEqual(['policy-a', 'policy-b', 'policy-c'])
    })
  })
})

describe('evaluatePolicyChain', () => {
  it('should return evaluated names for all-pass', () => {
    const result = evaluatePolicyChain(
      [allowPolicy('a'), allowPolicy('b'), allowPolicy('c')],
      makeMetadata(),
    )
    expect(result.evaluated).toEqual(['a', 'b', 'c'])
    expect(result.failures).toEqual([])
    expect(result.allowed).toBe(true)
  })

  it('should return failure names', () => {
    const result = evaluatePolicyChain(
      [
        allowPolicy('a'),
        rejectPolicy('b', 'fail_b'),
        allowPolicy('c'),
        rejectPolicy('d', 'fail_d'),
      ],
      makeMetadata(),
    )
    expect(result.evaluated).toEqual(['a', 'b', 'c', 'd'])
    expect(result.failures).toEqual(['b', 'd'])
    expect(result.allowed).toBe(false)
    if (!result.allowed) {
      expect(result.reason).toBe('fail_b') // first failure
    }
  })

  it('should return empty arrays for no policies', () => {
    const result = evaluatePolicyChain([], makeMetadata())
    expect(result.evaluated).toEqual([])
    expect(result.failures).toEqual([])
    expect(result.allowed).toBe(true)
  })
})
