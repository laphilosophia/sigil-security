import { describe, expect, it } from 'vitest'
import { detectAnomalies } from '../src/index.js'

describe('anomaly detection', () => {
  it('should treat a positive sample over a zero baseline as infinite deviation', () => {
    const findings = detectAnomalies(
      {
        validationFailRate: 0,
        invalidMacRate: 2,
        generationRate: 0,
        oneShotReplayCount: 0,
        timingVariance: 0,
      },
      {
        validationFailRate: 0,
        invalidMacRate: 0,
        generationRate: 0,
        timingVariance: 0,
      },
    )

    expect(findings).toContainEqual({
      type: 'invalid_mac_spike',
      severity: 'critical',
      current: 2,
      baseline: 0,
      deviation: Number.POSITIVE_INFINITY,
    })
  })

  it('should avoid findings when both the sample and baseline are zero', () => {
    const findings = detectAnomalies(
      {
        validationFailRate: 0,
        invalidMacRate: 0,
        generationRate: 0,
        oneShotReplayCount: 0,
        timingVariance: 0,
      },
      {
        validationFailRate: 0,
        invalidMacRate: 0,
        generationRate: 0,
        timingVariance: 0,
      },
    )

    expect(findings).toEqual([])
  })
})
