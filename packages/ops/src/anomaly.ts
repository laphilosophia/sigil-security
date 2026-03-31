export interface AnomalyBaseline {
  readonly validationFailRate: number
  readonly invalidMacRate: number
  readonly generationRate: number
  readonly timingVariance: number
}

export interface AnomalySample {
  readonly validationFailRate: number
  readonly invalidMacRate: number
  readonly generationRate: number
  readonly oneShotReplayCount: number
  readonly timingVariance: number
}

export interface AnomalyThresholds {
  readonly warningMultiplier: number
  readonly criticalMultiplier: number
}

export type AnomalySeverity = 'warning' | 'critical'

export interface AnomalyFinding {
  readonly type: string
  readonly severity: AnomalySeverity
  readonly current: number
  readonly baseline: number
  readonly deviation: number
}

const DEFAULT_THRESHOLDS: AnomalyThresholds = {
  warningMultiplier: 2,
  criticalMultiplier: 5,
}

function ratio(current: number, baseline: number): number {
  if (baseline <= 0) {
    return current > 0 ? Number.POSITIVE_INFINITY : 0
  }
  return current / baseline
}

function buildFinding(
  type: string,
  current: number,
  baseline: number,
  thresholds: AnomalyThresholds,
): AnomalyFinding | null {
  const deviation = ratio(current, baseline)
  if (deviation >= thresholds.criticalMultiplier) {
    return {
      type,
      severity: 'critical',
      current,
      baseline,
      deviation,
    }
  }

  if (deviation >= thresholds.warningMultiplier) {
    return {
      type,
      severity: 'warning',
      current,
      baseline,
      deviation,
    }
  }

  return null
}

export function detectAnomalies(
  sample: AnomalySample,
  baseline: AnomalyBaseline,
  thresholds: AnomalyThresholds = DEFAULT_THRESHOLDS,
): readonly AnomalyFinding[] {
  const findings: AnomalyFinding[] = []

  const validationSpike = buildFinding(
    'validation_fail_spike',
    sample.validationFailRate,
    baseline.validationFailRate,
    thresholds,
  )
  if (validationSpike !== null) findings.push(validationSpike)

  const invalidMacSpike = buildFinding(
    'invalid_mac_spike',
    sample.invalidMacRate,
    baseline.invalidMacRate,
    thresholds,
  )
  if (invalidMacSpike !== null) findings.push(invalidMacSpike)

  const generationSpike = buildFinding(
    'generation_spike',
    sample.generationRate,
    baseline.generationRate,
    thresholds,
  )
  if (generationSpike !== null) findings.push(generationSpike)

  const timingVariance = buildFinding(
    'timing_variance',
    sample.timingVariance,
    baseline.timingVariance,
    thresholds,
  )
  if (timingVariance !== null) findings.push(timingVariance)

  if (sample.oneShotReplayCount > 0) {
    findings.push({
      type: 'one_shot_replay',
      severity: 'critical',
      current: sample.oneShotReplayCount,
      baseline: 0,
      deviation: Number.POSITIVE_INFINITY,
    })
  }

  return findings
}
