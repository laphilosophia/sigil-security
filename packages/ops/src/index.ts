// @sigil-security/ops — Telemetry, monitoring, and anomaly detection
// Dependency CVEs: see repo docs/SECURITY_ADVISORIES.md

export { METRIC_POINTS } from './metric-points.js'
export type { MetricPoint } from './metric-points.js'

export { createNoopMetricsCollector } from './metrics.js'
export type { MetricLabels, MetricsCollector } from './metrics.js'

export { detectAnomalies } from './anomaly.js'
export type {
  AnomalyBaseline,
  AnomalyFinding,
  AnomalySample,
  AnomalySeverity,
  AnomalyThresholds,
} from './anomaly.js'

export { createStructuredLogger } from './structured-logger.js'
export type { LogLevel, StructuredLogEntry, StructuredLogger } from './structured-logger.js'

export { createTelemetryMiddleware } from './telemetry-middleware.js'
export type { TelemetryOptions } from './telemetry-middleware.js'
