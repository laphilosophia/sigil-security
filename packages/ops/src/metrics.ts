export interface MetricLabels {
  readonly [key: string]: string
}

export interface MetricsCollector {
  increment(name: string, labels?: MetricLabels): void
  gauge(name: string, value: number, labels?: MetricLabels): void
  histogram(name: string, value: number, labels?: MetricLabels): void
}

export function createNoopMetricsCollector(): MetricsCollector {
  return {
    increment(): void {},
    gauge(): void {},
    histogram(): void {},
  }
}
