export type LogLevel = 'info' | 'warn' | 'error'

export interface StructuredLogEntry {
  readonly level: LogLevel
  readonly message: string
  readonly timestamp: number
  readonly context?: Readonly<Record<string, unknown>> | undefined
}

export interface StructuredLogger {
  info(message: string, context?: Readonly<Record<string, unknown>>): void
  warn(message: string, context?: Readonly<Record<string, unknown>>): void
  error(message: string, context?: Readonly<Record<string, unknown>>): void
}

function shouldRedact(key: string): boolean {
  const normalized = key.toLowerCase()
  return (
    normalized.includes('token') ||
    normalized.includes('nonce') ||
    normalized.includes('mac')
  )
}

function sanitizeValue(key: string, value: unknown, visited: WeakSet<object>): unknown {
  if (shouldRedact(key)) {
    return '[REDACTED]'
  }

  if (Array.isArray(value)) {
    if (visited.has(value)) {
      return '[Circular]'
    }

    visited.add(value)
    return value.map((item) => sanitizeValue(key, item, visited))
  }

  if (typeof value === 'object' && value !== null) {
    if (visited.has(value)) {
      return '[Circular]'
    }

    visited.add(value)
    const sanitized: Record<string, unknown> = {}
    for (const [nestedKey, nestedValue] of Object.entries(value)) {
      sanitized[nestedKey] = sanitizeValue(nestedKey, nestedValue, visited)
    }
    return sanitized
  }

  return value
}

export function createStructuredLogger(config?: {
  readonly sink?: ((entry: StructuredLogEntry) => void) | undefined
  readonly now?: (() => number) | undefined
}): StructuredLogger {
  const sink = config?.sink ?? (() => undefined)
  const now = config?.now ?? Date.now

  function write(level: LogLevel, message: string, context?: Readonly<Record<string, unknown>>): void {
    const sanitizedContext =
      context === undefined
        ? undefined
        : (sanitizeValue('context', context, new WeakSet()) as Readonly<
            Record<string, unknown>
          >)

    sink({
      level,
      message,
      timestamp: now(),
      context: sanitizedContext,
    })
  }

  return {
    info(message: string, context?: Readonly<Record<string, unknown>>): void {
      write('info', message, context)
    },

    warn(message: string, context?: Readonly<Record<string, unknown>>): void {
      write('warn', message, context)
    },

    error(message: string, context?: Readonly<Record<string, unknown>>): void {
      write('error', message, context)
    },
  }
}
