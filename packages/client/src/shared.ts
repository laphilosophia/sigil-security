import type { TokenState } from './types.js'

export const DEFAULT_TOKEN_HEADER_NAME = 'x-csrf-token'
export const DEFAULT_ONESHOT_HEADER_NAME = 'x-csrf-one-shot-token'
export const EXPIRED_HEADER_NAME = 'x-csrf-token-expired'

export function isTokenState(value: unknown): value is TokenState {
  if (typeof value !== 'object' || value === null) return false

  const candidate = value as { token?: unknown; expiresAt?: unknown }
  return typeof candidate.token === 'string' && typeof candidate.expiresAt === 'number'
}

export function resolveEndpointUrl(path: string): string {
  if (/^[a-z]+:/iu.test(path)) {
    return path
  }

  if (typeof globalThis.location !== 'undefined') {
    return new URL(path, globalThis.location.href).toString()
  }

  throw new Error(
    'Sigil client: a relative endpoint path requires a browser environment. Provide a full URL instead.',
  )
}
