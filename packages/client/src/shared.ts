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
  if (path.startsWith('//')) {
    throw new Error('Sigil client: protocol-relative endpoint URLs are not allowed.')
  }

  if (/^[a-z][a-z\d+\-.]*:/iu.test(path)) {
    const url = new URL(path)
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new Error('Sigil client: endpoint URLs must use http: or https:.')
    }
    return url.toString()
  }

  if (typeof globalThis.location !== 'undefined') {
    const url = new URL(path, globalThis.location.href)
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new Error('Sigil client: endpoint URLs must use http: or https:.')
    }
    return url.toString()
  }

  throw new Error(
    'Sigil client: a relative endpoint path requires a browser environment. Provide a full URL instead.',
  )
}
