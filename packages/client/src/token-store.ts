import type { StorageLike, TokenState, TokenStore } from './types.js'

class MemoryStorage implements StorageLike {
  private readonly values = new Map<string, string>()

  getItem(key: string): string | null {
    return this.values.get(key) ?? null
  }

  setItem(key: string, value: string): void {
    this.values.set(key, value)
  }

  removeItem(key: string): void {
    this.values.delete(key)
  }
}

const DEFAULT_TOKEN_KEY = 'sigil_csrf_token'
const DEFAULT_EXPIRES_AT_KEY = 'sigil_csrf_expires_at'

function resolveStorage(storage?: StorageLike): StorageLike {
  if (storage !== undefined) return storage

  if (typeof globalThis.localStorage !== 'undefined') {
    return globalThis.localStorage
  }

  return new MemoryStorage()
}

function isSameState(left: TokenState | null, right: TokenState | null): boolean {
  if (left === null || right === null) return left === right
  return left.token === right.token && left.expiresAt === right.expiresAt
}

function isValidTokenState(state: TokenState): boolean {
  return state.token !== '' && Number.isFinite(state.expiresAt) && state.expiresAt > 0
}

export function createTokenStore(config?: {
  readonly storage?: StorageLike | undefined
  readonly tokenKey?: string | undefined
  readonly expiresAtKey?: string | undefined
}): TokenStore {
  const storage = resolveStorage(config?.storage)
  const tokenKey = config?.tokenKey ?? DEFAULT_TOKEN_KEY
  const expiresAtKey = config?.expiresAtKey ?? DEFAULT_EXPIRES_AT_KEY
  const listeners = new Set<(state: TokenState | null) => void>()

  function notify(state: TokenState | null): void {
    for (const listener of listeners) {
      listener(state)
    }
  }

  function read(): TokenState | null {
    const token = storage.getItem(tokenKey)
    if (token === null || token === '') {
      return null
    }

    const expiresAtRaw = storage.getItem(expiresAtKey)
    if (expiresAtRaw === null || expiresAtRaw === '') {
      storage.removeItem(tokenKey)
      storage.removeItem(expiresAtKey)
      return null
    }

    const expiresAt = Number(expiresAtRaw)
    if (!Number.isFinite(expiresAt) || expiresAt <= 0) {
      storage.removeItem(tokenKey)
      storage.removeItem(expiresAtKey)
      return null
    }

    return { token, expiresAt }
  }

  function write(state: TokenState): void {
    if (!isValidTokenState(state)) {
      throw new Error('Sigil client: token state must include a non-empty token and positive expiry.')
    }

    const current = read()
    if (isSameState(current, state)) {
      return
    }

    storage.setItem(expiresAtKey, String(state.expiresAt))
    storage.setItem(tokenKey, state.token)
    notify(state)
  }

  function clear(): void {
    if (read() === null) {
      return
    }

    storage.removeItem(expiresAtKey)
    storage.removeItem(tokenKey)
    notify(null)
  }

  function subscribe(listener: (state: TokenState | null) => void): () => void {
    listeners.add(listener)
    return (): void => {
      listeners.delete(listener)
    }
  }

  return {
    tokenKey,
    expiresAtKey,
    read,
    write,
    clear,
    subscribe,
  }
}

export { DEFAULT_TOKEN_KEY, DEFAULT_EXPIRES_AT_KEY }
