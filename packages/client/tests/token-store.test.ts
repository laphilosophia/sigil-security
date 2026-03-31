import { describe, expect, it } from 'vitest'
import { createTokenStore } from '../src/index.js'
import type { StorageLike, TokenState } from '../src/types.js'

class SpyStorage implements StorageLike {
  readonly values = new Map<string, string>()
  readonly setCalls: Array<{ readonly key: string; readonly value: string }> = []
  readonly removeCalls: string[] = []

  getItem(key: string): string | null {
    return this.values.get(key) ?? null
  }

  setItem(key: string, value: string): void {
    this.setCalls.push({ key, value })
    this.values.set(key, value)
  }

  removeItem(key: string): void {
    this.removeCalls.push(key)
    this.values.delete(key)
  }
}

describe('token store', () => {
  it('should clear corrupted expiry values during reads', () => {
    const storage = new SpyStorage()
    storage.values.set('sigil_csrf_token', 'token-1')
    storage.values.set('sigil_csrf_expires_at', 'not-a-number')

    const store = createTokenStore({ storage })

    expect(store.read()).toBeNull()
    expect(storage.removeCalls).toEqual(['sigil_csrf_token', 'sigil_csrf_expires_at'])
  })

  it('should treat an empty token as missing state', () => {
    const storage = new SpyStorage()
    storage.values.set('sigil_csrf_token', '')
    storage.values.set('sigil_csrf_expires_at', '1000')

    const store = createTokenStore({ storage })

    expect(store.read()).toBeNull()
  })

  it('should notify subscribers in write-write-clear order', () => {
    const store = createTokenStore({
      storage: new SpyStorage(),
    })
    const events: Array<TokenState | null> = []
    const unsubscribe = store.subscribe((state): void => {
      events.push(state)
    })

    store.write({ token: 'token-1', expiresAt: 1_000 })
    store.write({ token: 'token-2', expiresAt: 2_000 })
    store.clear()
    unsubscribe()
    store.write({ token: 'token-3', expiresAt: 3_000 })

    expect(events).toEqual([
      { token: 'token-1', expiresAt: 1_000 },
      { token: 'token-2', expiresAt: 2_000 },
      null,
    ])
  })

  it('should avoid duplicate writes and notifications for identical state', () => {
    const storage = new SpyStorage()
    const store = createTokenStore({ storage })
    const events: Array<TokenState | null> = []

    store.subscribe((state): void => {
      events.push(state)
    })

    store.write({ token: 'token-1', expiresAt: 1_000 })
    store.write({ token: 'token-1', expiresAt: 1_000 })

    expect(events).toEqual([{ token: 'token-1', expiresAt: 1_000 }])
    expect(storage.setCalls).toEqual([
      { key: 'sigil_csrf_expires_at', value: '1000' },
      { key: 'sigil_csrf_token', value: 'token-1' },
    ])
  })

  it('should reject non-positive expiry timestamps', () => {
    const storage = new SpyStorage()
    storage.values.set('sigil_csrf_token', 'token-1')
    storage.values.set('sigil_csrf_expires_at', '0')

    const store = createTokenStore({ storage })

    expect(store.read()).toBeNull()
    expect(storage.removeCalls).toEqual(['sigil_csrf_token', 'sigil_csrf_expires_at'])
  })

  it('should reject invalid states during writes before notifying subscribers', () => {
    const storage = new SpyStorage()
    const store = createTokenStore({ storage })
    const events: Array<TokenState | null> = []

    store.subscribe((state): void => {
      events.push(state)
    })

    expect(() => {
      store.write({ token: '', expiresAt: 0 })
    }).toThrow('Sigil client: token state must include a non-empty token and positive expiry.')

    expect(events).toEqual([])
    expect(storage.setCalls).toEqual([])
  })
})
