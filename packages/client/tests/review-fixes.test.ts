import { afterEach, describe, expect, it, vi } from 'vitest'
import { createRefreshController, createTokenStore } from '../src/index.js'
import type { StorageLike } from '../src/types.js'

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

const originalLocation = globalThis.location

afterEach(() => {
  Object.defineProperty(globalThis, 'location', {
    value: originalLocation,
    writable: true,
    configurable: true,
  })
})

describe('client review fixes', () => {
  it('should reject relative endpoint paths outside browser environments', async () => {
    const tokenStore = createTokenStore({
      storage: new MemoryStorage(),
    })
    tokenStore.write({ token: 'stale', expiresAt: 1_000 })

    Object.defineProperty(globalThis, 'location', {
      value: undefined,
      writable: true,
      configurable: true,
    })

    const controller = createRefreshController({
      fetch: vi.fn(async () => new Response(JSON.stringify({
        token: 'fresh',
        expiresAt: 2_000,
      }))),
      tokenStore,
      syncChannel: {
        publish: vi.fn(),
        subscribe: vi.fn(() => (): void => undefined),
        close: vi.fn(),
      },
      leaderCoordinator: {
        runAsLeader: vi.fn(async <T,>(task: () => Promise<T>) => ({
          executed: true,
          value: await task(),
        })),
        close: vi.fn(),
      },
      tokenTTLMs: 1_000,
      now: (): number => 900,
      refreshIntervalMs: 0,
    })

    await expect(controller.refreshIfNeeded()).rejects.toThrow(
      'Sigil client: a relative endpoint path requires a browser environment. Provide a full URL instead.',
    )
  })
})
