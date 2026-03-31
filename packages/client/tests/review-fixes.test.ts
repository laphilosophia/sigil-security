import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  createRefreshController,
  createSigilClient,
  createTokenStore,
  DEFAULT_TOKEN_ENDPOINT_PATH,
} from '../src/index.js'
import type {
  EventWindowLike,
  StorageLike,
  SyncChannel,
  TimerWindowLike,
} from '../src/types.js'

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
const originalNavigator = globalThis.navigator

class FakeWindow implements EventWindowLike, TimerWindowLike {
  intervalHandler: (() => void) | null = null

  addEventListener(
    _name: 'storage',
    _listener: (event: { readonly key: string | null }) => void,
  ): void {}

  removeEventListener(
    _name: 'storage',
    _listener: (event: { readonly key: string | null }) => void,
  ): void {}

  setInterval(handler: () => void, _timeoutMs: number): unknown {
    this.intervalHandler = handler
    return { handler }
  }

  clearInterval(_handle: unknown): void {}
}

afterEach(() => {
  Object.defineProperty(globalThis, 'location', {
    value: originalLocation,
    writable: true,
    configurable: true,
  })
  Object.defineProperty(globalThis, 'navigator', {
    value: originalNavigator,
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

  it('should reject protocol-relative endpoint URLs', async () => {
    const tokenStore = createTokenStore({
      storage: new MemoryStorage(),
    })
    tokenStore.write({ token: 'stale', expiresAt: 1_000 })

    const controller = createRefreshController({
      fetch: vi.fn(async () => new Response('{}')),
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
      tokenEndpointPath: '//attacker.example/token',
      tokenTTLMs: 1_000,
      now: (): number => 900,
      refreshIntervalMs: 0,
    })

    await expect(controller.refreshIfNeeded()).rejects.toThrow(
      'Sigil client: protocol-relative endpoint URLs are not allowed.',
    )
  })

  it('should reject non-http endpoint URLs', async () => {
    const tokenStore = createTokenStore({
      storage: new MemoryStorage(),
    })
    tokenStore.write({ token: 'stale', expiresAt: 1_000 })

    const controller = createRefreshController({
      fetch: vi.fn(async () => new Response('{}')),
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
      tokenEndpointPath: 'javascript:alert(1)',
      tokenTTLMs: 1_000,
      now: (): number => 900,
      refreshIntervalMs: 0,
    })

    await expect(controller.refreshIfNeeded()).rejects.toThrow(
      'Sigil client: endpoint URLs must use http: or https:.',
    )
  })

  it('should tolerate missing navigator locks in node-like environments', () => {
    Object.defineProperty(globalThis, 'navigator', {
      value: undefined,
      writable: true,
      configurable: true,
    })

    const client = createSigilClient({
      storage: new MemoryStorage(),
      window: new FakeWindow(),
      fetch: vi.fn(async () => new Response('{}')),
      autoStart: false,
    })

    expect(client.getTokenState()).toBeNull()

    client.destroy()
  })

  it('should re-check the token store before waiting for a follower sync event', async () => {
    const tokenStore = createTokenStore({
      storage: new MemoryStorage(),
    })
    const staleState = { token: 'stale', expiresAt: 1_000 }
    const freshState = { token: 'fresh', expiresAt: 5_000 }
    tokenStore.write(staleState)
    const syncChannel: SyncChannel = {
      publish(): void {},
      subscribe(): () => void {
        return (): void => undefined
      },
      close(): void {},
    }
    const fetch = vi.fn(async () => new Response(JSON.stringify(freshState)))
    const leaderCoordinator = {
      async runAsLeader<T>(_task: () => Promise<T>) {
        tokenStore.write(freshState)
        return { executed: false } as const
      },
      close(): void {},
    }
    const controller = createRefreshController({
      fetch,
      tokenStore,
      syncChannel,
      leaderCoordinator,
      tokenEndpointPath: `https://example.com${DEFAULT_TOKEN_ENDPOINT_PATH}`,
      tokenTTLMs: 1_000,
      now: (): number => 900,
      waitForSyncMs: 1,
      refreshIntervalMs: 0,
    })

    await expect(controller.refreshToken(false)).resolves.toEqual(freshState)
    expect(fetch).not.toHaveBeenCalled()
  })

  it('should contain scheduled refresh failures without unhandled rejections', async () => {
    const tokenStore = createTokenStore({
      storage: new MemoryStorage(),
    })
    tokenStore.write({ token: 'stale', expiresAt: 1_000 })
    const fakeWindow = new FakeWindow()
    const unhandled = vi.fn()

    process.once('unhandledRejection', unhandled)

    const controller = createRefreshController({
      fetch: vi.fn(async () => {
        throw new Error('refresh_failed')
      }),
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
      tokenEndpointPath: `https://example.com${DEFAULT_TOKEN_ENDPOINT_PATH}`,
      tokenTTLMs: 1_000,
      now: (): number => 900,
      refreshIntervalMs: 10,
      window: fakeWindow,
    })

    controller.start()
    fakeWindow.intervalHandler?.()
    await new Promise((resolve) => setTimeout(resolve, 0))
    process.off('unhandledRejection', unhandled)

    expect(unhandled).not.toHaveBeenCalled()

    controller.stop()
  })
})
