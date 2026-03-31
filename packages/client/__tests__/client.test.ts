import { describe, expect, it, vi } from 'vitest'
import {
  createLeaderCoordinator,
  createRefreshController,
  createSigilClient,
  createTokenStore,
  shouldRefreshToken,
} from '../src/index.js'
import type {
  BroadcastChannelLike,
  EventWindowLike,
  LockManagerLike,
  StorageLike,
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

class FakeWindow implements EventWindowLike, TimerWindowLike {
  readonly intervals: unknown[] = []
  readonly cleared: unknown[] = []
  private readonly listeners = new Set<(event: { readonly key: string | null }) => void>()

  addEventListener(
    _name: 'storage',
    listener: (event: { readonly key: string | null }) => void,
  ): void {
    this.listeners.add(listener)
  }

  removeEventListener(
    _name: 'storage',
    listener: (event: { readonly key: string | null }) => void,
  ): void {
    this.listeners.delete(listener)
  }

  setInterval(handler: () => void, _timeoutMs: number): unknown {
    const handle = { handler }
    this.intervals.push(handle)
    return handle
  }

  clearInterval(handle: unknown): void {
    this.cleared.push(handle)
  }
}

class FakeBroadcastChannel implements BroadcastChannelLike {
  private static readonly channels = new Map<string, Set<FakeBroadcastChannel>>()

  private readonly listeners = new Set<(event: { readonly data: unknown }) => void>()

  constructor(private readonly name: string) {
    const bucket = FakeBroadcastChannel.channels.get(name) ?? new Set<FakeBroadcastChannel>()
    bucket.add(this)
    FakeBroadcastChannel.channels.set(name, bucket)
  }

  postMessage(message: unknown): void {
    const bucket = FakeBroadcastChannel.channels.get(this.name)
    if (bucket === undefined) return

    for (const channel of bucket) {
      if (channel === this) continue
      channel.emit(message)
    }
  }

  addEventListener(
    _name: 'message',
    listener: (event: { readonly data: unknown }) => void,
  ): void {
    this.listeners.add(listener)
  }

  removeEventListener(
    _name: 'message',
    listener: (event: { readonly data: unknown }) => void,
  ): void {
    this.listeners.delete(listener)
  }

  close(): void {
    FakeBroadcastChannel.channels.get(this.name)?.delete(this)
    this.listeners.clear()
  }

  private emit(data: unknown): void {
    for (const listener of this.listeners) {
      listener({ data })
    }
  }
}

class FakeLockManager implements LockManagerLike {
  private readonly held = new Set<string>()

  async request<T>(
    name: string,
    _options: { readonly ifAvailable?: boolean },
    callback: (lock: object | null) => Promise<T> | T,
  ): Promise<T> {
    if (this.held.has(name)) {
      return callback(null)
    }

    this.held.add(name)
    try {
      return await callback({ name })
    } finally {
      this.held.delete(name)
    }
  }
}

describe('client package', () => {
  it('should compute the refresh window correctly', () => {
    expect(
      shouldRefreshToken(
        {
          token: 'token-1',
          expiresAt: 1_000,
        },
        900,
        1_000,
        0.25,
      ),
    ).toBe(true)

    expect(
      shouldRefreshToken(
        {
          token: 'token-1',
          expiresAt: 1_000,
        },
        700,
        1_000,
        0.25,
      ),
    ).toBe(false)
  })

  it('should refresh when the token is in the final refresh window', async () => {
    const tokenStore = createTokenStore({
      storage: new MemoryStorage(),
    })
    tokenStore.write({ token: 'stale', expiresAt: 1_000 })

    const syncChannel = {
      publish: vi.fn(),
      subscribe: vi.fn(() => (): void => undefined),
      close: vi.fn(),
    }
    const leaderCoordinator = {
      runAsLeader: vi.fn(async <T,>(task: () => Promise<T>) => ({
        executed: true,
        value: await task(),
      })),
      close: vi.fn(),
    }
    const controller = createRefreshController({
      fetch: vi.fn(async () => new Response(JSON.stringify({
        token: 'fresh',
        expiresAt: 2_000,
      }))),
      tokenStore,
      syncChannel,
      leaderCoordinator,
      tokenTTLMs: 1_000,
      now: (): number => 900,
      refreshIntervalMs: 0,
      waitForSyncMs: 1,
    })

    const refreshed = await controller.refreshIfNeeded()

    expect(refreshed).toEqual({ token: 'fresh', expiresAt: 2_000 })
    expect(tokenStore.read()).toEqual({ token: 'fresh', expiresAt: 2_000 })
    expect(syncChannel.publish).toHaveBeenCalledWith({
      type: 'token-updated',
      state: { token: 'fresh', expiresAt: 2_000 },
    })
  })

  it('should synchronize token updates across clients', () => {
    const clientA = createSigilClient({
      storage: new MemoryStorage(),
      broadcastChannel: FakeBroadcastChannel,
      window: new FakeWindow(),
      fetch: vi.fn(async () => new Response('{}')),
      autoStart: false,
    })
    const clientB = createSigilClient({
      storage: new MemoryStorage(),
      broadcastChannel: FakeBroadcastChannel,
      window: new FakeWindow(),
      fetch: vi.fn(async () => new Response('{}')),
      autoStart: false,
    })

    clientA.setToken({ token: 'shared-token', expiresAt: 2_000 })

    expect(clientB.getTokenState()).toEqual({ token: 'shared-token', expiresAt: 2_000 })

    clientA.clearToken()

    expect(clientB.getTokenState()).toBeNull()

    clientA.destroy()
    clientB.destroy()
  })

  it('should elect a single leader during refresh races', async () => {
    const locks = new FakeLockManager()
    const coordinatorA = createLeaderCoordinator({ locks, lockName: 'refresh-lock' })
    const coordinatorB = createLeaderCoordinator({ locks, lockName: 'refresh-lock' })
    let executions = 0

    const [first, second] = await Promise.all([
      coordinatorA.runAsLeader(async () => {
        executions += 1
        await Promise.resolve()
        return 'leader'
      }),
      coordinatorB.runAsLeader(async () => {
        executions += 1
        return 'follower'
      }),
    ])

    expect(executions).toBe(1)
    expect([first.executed, second.executed].filter(Boolean)).toHaveLength(1)

    coordinatorA.close()
    coordinatorB.close()
  })

  it('should retry once after an expired-token response', async () => {
    const calls: Array<{ readonly url: string; readonly token: string | null }> = []
    const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      const url = new URL(request.url, 'https://example.com')

      if (url.pathname === '/api/csrf/token') {
        return new Response(
          JSON.stringify({
            token: 'fresh-token',
            expiresAt: 10_000,
          }),
          { status: 200 },
        )
      }

      calls.push({
        url: url.pathname,
        token: request.headers.get('x-csrf-token'),
      })

      if (calls.length === 1) {
        return new Response(JSON.stringify({ error: 'CSRF validation failed' }), {
          status: 403,
          headers: {
            'X-CSRF-Token-Expired': 'true',
          },
        })
      }

      return new Response(JSON.stringify({ ok: true }), { status: 200 })
    })

    const client = createSigilClient({
      storage: new MemoryStorage(),
      window: new FakeWindow(),
      broadcastChannel: FakeBroadcastChannel,
      fetch,
      autoStart: false,
      initialToken: {
        token: 'stale-token',
        expiresAt: 100_000,
      },
    })

    const response = await client.fetch('https://example.com/protected', {
      method: 'POST',
    })

    expect(response.status).toBe(200)
    expect(calls).toEqual([
      { url: '/protected', token: 'fresh-token' },
      { url: '/protected', token: 'fresh-token' },
    ])

    client.destroy()
  })

  it('should request one-shot tokens for protected high-assurance requests', async () => {
    const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      const url = new URL(request.url, 'https://example.com')

      if (url.pathname === '/api/csrf/token') {
        return new Response(
          JSON.stringify({
            token: 'csrf-token',
            expiresAt: 10_000,
          }),
          { status: 200 },
        )
      }

      if (url.pathname === '/api/csrf/one-shot') {
        expect(request.headers.get('x-csrf-token')).toBe('csrf-token')
        return new Response(
          JSON.stringify({
            token: 'one-shot-token',
            expiresAt: 10_000,
            action: 'POST:/payments',
          }),
          { status: 200 },
        )
      }

      expect(request.headers.get('x-csrf-token')).toBe('csrf-token')
      expect(request.headers.get('x-csrf-one-shot-token')).toBe('one-shot-token')
      return new Response(JSON.stringify({ ok: true }), { status: 200 })
    })

    const client = createSigilClient({
      storage: new MemoryStorage(),
      window: new FakeWindow(),
      broadcastChannel: FakeBroadcastChannel,
      fetch,
      autoStart: false,
      resolveOneShotAction: (): string => 'POST:/payments',
    })

    const response = await client.fetch('https://example.com/payments', {
      method: 'POST',
    })

    expect(response.status).toBe(200)

    client.destroy()
  })

  it('should clean up timers and subscriptions on destroy', () => {
    const fakeWindow = new FakeWindow()
    const client = createSigilClient({
      storage: new MemoryStorage(),
      window: fakeWindow,
      broadcastChannel: FakeBroadcastChannel,
      fetch: vi.fn(async () => new Response('{}')),
    })

    expect(fakeWindow.intervals).toHaveLength(1)

    client.destroy()

    expect(fakeWindow.cleared).toHaveLength(1)
  })
})

