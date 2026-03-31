import { describe, expect, it } from 'vitest'
import { createSyncChannel } from '../src/index.js'
import type {
  BroadcastChannelLike,
  EventWindowLike,
  TokenState,
} from '../src/types.js'

class FakeWindow implements EventWindowLike {
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

  dispatchStorage(key: string | null): void {
    for (const listener of this.listeners) {
      listener({ key })
    }
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

describe('sync channel', () => {
  it('should publish storage-based updates from the window event path', () => {
    let currentState: TokenState | null = { token: 'token-1', expiresAt: 1_000 }
    const fakeWindow = new FakeWindow()
    const channel = createSyncChannel({
      window: fakeWindow,
      tokenKey: 'sigil_csrf_token',
      expiresAtKey: 'sigil_csrf_expires_at',
      readState: (): TokenState | null => currentState,
    })
    const events: unknown[] = []
    channel.subscribe((message): void => {
      events.push(message)
    })

    fakeWindow.dispatchStorage('ignored_key')
    fakeWindow.dispatchStorage('sigil_csrf_token')
    currentState = null
    fakeWindow.dispatchStorage('sigil_csrf_token')

    expect(events).toEqual([
      { type: 'token-updated', state: { token: 'token-1', expiresAt: 1_000 } },
      { type: 'token-cleared' },
    ])

    channel.close()
  })

  it('should synchronize over broadcast channel and ignore malformed payloads', () => {
    const sender = createSyncChannel({
      broadcastChannel: FakeBroadcastChannel,
      tokenKey: 'sigil_csrf_token',
      expiresAtKey: 'sigil_csrf_expires_at',
      readState: (): TokenState | null => null,
    })
    const receiver = createSyncChannel({
      broadcastChannel: FakeBroadcastChannel,
      tokenKey: 'sigil_csrf_token',
      expiresAtKey: 'sigil_csrf_expires_at',
      readState: (): TokenState | null => null,
    })
    const rawBroadcaster = new FakeBroadcastChannel('sigil_csrf_sync')
    const events: unknown[] = []

    receiver.subscribe((message): void => {
      events.push(message)
    })

    rawBroadcaster.postMessage({ type: 'token-updated', state: { token: 123, expiresAt: 'bad' } })
    sender.publish({ type: 'token-updated', state: { token: 'token-2', expiresAt: 2_000 } })

    expect(events).toEqual([
      { type: 'token-updated', state: { token: 'token-2', expiresAt: 2_000 } },
    ])

    rawBroadcaster.close()
    sender.close()
    receiver.close()
  })

  it('should react to expiry-only storage updates when the token value stays the same', () => {
    let currentState: TokenState | null = { token: 'token-1', expiresAt: 1_000 }
    const fakeWindow = new FakeWindow()
    const channel = createSyncChannel({
      window: fakeWindow,
      tokenKey: 'sigil_csrf_token',
      expiresAtKey: 'sigil_csrf_expires_at',
      readState: (): TokenState | null => currentState,
    })
    const events: unknown[] = []
    channel.subscribe((message): void => {
      events.push(message)
    })

    currentState = { token: 'token-1', expiresAt: 2_000 }
    fakeWindow.dispatchStorage('sigil_csrf_expires_at')

    expect(events).toEqual([
      { type: 'token-updated', state: { token: 'token-1', expiresAt: 2_000 } },
    ])

    channel.close()
  })
})
