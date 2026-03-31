import type {
  BroadcastChannelConstructorLike,
  BroadcastChannelLike,
  EventWindowLike,
  SyncChannel,
  SyncMessage,
  TokenState,
} from './types.js'
import { isTokenState } from './shared.js'

const DEFAULT_SYNC_CHANNEL_NAME = 'sigil_csrf_sync'

function createBroadcastChannel(
  BroadcastCtor: BroadcastChannelConstructorLike | undefined,
  channelName: string,
): BroadcastChannelLike | null {
  if (BroadcastCtor === undefined) {
    return null
  }

  return new BroadcastCtor(channelName)
}

function isSyncMessage(value: unknown): value is SyncMessage {
  if (typeof value !== 'object' || value === null) return false

  const candidate = value as { type?: unknown; state?: unknown }
  if (candidate.type === 'token-cleared') return true
  if (candidate.type === 'token-updated') {
    return isTokenState(candidate.state)
  }
  return false
}

export function createSyncChannel(config: {
  readonly channelName?: string | undefined
  readonly broadcastChannel?: BroadcastChannelConstructorLike | undefined
  readonly window?: EventWindowLike | undefined
  readonly tokenKey: string
  readonly readState: () => TokenState | null
}): SyncChannel {
  const listeners = new Set<(message: SyncMessage) => void>()
  const channelName = config.channelName ?? DEFAULT_SYNC_CHANNEL_NAME
  const BroadcastCtor: BroadcastChannelConstructorLike | undefined =
    config.broadcastChannel ??
    (globalThis as typeof globalThis & {
      BroadcastChannel?: BroadcastChannelConstructorLike
    }).BroadcastChannel
  const channel = createBroadcastChannel(BroadcastCtor, channelName)
  const eventWindow = config.window

  function notify(message: SyncMessage): void {
    for (const listener of listeners) {
      listener(message)
    }
  }

  const onMessage = (event: { readonly data: unknown }): void => {
    if (!isSyncMessage(event.data)) return
    notify(event.data)
  }

  const onStorage = (event: { readonly key: string | null }): void => {
    if (event.key !== config.tokenKey) return

    const state = config.readState()
    if (state === null) {
      notify({ type: 'token-cleared' })
      return
    }

    notify({ type: 'token-updated', state })
  }

  channel?.addEventListener('message', onMessage)
  eventWindow?.addEventListener('storage', onStorage)

  return {
    publish(message: SyncMessage): void {
      channel?.postMessage(message)
    },

    subscribe(listener: (message: SyncMessage) => void): () => void {
      listeners.add(listener)
      return (): void => {
        listeners.delete(listener)
      }
    },

    close(): void {
      channel?.removeEventListener('message', onMessage)
      channel?.close()
      eventWindow?.removeEventListener('storage', onStorage)
      listeners.clear()
    },
  }
}

export { DEFAULT_SYNC_CHANNEL_NAME }
