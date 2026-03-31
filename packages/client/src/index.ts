// @sigil-security/client — Browser SDK for token lifecycle management

import { createLeaderCoordinator, DEFAULT_LEADER_LOCK_NAME } from './leader.js'
import {
  createRefreshController,
  DEFAULT_REFRESH_INTERVAL_MS,
  DEFAULT_REFRESH_WINDOW_RATIO,
  DEFAULT_TOKEN_ENDPOINT_PATH,
  DEFAULT_TOKEN_TTL_MS,
  shouldRefreshToken,
} from './refresh.js'
import { createSyncChannel, DEFAULT_SYNC_CHANNEL_NAME } from './sync.js'
import {
  createTokenStore,
  DEFAULT_EXPIRES_AT_KEY,
  DEFAULT_TOKEN_KEY,
} from './token-store.js'
import { createOneShotTokenRequester, DEFAULT_ONESHOT_ENDPOINT_PATH } from './one-shot.js'
import {
  createSigilFetchInterceptor,
  DEFAULT_ONESHOT_HEADER_NAME,
  DEFAULT_PROTECTED_METHODS,
  DEFAULT_TOKEN_HEADER_NAME,
} from './interceptor.js'
import type {
  EventWindowLike,
  LockManagerLike,
  SigilClient,
  SigilClientConfig,
  TimerWindowLike,
  TokenState,
} from './types.js'

function resolveFetch(fetchImpl?: typeof globalThis.fetch): typeof globalThis.fetch {
  if (fetchImpl !== undefined) return fetchImpl
  if (typeof globalThis.fetch === 'undefined') {
    throw new Error('Sigil client requires a fetch implementation')
  }
  return globalThis.fetch.bind(globalThis)
}

function resolveWindowLike(
  value?: EventWindowLike & TimerWindowLike,
): EventWindowLike & TimerWindowLike {
  if (value !== undefined) return value

  return {
    addEventListener: globalThis.addEventListener.bind(globalThis),
    removeEventListener: globalThis.removeEventListener.bind(globalThis),
    setInterval: globalThis.setInterval.bind(globalThis),
    clearInterval: globalThis.clearInterval.bind(globalThis),
  }
}

function resolveLocks(value?: LockManagerLike): LockManagerLike | undefined {
  const navigatorLike = globalThis.navigator as
    | (Navigator & { locks?: LockManagerLike })
    | undefined
  return value ?? navigatorLike?.locks
}

export type {
  BroadcastChannelConstructorLike,
  BroadcastChannelLike,
  EventWindowLike,
  FetchLike,
  LeaderCoordinator,
  LockManagerLike,
  OneShotActionResolver,
  OneShotTokenRequester,
  OneShotTokenResponse,
  RefreshController,
  SigilClient,
  SigilClientConfig,
  StorageLike,
  SyncChannel,
  SyncMessage,
  TokenState,
  TokenStore,
} from './types.js'

export {
  createLeaderCoordinator,
  DEFAULT_LEADER_LOCK_NAME,
  createRefreshController,
  DEFAULT_REFRESH_INTERVAL_MS,
  DEFAULT_REFRESH_WINDOW_RATIO,
  DEFAULT_TOKEN_ENDPOINT_PATH,
  DEFAULT_TOKEN_TTL_MS,
  shouldRefreshToken,
  createSyncChannel,
  DEFAULT_SYNC_CHANNEL_NAME,
  createTokenStore,
  DEFAULT_TOKEN_KEY,
  DEFAULT_EXPIRES_AT_KEY,
  createOneShotTokenRequester,
  DEFAULT_ONESHOT_ENDPOINT_PATH,
  createSigilFetchInterceptor,
  DEFAULT_ONESHOT_HEADER_NAME,
  DEFAULT_PROTECTED_METHODS,
  DEFAULT_TOKEN_HEADER_NAME,
}

export function createSigilClient(config: SigilClientConfig = {}): SigilClient {
  const fetchImpl = resolveFetch(config.fetch)
  const windowLike = resolveWindowLike(config.window)
  const tokenStore = createTokenStore({
    storage: config.storage,
    tokenKey: config.tokenKey ?? DEFAULT_TOKEN_KEY,
    expiresAtKey: config.expiresAtKey ?? DEFAULT_EXPIRES_AT_KEY,
  })
  const syncChannel = createSyncChannel({
    channelName: config.syncChannelName ?? DEFAULT_SYNC_CHANNEL_NAME,
    broadcastChannel: config.broadcastChannel,
    window: windowLike,
    tokenKey: tokenStore.tokenKey,
    expiresAtKey: tokenStore.expiresAtKey,
    readState: (): TokenState | null => tokenStore.read(),
  })
  const unsubscribeSync = syncChannel.subscribe((message) => {
    if (message.type === 'token-cleared') {
      tokenStore.clear()
      return
    }
    tokenStore.write(message.state)
  })
  const leaderCoordinator = createLeaderCoordinator({
    lockName: config.leaderLockName ?? DEFAULT_LEADER_LOCK_NAME,
    locks: resolveLocks(config.locks),
  })
  const refreshController = createRefreshController({
    fetch: fetchImpl,
    tokenStore,
    syncChannel,
    leaderCoordinator,
    tokenEndpointPath: config.tokenEndpointPath,
    tokenTTLMs: config.tokenTTLMs,
    refreshWindowRatio: config.refreshWindowRatio,
    refreshIntervalMs: config.refreshIntervalMs,
    credentials: config.credentials,
    now: config.now,
    waitForSyncMs: config.refreshWaitForSyncMs,
    window: windowLike,
  })
  const oneShotRequester = createOneShotTokenRequester({
    fetch: fetchImpl,
    refreshController,
    oneShotEndpointPath: config.oneShotEndpointPath,
    tokenHeaderName: config.tokenHeaderName,
    credentials: config.credentials,
  })
  const protectedFetch = createSigilFetchInterceptor({
    fetch: fetchImpl,
    refreshController,
    oneShotRequester,
    tokenHeaderName: config.tokenHeaderName ?? DEFAULT_TOKEN_HEADER_NAME,
    oneShotHeaderName: config.oneShotHeaderName ?? DEFAULT_ONESHOT_HEADER_NAME,
    protectedMethods: config.protectedMethods ?? DEFAULT_PROTECTED_METHODS,
    retryOnExpired: config.retryOnExpired,
    resolveOneShotAction: config.resolveOneShotAction,
  })

  if (config.initialToken !== undefined) {
    tokenStore.write(config.initialToken)
  }

  if (config.autoStart ?? true) {
    refreshController.start()
  }

  return {
    fetch: protectedFetch,

    start(): void {
      refreshController.start()
    },

    stop(): void {
      refreshController.stop()
    },

    destroy(): void {
      refreshController.stop()
      unsubscribeSync()
      syncChannel.close()
      leaderCoordinator.close()
    },

    getTokenState(): TokenState | null {
      return tokenStore.read()
    },

    setToken(state: TokenState): void {
      tokenStore.write(state)
      syncChannel.publish({ type: 'token-updated', state })
    },

    clearToken(): void {
      tokenStore.clear()
      syncChannel.publish({ type: 'token-cleared' })
    },

    refreshToken(force?: boolean): Promise<TokenState> {
      return refreshController.refreshToken(force)
    },

    requestOneShotToken(
      action: string,
      context?: readonly string[],
    ): Promise<{ readonly token: string; readonly expiresAt: number; readonly action: string }> {
      return oneShotRequester.request(action, context)
    },
  }
}
