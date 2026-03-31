import type {
  FetchLike,
  LeaderCoordinator,
  RefreshController,
  SyncChannel,
  TimerWindowLike,
  TokenState,
  TokenStore,
} from './types.js'
import { isTokenState, resolveEndpointUrl } from './shared.js'

const DEFAULT_TOKEN_TTL_MS = 20 * 60 * 1000
const DEFAULT_REFRESH_WINDOW_RATIO = 0.25
const DEFAULT_REFRESH_INTERVAL_MS = 60 * 1000
const DEFAULT_WAIT_FOR_SYNC_MS = 250
const DEFAULT_TOKEN_ENDPOINT_PATH = '/api/csrf/token'

async function parseTokenResponse(response: Response): Promise<TokenState> {
  if (!response.ok) {
    throw new Error(`Token refresh failed with status ${String(response.status)}`)
  }

  const body: unknown = await response.json()
  if (!isTokenState(body)) {
    throw new Error('Token refresh returned an invalid payload')
  }

  return body
}

function resolveTimerWindow(windowLike?: TimerWindowLike): TimerWindowLike {
  if (windowLike !== undefined) return windowLike

  return {
    setInterval: globalThis.setInterval.bind(globalThis),
    clearInterval: globalThis.clearInterval.bind(globalThis),
  }
}

async function waitForTokenUpdate(
  tokenStore: TokenStore,
  timeoutMs: number,
): Promise<TokenState> {
  return new Promise<TokenState>((resolve, reject) => {
    const timeout = globalThis.setTimeout(() => {
      unsubscribe()
      reject(new Error('Timed out waiting for token synchronization'))
    }, timeoutMs)

    const unsubscribe = tokenStore.subscribe((state) => {
      if (state === null) return
      globalThis.clearTimeout(timeout)
      unsubscribe()
      resolve(state)
    })
  })
}

export function shouldRefreshToken(
  state: TokenState,
  now: number,
  tokenTTLms: number = DEFAULT_TOKEN_TTL_MS,
  refreshWindowRatio: number = DEFAULT_REFRESH_WINDOW_RATIO,
): boolean {
  const refreshWindowMs = tokenTTLms * refreshWindowRatio
  const remaining = state.expiresAt - now
  return remaining <= refreshWindowMs
}

export function createRefreshController(config: {
  readonly fetch: FetchLike
  readonly tokenStore: TokenStore
  readonly syncChannel: SyncChannel
  readonly leaderCoordinator: LeaderCoordinator
  readonly tokenEndpointPath?: string | undefined
  readonly tokenTTLMs?: number | undefined
  readonly refreshWindowRatio?: number | undefined
  readonly refreshIntervalMs?: number | undefined
  readonly credentials?: RequestCredentials | undefined
  readonly now?: (() => number) | undefined
  readonly waitForSyncMs?: number | undefined
  readonly window?: TimerWindowLike | undefined
}): RefreshController {
  const fetchImpl = config.fetch
  const tokenStore = config.tokenStore
  const syncChannel = config.syncChannel
  const leaderCoordinator = config.leaderCoordinator
  const tokenEndpointPath = config.tokenEndpointPath ?? DEFAULT_TOKEN_ENDPOINT_PATH
  const tokenTTLMs = config.tokenTTLMs ?? DEFAULT_TOKEN_TTL_MS
  const refreshWindowRatio = config.refreshWindowRatio ?? DEFAULT_REFRESH_WINDOW_RATIO
  const refreshIntervalMs = config.refreshIntervalMs ?? DEFAULT_REFRESH_INTERVAL_MS
  const credentials = config.credentials ?? 'same-origin'
  const now = config.now ?? Date.now
  const waitForSyncMs = config.waitForSyncMs ?? DEFAULT_WAIT_FOR_SYNC_MS
  const timerWindow = resolveTimerWindow(config.window)
  let intervalHandle: unknown = null

  async function fetchToken(): Promise<TokenState> {
    const response = await fetchImpl(resolveEndpointUrl(tokenEndpointPath), {
      method: 'GET',
      credentials,
    })
      return parseTokenResponse(response)
  }

  async function refreshIfNeeded(): Promise<TokenState | null> {
    const current = tokenStore.read()
    if (current === null) return null

    if (!shouldRefreshToken(current, now(), tokenTTLMs, refreshWindowRatio)) {
      return current
    }

    return refreshToken(true)
  }

  async function refreshToken(force: boolean = false): Promise<TokenState> {
    const current = tokenStore.read()
    if (
      current !== null &&
      !force &&
      !shouldRefreshToken(current, now(), tokenTTLMs, refreshWindowRatio)
    ) {
      return current
    }

    const leaderResult = await leaderCoordinator.runAsLeader(async () => {
      const fresh = await fetchToken()
      tokenStore.write(fresh)
      syncChannel.publish({ type: 'token-updated', state: fresh })
      return fresh
    })

    if (leaderResult.executed) {
      return leaderResult.value
    }

    try {
      return await waitForTokenUpdate(tokenStore, waitForSyncMs)
    } catch {
      const fallback = await fetchToken()
      tokenStore.write(fallback)
      syncChannel.publish({ type: 'token-updated', state: fallback })
      return fallback
    }
  }

  return {
    start(): void {
      if (intervalHandle !== null || refreshIntervalMs <= 0) return

      intervalHandle = timerWindow.setInterval(() => {
        void refreshIfNeeded()
      }, refreshIntervalMs)
    },

    stop(): void {
      if (intervalHandle === null) return
      timerWindow.clearInterval(intervalHandle)
      intervalHandle = null
    },

    refreshIfNeeded,
    refreshToken,

    getTokenState(): TokenState | null {
      return tokenStore.read()
    },
  }
}

export {
  DEFAULT_TOKEN_ENDPOINT_PATH,
  DEFAULT_TOKEN_TTL_MS,
  DEFAULT_REFRESH_WINDOW_RATIO,
  DEFAULT_REFRESH_INTERVAL_MS,
}
