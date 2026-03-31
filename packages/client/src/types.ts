export interface TokenState {
  readonly token: string
  readonly expiresAt: number
}

export interface StorageLike {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
  removeItem(key: string): void
}

export interface StorageEventLike {
  readonly key: string | null
}

export interface EventWindowLike {
  addEventListener(name: 'storage', listener: (event: StorageEventLike) => void): void
  removeEventListener(name: 'storage', listener: (event: StorageEventLike) => void): void
}

export interface TimerWindowLike {
  setInterval(handler: () => void, timeoutMs: number): unknown
  clearInterval(handle: unknown): void
}

export interface BroadcastChannelMessageEventLike {
  readonly data: unknown
}

export interface BroadcastChannelLike {
  postMessage(message: unknown): void
  addEventListener(
    name: 'message',
    listener: (event: BroadcastChannelMessageEventLike) => void,
  ): void
  removeEventListener(
    name: 'message',
    listener: (event: BroadcastChannelMessageEventLike) => void,
  ): void
  close(): void
}

export interface BroadcastChannelConstructorLike {
  new (name: string): BroadcastChannelLike
}

export interface LockManagerLike {
  request<T>(
    name: string,
    options: { readonly ifAvailable?: boolean },
    callback: (lock: object | null) => Promise<T> | T,
  ): Promise<T>
}

export type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>

export interface TokenStore {
  readonly tokenKey: string
  readonly expiresAtKey: string
  read(): TokenState | null
  write(state: TokenState): void
  clear(): void
  subscribe(listener: (state: TokenState | null) => void): () => void
}

export type SyncMessage =
  | { readonly type: 'token-updated'; readonly state: TokenState }
  | { readonly type: 'token-cleared' }

export interface SyncChannel {
  publish(message: SyncMessage): void
  subscribe(listener: (message: SyncMessage) => void): () => void
  close(): void
}

export type LeaderResult<T> =
  | { readonly executed: true; readonly value: T }
  | { readonly executed: false }

export interface LeaderCoordinator {
  runAsLeader<T>(task: () => Promise<T>): Promise<LeaderResult<T>>
  close(): void
}

export interface RefreshController {
  start(): void
  stop(): void
  refreshIfNeeded(): Promise<TokenState | null>
  refreshToken(force?: boolean): Promise<TokenState>
  getTokenState(): TokenState | null
}

export interface OneShotTokenResponse {
  readonly token: string
  readonly expiresAt: number
  readonly action: string
}

export interface OneShotTokenRequester {
  request(action: string, context?: readonly string[]): Promise<OneShotTokenResponse>
}

export type OneShotActionResolver =
  | ((request: Request) => string | undefined | Promise<string | undefined>)
  | undefined

export interface SigilClient {
  readonly fetch: FetchLike
  start(): void
  stop(): void
  destroy(): void
  getTokenState(): TokenState | null
  setToken(state: TokenState): void
  clearToken(): void
  refreshToken(force?: boolean): Promise<TokenState>
  requestOneShotToken(
    action: string,
    context?: readonly string[],
  ): Promise<OneShotTokenResponse>
}

export interface SigilClientConfig {
  readonly fetch?: FetchLike | undefined
  readonly storage?: StorageLike | undefined
  readonly window?: (EventWindowLike & TimerWindowLike) | undefined
  readonly broadcastChannel?: BroadcastChannelConstructorLike | undefined
  readonly locks?: LockManagerLike | undefined
  readonly tokenEndpointPath?: string | undefined
  readonly oneShotEndpointPath?: string | undefined
  readonly tokenHeaderName?: string | undefined
  readonly oneShotHeaderName?: string | undefined
  readonly tokenTTLMs?: number | undefined
  readonly refreshWindowRatio?: number | undefined
  readonly refreshIntervalMs?: number | undefined
  readonly refreshWaitForSyncMs?: number | undefined
  readonly protectedMethods?: readonly string[] | undefined
  readonly credentials?: RequestCredentials | undefined
  readonly resolveOneShotAction?: OneShotActionResolver
  readonly initialToken?: TokenState | undefined
  readonly autoStart?: boolean | undefined
  readonly tokenKey?: string | undefined
  readonly expiresAtKey?: string | undefined
  readonly syncChannelName?: string | undefined
  readonly leaderLockName?: string | undefined
  readonly retryOnExpired?: boolean | undefined
  readonly now?: (() => number) | undefined
}
