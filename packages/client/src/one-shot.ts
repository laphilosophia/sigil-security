import type {
  FetchLike,
  OneShotTokenRequester,
  OneShotTokenResponse,
  RefreshController,
} from './types.js'
import { DEFAULT_TOKEN_HEADER_NAME, resolveEndpointUrl } from './shared.js'

const DEFAULT_ONESHOT_ENDPOINT_PATH = '/api/csrf/one-shot'

function isOneShotTokenResponse(value: unknown): value is OneShotTokenResponse {
  if (typeof value !== 'object' || value === null) return false

  const candidate = value as { token?: unknown; expiresAt?: unknown; action?: unknown }
  return (
    typeof candidate.token === 'string' &&
    typeof candidate.expiresAt === 'number' &&
    typeof candidate.action === 'string'
  )
}

export function createOneShotTokenRequester(config: {
  readonly fetch: FetchLike
  readonly refreshController: RefreshController
  readonly oneShotEndpointPath?: string | undefined
  readonly tokenHeaderName?: string | undefined
  readonly credentials?: RequestCredentials | undefined
}): OneShotTokenRequester {
  const fetchImpl = config.fetch
  const refreshController = config.refreshController
  const oneShotEndpointPath = config.oneShotEndpointPath ?? DEFAULT_ONESHOT_ENDPOINT_PATH
  const tokenHeaderName = config.tokenHeaderName ?? DEFAULT_TOKEN_HEADER_NAME
  const credentials = config.credentials ?? 'same-origin'

  return {
    async request(action: string, context?: readonly string[]): Promise<OneShotTokenResponse> {
      const state = await refreshController.refreshToken(false)

      const response = await fetchImpl(resolveEndpointUrl(oneShotEndpointPath), {
        method: 'POST',
        credentials,
        headers: {
          'content-type': 'application/json',
          [tokenHeaderName]: state.token,
        },
        body: JSON.stringify({
          action,
          ...(context !== undefined ? { context: [...context] } : {}),
        }),
      })

      if (!response.ok) {
        throw new Error(`One-shot token request failed with status ${String(response.status)}`)
      }

      const body: unknown = await response.json()
      if (!isOneShotTokenResponse(body)) {
        throw new Error('One-shot token request returned an invalid payload')
      }

      return body
    },
  }
}

export { DEFAULT_ONESHOT_ENDPOINT_PATH }
