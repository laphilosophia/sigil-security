import type {
  FetchLike,
  OneShotActionResolver,
  OneShotTokenRequester,
  RefreshController,
  TokenState,
} from './types.js'
import {
  DEFAULT_ONESHOT_HEADER_NAME,
  DEFAULT_TOKEN_HEADER_NAME,
  EXPIRED_HEADER_NAME,
} from './shared.js'

const DEFAULT_PROTECTED_METHODS: readonly string[] = ['POST', 'PUT', 'PATCH', 'DELETE']

function needsProtection(method: string, protectedMethods: Set<string>): boolean {
  return protectedMethods.has(method.toUpperCase())
}

function applySecurityHeaders(
  request: Request,
  tokenState: TokenState,
  tokenHeaderName: string,
  oneShotHeaderName: string,
  oneShotToken: string | undefined,
  overrideHeaders: boolean,
): Request {
  const headers = new Headers(request.headers)

  if (overrideHeaders || !headers.has(tokenHeaderName)) {
    headers.set(tokenHeaderName, tokenState.token)
  }

  if (oneShotToken !== undefined && (overrideHeaders || !headers.has(oneShotHeaderName))) {
    headers.set(oneShotHeaderName, oneShotToken)
  }

  return new Request(request, { headers })
}

function shouldRetryExpired(response: Response): boolean {
  return response.status === 403 && response.headers.get(EXPIRED_HEADER_NAME) === 'true'
}

async function resolveOneShotToken(
  resolver: OneShotActionResolver,
  requester: OneShotTokenRequester,
  request: Request,
): Promise<string | undefined> {
  if (resolver === undefined) return undefined

  const action = await resolver(request)
  if (action === undefined || action === '') return undefined

  const oneShot = await requester.request(action)
  return oneShot.token
}

export function createSigilFetchInterceptor(config: {
  readonly fetch: FetchLike
  readonly refreshController: RefreshController
  readonly oneShotRequester: OneShotTokenRequester
  readonly tokenHeaderName?: string | undefined
  readonly oneShotHeaderName?: string | undefined
  readonly protectedMethods?: readonly string[] | undefined
  readonly retryOnExpired?: boolean | undefined
  readonly resolveOneShotAction?: OneShotActionResolver
}): FetchLike {
  const fetchImpl = config.fetch
  const refreshController = config.refreshController
  const oneShotRequester = config.oneShotRequester
  const tokenHeaderName = config.tokenHeaderName ?? DEFAULT_TOKEN_HEADER_NAME
  const oneShotHeaderName = config.oneShotHeaderName ?? DEFAULT_ONESHOT_HEADER_NAME
  const protectedMethods = new Set(
    (config.protectedMethods ?? DEFAULT_PROTECTED_METHODS).map((method) => method.toUpperCase()),
  )
  const retryOnExpired = config.retryOnExpired ?? true
  const resolveOneShotAction = config.resolveOneShotAction

  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const baseRequest = new Request(input, init)
    if (!needsProtection(baseRequest.method, protectedMethods)) {
      return fetchImpl(baseRequest)
    }

    const currentToken =
      refreshController.getTokenState() ?? (await refreshController.refreshToken(false))
    const oneShotToken = await resolveOneShotToken(
      resolveOneShotAction,
      oneShotRequester,
      baseRequest.clone(),
    )
    let response = await fetchImpl(
      applySecurityHeaders(
        baseRequest.clone(),
        currentToken,
        tokenHeaderName,
        oneShotHeaderName,
        oneShotToken,
        false,
      ),
    )

    if (!retryOnExpired || !shouldRetryExpired(response)) {
      return response
    }

    const refreshedToken = await refreshController.refreshToken(true)
    const retryOneShot = await resolveOneShotToken(
      resolveOneShotAction,
      oneShotRequester,
      baseRequest.clone(),
    )
    response = await fetchImpl(
      applySecurityHeaders(
        baseRequest.clone(),
        refreshedToken,
        tokenHeaderName,
        oneShotHeaderName,
        retryOneShot,
        true,
      ),
    )

    return response
  }
}

export { DEFAULT_PROTECTED_METHODS, DEFAULT_TOKEN_HEADER_NAME, DEFAULT_ONESHOT_HEADER_NAME }
