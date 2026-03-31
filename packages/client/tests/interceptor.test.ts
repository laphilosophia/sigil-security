import { describe, expect, it, vi } from 'vitest'
import { createSigilFetchInterceptor } from '../src/index.js'
import type { OneShotTokenRequester, RefreshController } from '../src/types.js'

function createRefreshControllerStub(): RefreshController {
  return {
    start(): void {},
    stop(): void {},
    async refreshIfNeeded() {
      return null
    },
    async refreshToken() {
      return {
        token: 'fresh-token',
        expiresAt: 5_000,
      }
    },
    getTokenState() {
      return {
        token: 'stale-token',
        expiresAt: 100,
      }
    },
  }
}

function createOneShotRequesterStub(): OneShotTokenRequester {
  return {
    async request() {
      return {
        token: 'one-shot-token',
        expiresAt: 5_000,
        action: 'POST:/payments',
      }
    },
  }
}

describe('fetch interceptor', () => {
  it('should refresh before attaching headers to protected requests', async () => {
    const refreshController = createRefreshControllerStub()
    const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)

      expect(request.headers.get('x-csrf-token')).toBe('fresh-token')
      return new Response(JSON.stringify({ ok: true }), { status: 200 })
    })
    const protectedFetch = createSigilFetchInterceptor({
      fetch,
      refreshController,
      oneShotRequester: createOneShotRequesterStub(),
    })

    const response = await protectedFetch('https://example.com/protected', {
      method: 'POST',
    })

    expect(response.status).toBe(200)
  })
})
