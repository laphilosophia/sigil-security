import { describe, expect, it, vi } from 'vitest'
import { createOneShotTokenRequester } from '../src/index.js'
import type { RefreshController } from '../src/types.js'

function createRefreshControllerStub(): RefreshController {
  return {
    start(): void {},
    stop(): void {},
    async refreshIfNeeded() {
      return {
        token: 'csrf-token',
        expiresAt: 1_000,
      }
    },
    async refreshToken() {
      return {
        token: 'csrf-token',
        expiresAt: 1_000,
      }
    },
    getTokenState() {
      return {
        token: 'csrf-token',
        expiresAt: 1_000,
      }
    },
  }
}

describe('one-shot token requester', () => {
  it('should reject non-ok responses', async () => {
    const requester = createOneShotTokenRequester({
      fetch: vi.fn(async () => new Response(JSON.stringify({ error: 'denied' }), { status: 500 })),
      refreshController: createRefreshControllerStub(),
      oneShotEndpointPath: 'https://example.com/api/csrf/one-shot',
    })

    await expect(requester.request('POST:/payments')).rejects.toThrow(
      'One-shot token request failed with status 500',
    )
  })

  it('should reject invalid payload shapes', async () => {
    const requester = createOneShotTokenRequester({
      fetch: vi.fn(async () => new Response(JSON.stringify({ token: 'missing-action' }), { status: 200 })),
      refreshController: createRefreshControllerStub(),
      oneShotEndpointPath: 'https://example.com/api/csrf/one-shot',
    })

    await expect(requester.request('POST:/payments')).rejects.toThrow(
      'One-shot token request returned an invalid payload',
    )
  })
})
