import { describe, expect, it } from 'vitest'
import { createSigil } from '../src/sigil.js'
import { createFetchMiddleware } from '../src/adapters/fetch.js'

describe('runtime integration flow', () => {
  const masterSecret = 'test-master-secret-at-least-32-bytes-long!'

  it('should allow a full fetch middleware flow with rotation continuity', async () => {
    const sigil = await createSigil({
      masterSecret,
      allowedOrigins: ['https://example.com'],
    })

    const tokenResult = await sigil.generateToken()
    expect(tokenResult.success).toBe(true)
    if (!tokenResult.success) return

    const middleware = createFetchMiddleware(
      sigil,
      () => new Response(JSON.stringify({ ok: true }), {
        headers: { 'content-type': 'application/json' },
      }),
    )

    const allowedResponse = await middleware(new Request('https://example.com/api/data', {
      method: 'POST',
      headers: {
        'origin': 'https://example.com',
        'sec-fetch-site': 'same-origin',
        'content-type': 'application/json',
        'x-csrf-token': tokenResult.token,
      },
      body: JSON.stringify({ action: 'update' }),
    }))

    expect(allowedResponse.status).toBe(200)
    expect(await allowedResponse.json()).toEqual({ ok: true })

    await sigil.rotateKeys()

    const rotatedValidation = await sigil.validateToken(tokenResult.token)
    expect(rotatedValidation.valid).toBe(true)

    const tamperedToken = `invalid-${tokenResult.token}`
    const blockedResponse = await middleware(new Request('https://example.com/api/data', {
      method: 'POST',
      headers: {
        'origin': 'https://example.com',
        'sec-fetch-site': 'same-origin',
        'content-type': 'application/json',
        'x-csrf-token': tamperedToken,
      },
      body: JSON.stringify({ action: 'update' }),
    }))

    expect(blockedResponse.status).toBe(403)
    expect(await blockedResponse.json()).toEqual({ error: 'CSRF validation failed' })
  })

  it('should reject one-shot replay after a successful validation', async () => {
    const sigil = await createSigil({
      masterSecret,
      allowedOrigins: ['https://example.com'],
      oneShotEnabled: true,
    })

    const tokenResult = await sigil.generateOneShotToken('POST:/api/delete', ['session-123'])
    expect(tokenResult.success).toBe(true)
    if (!tokenResult.success) return

    const firstValidation = await sigil.validateOneShotToken(
      tokenResult.token,
      'POST:/api/delete',
      ['session-123'],
    )
    expect(firstValidation.valid).toBe(true)

    const replayValidation = await sigil.validateOneShotToken(
      tokenResult.token,
      'POST:/api/delete',
      ['session-123'],
    )
    expect(replayValidation).toEqual({ valid: false, reason: 'nonce_reused' })
  })
})
