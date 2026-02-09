import { describe, it, expect } from 'vitest'
import {
  createErrorResponse,
  createTokenResponse,
  createOneShotTokenResponse,
} from '../src/error-response.js'

describe('error-response', () => {
  describe('createErrorResponse', () => {
    it('should return 403 with uniform error message', () => {
      const response = createErrorResponse(false)

      expect(response.status).toBe(403)
      expect(response.body.error).toBe('CSRF validation failed')
    })

    it('should NEVER differentiate error types in body', () => {
      const expired = createErrorResponse(true)
      const notExpired = createErrorResponse(false)

      // Body MUST be identical — no error oracle
      expect(expired.body.error).toBe(notExpired.body.error)
      expect(expired.body.error).toBe('CSRF validation failed')
    })

    it('should add X-CSRF-Token-Expired header when expired', () => {
      const response = createErrorResponse(true)

      expect(response.headers['X-CSRF-Token-Expired']).toBe('true')
    })

    it('should NOT add expired header when not expired', () => {
      const response = createErrorResponse(false)

      expect(response.headers['X-CSRF-Token-Expired']).toBeUndefined()
    })

    it('should have no extra headers when not expired', () => {
      const response = createErrorResponse(false)

      expect(Object.keys(response.headers)).toHaveLength(0)
    })
  })

  describe('createTokenResponse', () => {
    it('should return 200 with token and expiresAt', () => {
      const response = createTokenResponse('test-token', 1234567890)

      expect(response.status).toBe(200)
      expect(response.body.token).toBe('test-token')
      expect(response.body.expiresAt).toBe(1234567890)
    })
  })

  describe('createOneShotTokenResponse', () => {
    it('should return 200 with token, expiresAt, and action', () => {
      const response = createOneShotTokenResponse(
        'oneshot-token',
        1234567890,
        'POST:/api/delete',
      )

      expect(response.status).toBe(200)
      expect(response.body.token).toBe('oneshot-token')
      expect(response.body.expiresAt).toBe(1234567890)
      expect(response.body.action).toBe('POST:/api/delete')
    })
  })
})
