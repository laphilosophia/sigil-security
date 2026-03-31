import { describe, expect, it } from 'vitest'
import * as runtime from '../src/index.js'

describe('runtime public api', () => {
  it('should expose the expected runtime entry points', () => {
    expect(runtime.createSigil).toBeTypeOf('function')
    expect(runtime.createErrorResponse).toBeTypeOf('function')
    expect(runtime.createTokenResponse).toBeTypeOf('function')
    expect(runtime.createOneShotTokenResponse).toBeTypeOf('function')
    expect(runtime.extractRequestMetadata).toBeTypeOf('function')
    expect(runtime.handleTokenEndpoint).toBeTypeOf('function')
    expect(runtime.createTokenEndpointError).toBeTypeOf('function')
    expect(runtime.DEFAULT_TOKEN_ENDPOINT_PATH).toBe('/api/csrf/token')
    expect(runtime.DEFAULT_ONESHOT_ENDPOINT_PATH).toBe('/api/csrf/one-shot')
  })
})
