import { describe, it, expect } from 'vitest'

describe('@sigil-security/core', () => {
  it('should export from package', async () => {
    const mod = await import('../src/index.js')
    expect(mod).toBeDefined()
  })
})
