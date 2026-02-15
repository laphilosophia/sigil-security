import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    name: 'policy',
    setupFiles: ['../../vitest.setup.ts'],
  },
})
