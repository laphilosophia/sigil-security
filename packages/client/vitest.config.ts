import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    name: 'client',
    setupFiles: ['../../vitest.setup.ts'],
  },
})
