import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    name: 'core',
    setupFiles: ['../../vitest.setup.ts'],
  },
})
