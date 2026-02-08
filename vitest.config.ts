import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    projects: ['packages/*'],
    coverage: {
      provider: 'v8',
      thresholds: {
        lines: 90,
        branches: 85,
      },
    },
  },
})
