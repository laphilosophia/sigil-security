import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    setupFiles: ['./vitest.setup.ts'],
    projects: ['packages/*'],
    // Note: Coverage thresholds are enforced by scripts/verify-coverage.mjs.
    // Vitest is configured here only to generate the reports consumed by that script.
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary'],
      exclude: ['coverage/**', 'packages/*/coverage/**', '**/dist/**', '**/*.d.ts'],
    },
  },
})
