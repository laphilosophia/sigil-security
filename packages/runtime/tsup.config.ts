import { defineConfig } from 'tsup'

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'adapters/express': 'src/adapters/express.ts',
    'adapters/fastify': 'src/adapters/fastify.ts',
    'adapters/elysia': 'src/adapters/elysia.ts',
    'adapters/fetch': 'src/adapters/fetch.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  target: 'node18',
  sourcemap: true,
  external: [
    'express',
    'fastify',
    'elysia',
  ],
})
