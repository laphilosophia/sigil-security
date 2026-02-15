// #region agent log — runtime evidence for crypto/globalThis (hypotheses H1–H5)
import { appendFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
const root = join(fileURLToPath(import.meta.url), '..')
const dir = join(root, '.cursor')
const logPath = join(dir, 'debug.log')
const payload = {
  hypothesisId: 'H1-H5',
  location: 'vitest.setup.ts',
  message: 'crypto/globalThis check',
  data: {
    typeofCrypto: typeof (globalThis as unknown as { crypto?: unknown }).crypto,
    typeofGlobalThisCrypto: typeof globalThis.crypto,
    hasCrypto: 'crypto' in globalThis,
    nodeVersion: process.version,
    workerId: process.env.VITEST_WORKER_ID ?? 'main',
  },
  timestamp: Date.now(),
}
try {
  mkdirSync(dir, { recursive: true })
  appendFileSync(logPath, JSON.stringify(payload) + '\n')
} catch {
  // ignore
}
// #endregion
