// Ensure Web Crypto API is available in test env (CI workers may not have globalThis.crypto)
import { webcrypto } from 'node:crypto'
if (typeof (globalThis as unknown as { crypto?: Crypto }).crypto === 'undefined') {
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto,
    writable: true,
    configurable: true,
  })
}

if (typeof (globalThis as { location?: URL }).location === 'undefined') {
  Object.defineProperty(globalThis, 'location', {
    value: new URL('https://example.com/app'),
    writable: true,
    configurable: true,
  })
}

if (process.env.SIGIL_TEST_DEBUG_LOGS === '1') {
  // #region agent log — runtime evidence for crypto/globalThis (hypotheses H1–H5)
  const { appendFileSync, mkdirSync } = await import('node:fs')
  const { join } = await import('node:path')
  const { fileURLToPath } = await import('node:url')
  const root = join(fileURLToPath(import.meta.url), '..')
  const dir = join(root, 'logs')
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
}
