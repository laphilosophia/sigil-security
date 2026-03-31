import { bench, describe } from 'vitest'
import {
  WebCryptoCryptoProvider,
  computeAction,
  createKeyring,
  createNonceCache,
  deriveSigningKey,
  fromBase64Url,
  generateOneShotToken,
  generateToken,
  getActiveKey,
  toArrayBuffer,
  toBase64Url,
  validateOneShotToken,
  validateToken,
} from '../src/index.js'

const provider = new WebCryptoCryptoProvider()
const masterSecret = globalThis.crypto.getRandomValues(new Uint8Array(32)).buffer
const now = 1_700_000_000_000
const payload = new TextEncoder().encode('sigil-benchmark-payload')
const encodeBuffer = globalThis.crypto.getRandomValues(new Uint8Array(89))

const csrfKeyring = await createKeyring(provider, masterSecret, 1, 'csrf')
const csrfKey = getActiveKey(csrfKeyring)
if (csrfKey === undefined) {
  throw new Error('Benchmark setup failed: missing active csrf key')
}

const oneShotKeyring = await createKeyring(provider, masterSecret, 1, 'oneshot')
const oneShotKey = getActiveKey(oneShotKeyring)
if (oneShotKey === undefined) {
  throw new Error('Benchmark setup failed: missing active one-shot key')
}

const generatedToken = await generateToken(provider, csrfKey, undefined, undefined, now)
if (!generatedToken.success) {
  throw new Error(`Benchmark setup failed: ${generatedToken.reason}`)
}

const encodedPayload = toBase64Url(encodeBuffer)
const action = 'POST:/api/account/delete'
const hashedAction = await computeAction(provider, action)
const signKey = await deriveSigningKey(provider, masterSecret, 1, 'csrf')
await deriveSigningKey(provider, masterSecret, 7, 'csrf')
const signature = await provider.sign(signKey, payload)
const oneShotBenchmarkCache = createNonceCache()
const ONESHOT_BENCHMARK_FIXTURE_COUNT = 32_768

const oneShotFixtures: string[] = []

for (let index = 0; index < ONESHOT_BENCHMARK_FIXTURE_COUNT; index += 1) {
  const tokenResult = await generateOneShotToken(
    provider,
    oneShotKey,
    action,
    undefined,
    undefined,
    now + index,
  )

  if (!tokenResult.success) {
    throw new Error(`Benchmark setup failed: ${tokenResult.reason}`)
  }

  oneShotFixtures.push(tokenResult.token)
}

let oneShotCursor = 0
let hkdfColdCursor = 0

describe('core benchmarks', () => {
  bench('base64url encode', () => {
    toBase64Url(encodeBuffer)
  })

  bench('base64url decode', () => {
    fromBase64Url(encodedPayload)
  })

  bench('hmac sign', async () => {
    await provider.sign(signKey, payload)
  })

  bench('hmac verify', async () => {
    await provider.verify(signKey, signature, payload)
  })

  bench('hkdf deriveSigningKey (warm)', async () => {
    await deriveSigningKey(provider, masterSecret, 7, 'csrf')
  })

  bench('hkdf deriveKey (cold)', async () => {
    const coldProvider = new WebCryptoCryptoProvider()
    await coldProvider.deriveKey(
      masterSecret,
      'sigil-v1',
      `csrf-signing-key-benchmark-${String(hkdfColdCursor)}`,
    )
    hkdfColdCursor += 1
  })

  bench('token generation', async () => {
    await generateToken(provider, csrfKey, undefined, undefined, now)
  })

  bench('token validation', async () => {
    await validateToken(
      provider,
      csrfKeyring,
      generatedToken.token,
      undefined,
      undefined,
      undefined,
      now,
    )
  })

  bench('one-shot validation', async () => {
    const fixture = oneShotFixtures[oneShotCursor]
    if (fixture === undefined) {
      throw new Error('Benchmark setup failed: missing one-shot fixture')
    }
    oneShotCursor += 1

    await validateOneShotToken(
      provider,
      oneShotKey,
      fixture,
      action,
      oneShotBenchmarkCache,
      undefined,
      undefined,
      now,
    )
  })

  bench('action hash', async () => {
    await computeAction(provider, action)
  })

  bench('uint8array to arraybuffer copy', () => {
    toArrayBuffer(hashedAction)
  })
})
