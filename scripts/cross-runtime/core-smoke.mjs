import {
  WebCryptoCryptoProvider,
  createKeyring,
  createNonceCache,
  generateOneShotToken,
  generateToken,
  getActiveKey,
  validateOneShotToken,
  validateToken,
} from '../../packages/core/dist/index.js'

function assert(condition, message) {
  if (!condition) {
    throw new Error(message)
  }
}

const encoder = new TextEncoder()
const provider = new WebCryptoCryptoProvider()
// NOTE: Hardcoded master secret for cross-runtime smoke testing only.
// Do NOT copy or reuse this pattern in any production code.
const masterSecret = encoder.encode('cross-runtime-master-secret-at-least-32-bytes').buffer
const context = new Uint8Array(await provider.hash(encoder.encode('cross-runtime-context')))

const keyring = await createKeyring(provider, masterSecret, 7, 'csrf')
const activeKey = getActiveKey(keyring)
assert(activeKey !== undefined, 'missing active key')

const tokenResult = await generateToken(provider, activeKey, context)
assert(tokenResult.success, 'token generation failed')

const validationResult = await validateToken(provider, keyring, tokenResult.token, context)
assert(validationResult.valid, 'token validation failed')

const oneShotKeyring = await createKeyring(provider, masterSecret, 11, 'oneshot')
const oneShotKey = getActiveKey(oneShotKeyring)
assert(oneShotKey !== undefined, 'missing one-shot key')

const nonceCache = createNonceCache()
const oneShotResult = await generateOneShotToken(
  provider,
  oneShotKey,
  'POST:/api/critical',
  context,
)
assert(oneShotResult.success, 'one-shot token generation failed')

const oneShotValidation = await validateOneShotToken(
  provider,
  oneShotKey,
  oneShotResult.token,
  'POST:/api/critical',
  nonceCache,
  context,
)
assert(oneShotValidation.valid, 'one-shot token validation failed')

console.log('cross-runtime core smoke passed')
