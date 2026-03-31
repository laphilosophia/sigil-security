// @sigil-security/runtime — Shared Sigil instance helpers

import { computeContext, validateOneShotToken as coreValidateOneShotToken } from '@sigil-security/core'
import type { CryptoProvider, Keyring, NonceCache, ValidationResult } from '@sigil-security/core'

/**
 * Creates an instance-scoped kid generator with 8-bit wraparound.
 */
export function createKidGenerator(initialValue: number = 0): () => number {
  let kidCounter = initialValue
  return (): number => {
    kidCounter = (kidCounter + 1) & 0xff
    return kidCounter
  }
}

/**
 * Computes request context bindings when values are present.
 */
export async function resolveContextBytes(
  cryptoProvider: CryptoProvider,
  bindings?: readonly string[],
): Promise<Uint8Array | undefined> {
  if (bindings === undefined || bindings.length === 0) {
    return undefined
  }

  return computeContext(cryptoProvider, ...bindings)
}

/**
 * Validates a one-shot token against all keys in a keyring.
 *
 * One-shot tokens do NOT embed a kid, so every active key must be tried.
 * The nonce is consumed only on the first successful validation.
 *
 * @returns The first successful result, or the last failure
 */
export async function validateOneShotWithKeyring(
  cryptoProvider: CryptoProvider,
  keyring: Keyring,
  tokenString: string,
  expectedAction: string,
  nonceCache: NonceCache,
  expectedContext: Uint8Array | undefined,
  ttlMs: number,
): Promise<ValidationResult> {
  let lastResult: ValidationResult = { valid: false, reason: 'no_keys' }

  for (const key of keyring.keys) {
    const result = await coreValidateOneShotToken(
      cryptoProvider,
      key,
      tokenString,
      expectedAction,
      nonceCache,
      expectedContext,
      ttlMs,
    )
    if (result.valid) {
      return result
    }
    lastResult = result
  }

  return lastResult
}
