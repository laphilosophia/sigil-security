// @sigil-security/core — LRU + TTL nonce cache (10k max, 5min TTL, atomic CAS)

import { DEFAULT_NONCE_CACHE_MAX, DEFAULT_NONCE_CACHE_TTL_MS } from './types.js'

/**
 * NonceCache interface for one-shot token replay detection.
 *
 * - In-memory LRU + TTL (custom implementation, no external dependency)
 * - Atomic compare-and-swap for `markUsed` flag — prevents race conditions
 * - Cache is an optimization, NOT a security guarantee — must fail-open if unavailable
 * - NO external storage (Redis, DB) — in-memory only
 */
export interface NonceCache {
  /**
   * Checks if a nonce exists in the cache (has been seen).
   */
  has(nonce: Uint8Array): boolean

  /**
   * Atomic compare-and-swap: marks a nonce as used.
   * Returns true if successfully marked (nonce was NOT previously used).
   * Returns false if the nonce was already used (replay detected).
   */
  markUsed(nonce: Uint8Array): boolean

  /**
   * Adds a nonce to the cache with a TTL.
   * If the cache is at capacity, the oldest (LRU) entry is evicted.
   */
  add(nonce: Uint8Array, ttlMs: number): void

  /** Current number of entries in the cache */
  readonly size: number
}

/** Internal cache entry */
interface CacheEntry {
  /** Expiration timestamp (Date.now() + ttlMs) */
  expiresAt: number
  /** Whether this nonce has been consumed (used in validation) */
  used: boolean
}

/**
 * Converts a nonce Uint8Array to a string key for Map storage.
 * Uses hex encoding for consistent, reliable key generation.
 */
function nonceToKey(nonce: Uint8Array): string {
  let key = ''
  for (const byte of nonce) {
    key += (byte >>> 4).toString(16)
    key += (byte & 0x0f).toString(16)
  }
  return key
}

/**
 * Configuration for the nonce cache.
 */
export interface NonceCacheConfig {
  /** Maximum number of entries (default: 10,000) */
  readonly maxEntries?: number
  /** Default TTL for entries in milliseconds (default: 5 minutes) */
  readonly defaultTTLMs?: number
}

/**
 * Creates an in-memory LRU + TTL nonce cache.
 *
 * Design constraints:
 * - Max 10k entries (~1MB memory at ~100 bytes per entry)
 * - 5 minute TTL (matches one-shot token TTL)
 * - LRU eviction when capacity is reached
 * - Atomic CAS for markUsed (single-threaded JS = naturally atomic)
 * - Non-distributed, non-persistent
 *
 * @param config - Optional cache configuration
 * @returns NonceCache instance
 */
export function createNonceCache(config?: NonceCacheConfig): NonceCache {
  const maxEntries = config?.maxEntries ?? DEFAULT_NONCE_CACHE_MAX
  const defaultTTLMs = config?.defaultTTLMs ?? DEFAULT_NONCE_CACHE_TTL_MS

  // Map preserves insertion order — used for LRU eviction
  const cache = new Map<string, CacheEntry>()

  /**
   * Evicts expired entries from the cache.
   * Called periodically during add/markUsed operations.
   */
  function evictExpired(): void {
    const now = Date.now()
    for (const [key, entry] of cache) {
      if (entry.expiresAt <= now) {
        cache.delete(key)
      }
    }
  }

  /**
   * Evicts the oldest entry (LRU) if the cache is at capacity.
   */
  function evictLRU(): void {
    if (cache.size >= maxEntries) {
      // Map iterator returns entries in insertion order — first is oldest
      const firstKey = cache.keys().next().value
      if (firstKey !== undefined) {
        cache.delete(firstKey)
      }
    }
  }

  return {
    has(nonce: Uint8Array): boolean {
      const key = nonceToKey(nonce)
      const entry = cache.get(key)
      if (entry === undefined) return false

      // Check if expired
      if (entry.expiresAt <= Date.now()) {
        cache.delete(key)
        return false
      }

      return true
    },

    markUsed(nonce: Uint8Array): boolean {
      const key = nonceToKey(nonce)
      const entry = cache.get(key)

      if (entry === undefined) {
        // Nonce not in cache — add it as used
        // This handles the case where validation is called without prior add
        evictExpired()
        evictLRU()
        cache.set(key, {
          expiresAt: Date.now() + defaultTTLMs,
          used: true,
        })
        return true
      }

      // Check if expired
      if (entry.expiresAt <= Date.now()) {
        cache.delete(key)
        // Treat expired entry as new — add as used
        evictLRU()
        cache.set(key, {
          expiresAt: Date.now() + defaultTTLMs,
          used: true,
        })
        return true
      }

      // Atomic CAS: if not used, mark as used and return true
      // If already used, return false (replay detected)
      if (!entry.used) {
        entry.used = true
        return true
      }

      // Already used — replay detected
      return false
    },

    add(nonce: Uint8Array, ttlMs: number): void {
      evictExpired()
      evictLRU()

      const key = nonceToKey(nonce)
      cache.set(key, {
        expiresAt: Date.now() + ttlMs,
        used: false,
      })
    },

    get size(): number {
      return cache.size
    },
  }
}
