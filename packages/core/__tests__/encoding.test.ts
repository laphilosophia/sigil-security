import { describe, it, expect } from 'vitest'
import {
  toBase64Url,
  fromBase64Url,
  writeUint64BE,
  readUint64BE,
  concatBuffers,
} from '../src/encoding.js'

describe('encoding', () => {
  describe('toBase64Url / fromBase64Url', () => {
    it('should round-trip empty buffer', () => {
      const buf = new Uint8Array(0)
      const encoded = toBase64Url(buf)
      const decoded = fromBase64Url(encoded)
      expect(decoded).toEqual(buf)
    })

    it('should round-trip single byte', () => {
      const buf = new Uint8Array([0xff])
      const encoded = toBase64Url(buf)
      const decoded = fromBase64Url(encoded)
      expect(decoded).toEqual(buf)
    })

    it('should round-trip arbitrary data', () => {
      const buf = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
      const encoded = toBase64Url(buf)
      const decoded = fromBase64Url(encoded)
      expect(decoded).toEqual(buf)
    })

    it('should produce base64url characters (no + / =)', () => {
      // Data that would produce +, /, and = in standard base64
      const buf = new Uint8Array([0xfb, 0xef, 0xbe])
      const encoded = toBase64Url(buf)
      expect(encoded).not.toContain('+')
      expect(encoded).not.toContain('/')
      expect(encoded).not.toContain('=')
    })

    it('should round-trip 89 bytes (token size)', () => {
      const buf = new Uint8Array(89)
      globalThis.crypto.getRandomValues(buf)
      const encoded = toBase64Url(buf)
      const decoded = fromBase64Url(encoded)
      expect(decoded).toEqual(buf)
    })

    it('should round-trip 120 bytes (one-shot token size)', () => {
      const buf = new Uint8Array(120)
      globalThis.crypto.getRandomValues(buf)
      const encoded = toBase64Url(buf)
      const decoded = fromBase64Url(encoded)
      expect(decoded).toEqual(buf)
    })

    it('should decode known base64url string', () => {
      // "Hello" in base64url
      const decoded = fromBase64Url('SGVsbG8')
      const text = new TextDecoder().decode(decoded)
      expect(text).toBe('Hello')
    })

    it('should handle base64url with - and _ characters', () => {
      // [0xfb, 0xff, 0xfe] produces "+//+" in standard base64, "-__-" in base64url
      const buf = new Uint8Array([0xfb, 0xff, 0xfe])
      const encoded = toBase64Url(buf)
      expect(encoded).toBe('-__-')
      expect(encoded).not.toContain('+')
      expect(encoded).not.toContain('/')
      const decoded = fromBase64Url(encoded)
      expect(decoded).toEqual(buf)
    })

    it('should throw on invalid base64url input', () => {
      expect(() => fromBase64Url('!!!invalid!!!')).toThrow()
    })
  })

  describe('writeUint64BE / readUint64BE', () => {
    it('should round-trip zero', () => {
      const buf = new Uint8Array(8)
      writeUint64BE(buf, 0, 0)
      expect(readUint64BE(buf, 0)).toBe(0)
    })

    it('should round-trip small number', () => {
      const buf = new Uint8Array(8)
      writeUint64BE(buf, 42, 0)
      expect(readUint64BE(buf, 0)).toBe(42)
    })

    it('should round-trip Date.now() timestamp', () => {
      const now = Date.now()
      const buf = new Uint8Array(8)
      writeUint64BE(buf, now, 0)
      expect(readUint64BE(buf, 0)).toBe(now)
    })

    it('should round-trip large number', () => {
      const value = 1738886400000 // ~2025-02-07 in ms
      const buf = new Uint8Array(8)
      writeUint64BE(buf, value, 0)
      expect(readUint64BE(buf, 0)).toBe(value)
    })

    it('should round-trip MAX_SAFE_INTEGER', () => {
      const value = Number.MAX_SAFE_INTEGER
      const buf = new Uint8Array(8)
      writeUint64BE(buf, value, 0)
      expect(readUint64BE(buf, 0)).toBe(value)
    })

    it('should write in big-endian order', () => {
      const buf = new Uint8Array(8)
      writeUint64BE(buf, 0x01020304, 0)
      // High bytes should be 0, low 4 bytes should be 01 02 03 04
      expect(buf[4]).toBe(0x01)
      expect(buf[5]).toBe(0x02)
      expect(buf[6]).toBe(0x03)
      expect(buf[7]).toBe(0x04)
    })

    it('should support offset within buffer', () => {
      const buf = new Uint8Array(24)
      const value = 1234567890123
      writeUint64BE(buf, value, 8)
      expect(readUint64BE(buf, 8)).toBe(value)
      // Bytes before offset should be untouched
      expect(buf[0]).toBe(0)
      expect(buf[7]).toBe(0)
    })
  })

  describe('concatBuffers', () => {
    it('should concatenate empty arrays', () => {
      const result = concatBuffers()
      expect(result.length).toBe(0)
    })

    it('should return copy of single buffer', () => {
      const a = new Uint8Array([1, 2, 3])
      const result = concatBuffers(a)
      expect(result).toEqual(a)
      // Should be a new buffer (not same reference)
      expect(result.buffer).not.toBe(a.buffer)
    })

    it('should concatenate two buffers', () => {
      const a = new Uint8Array([1, 2, 3])
      const b = new Uint8Array([4, 5, 6])
      const result = concatBuffers(a, b)
      expect(result).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6]))
    })

    it('should concatenate multiple buffers', () => {
      const a = new Uint8Array([1])
      const b = new Uint8Array([2, 3])
      const c = new Uint8Array([4, 5, 6])
      const result = concatBuffers(a, b, c)
      expect(result).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6]))
    })

    it('should handle empty buffers in the mix', () => {
      const a = new Uint8Array([1, 2])
      const b = new Uint8Array(0)
      const c = new Uint8Array([3, 4])
      const result = concatBuffers(a, b, c)
      expect(result).toEqual(new Uint8Array([1, 2, 3, 4]))
    })
  })
})
