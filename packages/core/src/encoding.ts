// @sigil-security/core — Encoding utilities (base64url, buffer operations)

/**
 * Encodes a Uint8Array to base64url string (RFC 4648, no padding).
 * Pure function, zero dependencies.
 */
export function toBase64Url(buffer: Uint8Array): string {
  let binary = ''
  for (const byte of buffer) {
    binary += String.fromCharCode(byte)
  }
  const base64 = btoa(binary)
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * Decodes a base64url string (RFC 4648, no padding) to Uint8Array.
 * Pure function, zero dependencies.
 *
 * @throws {Error} If the input is not valid base64url
 */
export function fromBase64Url(encoded: string): Uint8Array {
  // Restore standard base64 characters
  let base64 = encoded.replace(/-/g, '+').replace(/_/g, '/')

  // Add padding
  const padLength = (4 - (base64.length % 4)) % 4
  base64 += '='.repeat(padLength)

  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

/**
 * Writes a number as big-endian 64-bit unsigned integer into a buffer at the given offset.
 * Supports values up to Number.MAX_SAFE_INTEGER (2^53 - 1).
 * Used for token timestamp serialization.
 */
export function writeUint64BE(buffer: Uint8Array, value: number, offset: number): void {
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength)
  const high = Math.floor(value / 0x100000000)
  const low = value % 0x100000000
  view.setUint32(offset, high, false)
  view.setUint32(offset + 4, low, false)
}

/**
 * Reads a big-endian 64-bit unsigned integer from a buffer at the given offset.
 * Returns a number (safe up to 2^53 - 1).
 * Used for token timestamp deserialization.
 */
export function readUint64BE(buffer: Uint8Array, offset: number): number {
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength)
  const high = view.getUint32(offset, false)
  const low = view.getUint32(offset + 4, false)
  return high * 0x100000000 + low
}

/**
 * Converts a Uint8Array to a proper ArrayBuffer.
 * Handles the Uint8Array.buffer -> ArrayBufferLike type issue.
 * Always creates a clean copy with its own ArrayBuffer.
 */
export function toArrayBuffer(uint8: Uint8Array): ArrayBuffer {
  const copy = uint8.slice()
  return copy.buffer as unknown as ArrayBuffer
}

/**
 * Concatenates multiple Uint8Arrays into a single Uint8Array.
 * Used for token assembly.
 */
export function concatBuffers(...buffers: Uint8Array[]): Uint8Array {
  let totalLength = 0
  for (const buf of buffers) {
    totalLength += buf.length
  }

  const result = new Uint8Array(totalLength)
  let offset = 0
  for (const buf of buffers) {
    result.set(buf, offset)
    offset += buf.length
  }

  return result
}
