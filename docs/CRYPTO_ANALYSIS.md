# Sigil — Cryptographic Backend Analysis

**Status:** Normative
**Scope:** WebCrypto evaluation and crypto architecture decisions
**Purpose:** Document the rationale behind Sigil's cryptographic stack choices

---

## 1. Sigil's Cryptographic Requirements

Sigil's core depends on the following primitives:

- HMAC-SHA256 (integrity / authenticity)
- HKDF-SHA256 (key derivation)
- CSPRNG (nonce generation)
- Constant-time comparison
- Optional AEAD: not required (no confidentiality needed)

WebCrypto provides this set fully and correctly.

Performance characteristics:

- HMAC verification: low latency (CPU-bound)
- RNG: OS-backed, cryptographically secure
- HKDF: native, constant-time
- Cross-runtime: Node/Bun/Deno compatible

For Sigil's security model, WebCrypto is not merely sufficient — it is the correct choice.

---

## 2. WebCrypto Strengths

### (A) Native & Constant-Time

More secure than Node crypto wrappers because:

- Native implementation
- Side-channel hardened
- Constant-time primitives

Timing risk is handled by the platform, not application code.

### (B) Cross-Runtime Determinism

Sigil targets:

- Node
- Bun
- Deno
- Edge

WebCrypto provides a single API with identical behavior. This is critical for portability.

### (C) Key Isolation Model

WebCrypto key objects:

- Raw key export is not required
- Memory exposure is reduced
- HSM/KMS integration is cleaner

### (D) RNG Quality

`crypto.getRandomValues` → OS entropy → production grade.

Sufficient for nonce generation.

---

## 3. WebCrypto Limitations

### (1) No Streaming Crypto

WebCrypto does not support:

- Incremental HMAC / hash
- Streaming signatures

Sigil token size is small (~89-120 bytes) → not an issue.

### (2) No Secure Memory Control

Sensitive key material:

- No zeroization guarantee
- No GC control

Realistic risk: low, but not as strong as HSM.

### (3) Deterministic Timing Not Guaranteed

Crypto operations may be constant-time, but:

- JS runtime variance
- GC pauses
- CPU cache effects
- Branch predictor behavior

→ Micro-variance exists.

However, `network jitter >> crypto jitter` → practically sufficient.

### (4) No Direct KMS / HSM

WebCrypto is a local crypto engine:

- No remote signing
- No hardware key custody

If enterprise KMS/HSM is required:

- Abstraction layer needed
- WebCrypto becomes the fallback

### (5) Key Rotation is Application Layer

Crypto primitives are sound → lifecycle management remains in application code.

---

## 4. Architectural Improvements

WebCrypto is sufficient, but three improvements elevate the system:

### (A) Key Hierarchy + Domain Separation

```
master
 ├─ csrf      → HKDF(master, salt="sigil-v1", info="csrf-signing-key-"+kid)
 ├─ oneshot   → HKDF(master, salt="sigil-v1", info="oneshot-signing-key-"+kid)
 └─ internal  → HKDF(master, salt="sigil-v1", info="internal-signing-key-"+kid)
```

HKDF-based domain separation closes the cross-protocol attack surface.

**Status:** Adopted — implemented in `sigil-core` crypto layer.

### (B) Constant-Length Token

Fixed token lengths eliminate the length oracle:

- Regular token: 89 bytes (fixed)
- One-shot token: 120 bytes (fixed)

Context field (`ctx`) is always 32 bytes — zero-padded if context binding is not used.

**Status:** Adopted — implemented in `sigil-core` token model.

### (C) CryptoProvider Abstraction Layer

Interface:

```typescript
interface CryptoProvider {
  sign(key: CryptoKey, data: Uint8Array): Promise<ArrayBuffer>
  verify(key: CryptoKey, signature: ArrayBuffer, data: Uint8Array): Promise<boolean>
  deriveKey(master: ArrayBuffer, salt: string, info: string): Promise<CryptoKey>
  randomBytes(length: number): Uint8Array
  hash(data: Uint8Array): Promise<ArrayBuffer>
}
```

Implementations:

- WebCrypto (default, ships with core)
- Node native (future, optional)
- KMS/HSM (enterprise, optional)
- Hardware secure enclave (future)

**Status:** Adopted — interface defined in `sigil-core`, only WebCrypto implementation shipped.

---

## 5. WebCrypto vs Node crypto

| Feature          | WebCrypto | Node crypto       |
| ---------------- | --------- | ----------------- |
| Constant-time    | Yes       | Generally yes     |
| Cross-runtime    | Yes       | No                |
| Native isolation | Yes       | No                |
| Streaming        | No        | Yes               |
| HSM/KMS          | Indirect  | Easier            |
| Security model   | Modern    | Legacy-compatible |

For Sigil → WebCrypto is the correct choice.

---

## 6. Production Security Level

If the following are correctly implemented:

- HKDF derivation
- HMAC verification
- RNG (CSPRNG)
- Key lifecycle
- Side-channel minimization
- Deterministic failure model
- Token canonicalization

→ The system is cryptographically production-grade.

WebCrypto is not the bottleneck.

---

## 7. When WebCrypto Is Insufficient

The following scenarios require a crypto backend abstraction:

- Hardware key custody mandatory (HSM-only signing)
- Ultra-high assurance (FIPS strict boundary)
- Remote signing infrastructure
- Key-never-in-memory model
- Very high side-channel threat environment

In these cases:

→ CryptoProvider abstraction is used
→ WebCrypto becomes the fallback

For most systems, this is not required.

---
