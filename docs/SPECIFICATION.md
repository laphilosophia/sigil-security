# Sigil-Security: Technical Specification

**Versiyon:** 1.0  
**Durum:** Production-Ready  
**Kapsam:** Stateless CSRF Savunma Kütüphanesi

---

**İçindekiler:**
- [Part I: Core Specification](#part-i-core-specification)
- [Part II: Token Lifecycle](#part-ii-token-lifecycle)
- [Part III: One-Shot Token Primitive](#part-iii-one-shot-token-primitive)

---

# Part I: Core Specification
Aşağıdaki metin, modern tarayıcı davranışına ve çoklu runtime hedeflerine göre tasarlanmış stateless, kriptografik doğrulamalı, çok katmanlı bir CSRF savunma kütüphanesi için referans proje dokümanıdır. Metin, uygulama mimarisi, güvenlik modeli, doğrulama katmanları, kriptografi tercihleri, tehdit modeli, araştırma referansları ve geliştirme planını kapsar.

---

## 1. Amaç ve Kapsam

Bu projenin amacı, klasik stateful CSRF middleware yaklaşımının sınırlamalarını ortadan kaldıran, modern tarayıcı güvenlik sinyallerini birincil doğrulama kaynağı olarak kullanan, stateless ve kriptografik olarak doğrulanabilir bir CSRF koruma kütüphanesi üretmektir. Hedef, Node.js, Bun ve Deno runtime’larında aynı çekirdek doğrulama mantığını çalıştırabilen, framework-agnostic bir güvenlik katmanı sağlamaktır.

Bu kütüphane yalnızca token üretip doğrulayan bir middleware değildir. Modern CSRF savunması, token + tarayıcı sinyalleri + istek bağlamı doğrulamasının birleşimidir. Bu nedenle tasarım, çok katmanlı doğrulama prensibine dayanır.

---

## 2. Tehdit Modeli

Korunan tehdit:

- Cross-site authenticated request (klasik CSRF)
- Cookie taşıyan otomatik tarayıcı istekleri
- SameSite bypass senaryoları (redirect chains, top-level navigation)
- Token replay (zaman penceresi içinde sınırlı)
- Token exfiltration sonrası bağlam dışı kullanım

Korunmayan tehdit:

- XSS (CSRF savunması XSS’i engellemez; XSS varsa CSRF kırılabilir)
- MitM (TLS dışı trafik)
- Compromised client environment
- Clickjacking (ayrı savunma gerekir)
- Same-origin logic bugs

Bu sınırlar dokümantasyonda açık şekilde belirtilmelidir.

---

## 3. Mimari Tasarım

Çekirdek doğrulama mantığı saf fonksiyonlardan oluşur ve runtime bağımsızdır. Adaptör katmanı framework’e göre HTTP soyutlamasını çevirir.

Katmanlar:

1. **Core (runtime-agnostic)**
   Token encode/decode, HMAC doğrulama, zaman penceresi, bağlam doğrulama.

2. **Policy Engine**
   Fetch Metadata, Origin/Referer, Method, Content-Type, Same-site ilişkisi.

3. **Adapters**
   Express, Fastify, Hono, Oak, Elysia, native fetch.

4. **Crypto Layer**
   WebCrypto (Node 18+, Bun, Deno). Native bağımlılık yok.

Stateless tasarım sayesinde oturum deposu, Redis veya sticky session gerekmez.

---

## 4. Token Modeli

### 4.1 Token Yapısı

Token yapısı:

```
base64url(
  kid | nonce | ts | ctx | mac
)
```

Alanlar:

- **kid**: Key ID (8-bit, key rotation için)
- **nonce**: 128-bit rastgele değer (crypto.getRandomValues)
- **ts**: unix timestamp (int64, big-endian)
- **ctx**: bağlayıcı veri (opsiyonel, SHA-256 hash)
- **mac**: HMAC-SHA256(derived_key, kid|nonce|ts|ctx)

### 4.2 Kriptografik Parametreler (Sabit)

**Entropy:**

- Nonce: 128-bit (16 byte) — crypto.getRandomValues
- Minimum entropy: 2^128 (collision resistance)

**MAC:**

- HMAC-SHA256 (256-bit output)
- **MAC truncation yapılmaz** (timing oracle riski)
- Full 256-bit MAC kullanılır

**Encoding:**

- base64url (RFC 4648)
- **Padding yok** (canonical form)
- Max token length: ~120 karakter

**Key Derivation:**

- HKDF-SHA256 (RFC 5869)
- Master secret → versioned signing keys
- Key rotation için kid (Key ID) kullanılır

### 4.3 Token Özellikleri

- Sunucu tarafında saklama yok (stateless)
- Token çalınsa bile bağlam dışı kullanılamaz (context binding)
- TTL ile replay penceresi sınırlanır (**tasarım sınırı, zafiyet değil**)
- Constant-time doğrulama (timing attack koruması)
- Deterministic failure path (error oracle koruması)

### 4.4 Token Replay Modeli

**Önemli:** Token replay, stateless + TTL modelinde **kaçınılmaz tasarım sınırıdır**, zafiyet değildir.

Replay koruması:

- TTL penceresi (önerilen: 10-30 dakika)
- Context binding (session/user/origin)
- Origin validation (cross-site replay engellenir)

Replay saldırısı için gerekli:

- Valid token (exfiltration)
- Valid cookie (session)
- Valid origin (same-site)

Bu noktada saldırı CSRF değil, **token exfiltration** (XSS) olur.

---

## 5. Doğrulama Katmanları

Token tek başına yeterli kabul edilmez. Çok katmanlı politika uygulanır.

### 5.1 Fetch Metadata

`Sec-Fetch-Site`:

- same-origin / same-site → izin
- cross-site → reddet (state-changing request)

Bu, modern tarayıcılarda düşük maliyetli ve güçlü filtredir.

**Destek:**

- Chrome 76+
- Firefox 90+
- Edge 79+
- Safari 16.4+ (partial)

**Legacy Browser Davranışı:**

**Risk Değerlendirmesi:** Modern web'de Fetch Metadata olmayan browser payı **düşük ama non-zero**.

**Fallback Stratejisi:**

#### Degraded Mode (Önerilen)

- Fetch Metadata yok → degrade to Origin + Token validation
- Origin/Referer + Token zorunlu
- Log warning (legacy browser detected)

#### Strict Mode (High-Security)

- Fetch Metadata yok → reject
- Modern browser zorunlu
- User-Agent whitelist opsiyonel

**Konfigürasyon:**

```javascript
{
  legacyBrowserMode: 'degraded' | 'strict',
  requireFetchMetadata: false // degraded mode için
}
```

Referans: W3C Fetch Metadata Request Headers

---

### 5.2 Origin / Referer

- Origin header varsa strict match
- Yoksa Referer fallback
- Cross-origin mismatch → reddet

Referans: RFC 6454 (Origin)

---

### 5.3 SameSite Politika

Varsayılan:

- `SameSite=Lax`
- `Secure` zorunlu
- `Strict` opsiyonel

CSRF paketi cookie üretmez; ancak doğrulama politikası expose edilir.

Referans: RFC 6265bis

---

### 5.4 HTTP Method Koruması

Korunan:

- POST
- PUT
- PATCH
- DELETE

GET default olarak korunmaz.

---

### 5.5 Content-Type Kısıtı

İzin verilen:

- application/json
- application/x-www-form-urlencoded
- multipart/form-data

Diğerleri reddedilebilir veya opsiyonel bırakılır.

---

### 5.6 Token Doğrulama

Adımlar:

1. Token parse
2. Zaman penceresi kontrolü
3. HMAC doğrulama
4. Bağlam doğrulama (opsiyonel)

### 5.7 Side-Channel Koruması

**Kritik:** Timing attack tek side-channel değildir.

#### Timing Attack

- **Constant-time HMAC doğrulama** zorunlu
- Crypto API native constant-time kullanmalı
- String comparison yerine crypto.timingSafeEqual

#### Early Reject Leakage

- Token parse başarısız → hemen reject **YAPILMAZ**
- TTL expired → hemen reject **YAPILMAZ**
- Tüm doğrulama adımları tamamlanır
- **Single failure path** (her hata aynı response time)

#### Error Type Oracle

- "Invalid token" vs "Expired token" vs "Invalid signature" → **AYR EDILMAZ**
- Tek error message: "CSRF validation failed"
- Error detail loglanır ama client'a gönderilmez

#### Token Length Oracle

- Token length validation → constant-time
- Short token → padding ile normalize edilir
- Length leak → token format inference riski

#### Branch Prediction Leak

- Conditional branch → timing variation
- Crypto operations → branch-free implementation
- Modern CPU speculative execution riski (nadir ama var)

### 5.8 Deterministic Failure Model

**Single Failure Path Prensibi:**

```
validate(token):
  valid = true

  # Parse (constant-time)
  parsed = parse(token)
  valid &= parsed.success

  # TTL check (constant-time)
  ttl_valid = check_ttl(parsed.ts)
  valid &= ttl_valid

  # HMAC verify (constant-time)
  mac_valid = verify_mac(parsed)
  valid &= mac_valid

  # Context check (constant-time)
  ctx_valid = verify_context(parsed.ctx)
  valid &= ctx_valid

  # Single exit point
  if valid:
    return SUCCESS
  else:
    return FAILURE  # Same response time
```

**Avantajlar:**

- Timing leak yok
- Error oracle yok
- Branch prediction leak minimal

---

## 6. Bağlam Bağlama (Context Binding)

### 6.1 Temel Kavram

Opsiyonel güvenlik artırımı:

- session id hash
- user id hash
- origin hash
- deployment salt
- per-form nonce

Yanlış konfigürasyon false-negative üretebileceği için default kapalıdır.

### 6.2 Risk Tier Modeli

**Kritik:** Context binding her endpoint için aynı katılıkta uygulanmamalıdır.

#### Low Assurance (Relaxed Binding)

- **Endpoint türü:** Read-only, non-destructive
- **Binding:** Opsiyonel veya soft-fail
- **Örnek:** Profil görüntüleme, liste sorgulama

#### Medium Assurance (Standard Binding)

- **Endpoint türü:** State-changing ama reversible
- **Binding:** Session ID hash (soft-fail with grace period)
- **Örnek:** Profil güncelleme, ayar değişikliği

#### High Assurance (Strict Binding)

- **Endpoint türü:** Financial, destructive, irreversible
- **Binding:** Session + User + Origin hash (fail-closed)
- **Örnek:** Para transferi, hesap silme, yetki değişikliği

### 6.3 Soft-Fail vs Fail-Closed

**Soft-Fail (Medium Assurance):**

- Context mismatch → log warning + allow
- Grace period: 5 dakika (session rotation toleransı)
- Telemetry ile false-negative oranı ölçülür

**Fail-Closed (High Assurance):**

- Context mismatch → reject + audit log
- Grace period yok
- Security > usability

### 6.4 False-Negative Mitigation

- Session rotation sonrası 5 dakika grace period
- Multi-device login detection (user agent fingerprint)
- Telemetry: context mismatch rate < %1 hedefi

---

## 7. Key Management ve Rotation

### 7.1 Key Derivation

**Master Secret → Signing Keys:**

```
HKDF-SHA256(
  master_secret,
  salt = "sigil-csrf-v1",
  info = "signing-key-" + kid
)
```

**Avantajlar:**

- Versioned keys (kid ile)
- Master secret leak → sadece rotation gerekir
- Raw secret yerine derived key kullanımı

### 7.2 Key Rotation Stratejisi

**Keyring Modeli:**

- Active key (kid = current)
- Previous keys (kid = current-1, current-2, ...)
- Max keyring size: 3 (active + 2 previous)

**Rotation Frekansı:**

- **Önerilen:** 7 gün (haftalık)
- **Minimum:** 1 gün (günlük, high-security)
- **Maximum:** 30 gün (aylık, low-risk)

**Rotation Prosedürü:**

1. Yeni key derive edilir (kid++)
2. Eski active key → previous keys
3. Token generation yeni key ile
4. Token validation tüm keyring ile
5. Oldest key drop edilir (keyring size limit)

**Kesintisiz Rotation:**

- TTL + keyring overlap sayesinde zero-downtime
- Örn: TTL=30dk, rotation=7gün → 30dk overlap yeterli

### 7.3 Key Compromise Senaryoları

**Senaryo 1: Signing Key Leak (kid-specific)**

- Etki: Saldırgan o kid ile valid token üretebilir
- Mitigation: Emergency rotation (kid invalidate)
- Blast radius: Sadece o kid'li tokenlar

**Senaryo 2: Master Secret Leak**

- Etki: Tüm derived keyler compromise
- Mitigation: Master secret rotation + tüm kid'ler invalidate
- Blast radius: Tüm aktif tokenlar geçersiz

**Ayrım Kritik:** Key rotation (normal) vs key compromise (emergency)

---

## 8. Runtime Uyumluluğu ve Client Çeşitliliği

### 8.1 Runtime Desteği

Tek kripto API: **WebCrypto**

Destek:

- Node ≥18
- Bun
- Deno
- Edge runtimes (Cloudflare Workers, Vercel Edge)

Stream tüketmeyen doğrulama; serverless uyumlu.

### 8.2 Browser vs API Mode

**Kritik:** Dokümantasyon tamamen browser varsayımıyla yazılmış. Gerçek dünyada non-browser client'lar var.

#### Browser Mode (Default)

- **Client:** Modern tarayıcı
- **Validation:** Full multi-layer (Fetch Metadata + Origin + Token)
- **Fetch Metadata:** Enforce
- **Origin/Referer:** Enforce

#### API Mode (Non-Browser)

- **Client:** Mobile app, CLI, internal service, curl, bot
- **Validation:** Token-only (Fetch Metadata yok)
- **Fetch Metadata:** Skip (header yok)
- **Origin/Referer:** Optional (güvenilir client ise skip)

#### Mode Detection

**Otomatik:**

- `Sec-Fetch-Site` header var → Browser Mode
- `Sec-Fetch-Site` header yok → API Mode

**Manuel:**

- `X-Client-Type: api` header → Force API Mode
- Configuration: `allowApiMode: true/false`

#### API Mode Güvenlik

API Mode'da Fetch Metadata yok ama:

- Token doğrulama zorunlu
- Context binding önerilir (API key hash)
- Rate limiting zorunlu
- IP whitelist opsiyonel

### 8.3 Token Transport Canonicalization

**Kritik:** Token taşıma kanalı belirsizliği bug üretir.

#### Transport Precedence (Strict Order)

1. **Custom Header** (önerilen): `X-CSRF-Token`
2. **Request Body** (JSON): `{ "csrf_token": "..." }`
3. **Request Body** (form): `csrf_token=...`
4. **Query Parameter** (deprecated, güvensiz): `?csrf_token=...`

**Precedence Kuralı:**

- İlk bulunan geçerli token kullanılır
- Multiple token → first match wins
- Duplicate header → first value

#### Ambiguity Handling

**Multiple Token Conflict:**

- Header + Body farklı token → header öncelikli
- Body JSON + Form → JSON öncelikli
- Log warning (suspicious behavior)

**Duplicate Header:**

- İlk değer kullanılır
- Audit log (potential attack)

**Content-Type Mismatch:**

- `Content-Type: application/json` ama form data → reject
- `Content-Type: application/x-www-form-urlencoded` ama JSON → reject

**Missing Token:**

- State-changing method (POST/PUT/PATCH/DELETE) → reject
- GET → allow (ama log if suspicious)

### 8.4 Fetch Metadata Edge-Cases

**Same-Site but Cross-Origin (Subdomain):**

- `Sec-Fetch-Site: same-site`
- `Origin: https://api.example.com`
- `Referer: https://app.example.com`
- **Karar:** Allow (same-site) ama log (cross-origin)

**Service Worker Initiated Request:**

- Service worker → `Sec-Fetch-Site` değişebilir
- **Karar:** Fallback to Origin/Referer validation

**Browser Extension Initiated Request:**

- Extension → `Sec-Fetch-Site: none` veya eksik
- **Karar:** Reject (untrusted origin)

**Preflight-less Credentialed Request:**

- Simple request (GET/POST form) → preflight yok
- **Karar:** Fetch Metadata + Token zorunlu

### 8.5 Non-Browser Client Örnekleri

**Mobile App:**

- Native HTTP client (URLSession, OkHttp)
- Fetch Metadata yok
- API Mode + Token + API key hash

**CLI Tool:**

- curl, wget
- Fetch Metadata yok
- API Mode + Token + user authentication

**Internal Service:**

- Server-to-server
- Fetch Metadata yok
- API Mode + Token + service authentication

**Bot/Scraper:**

- Headless browser veya HTTP client
- Fetch Metadata var/yok (depends)
- Browser Mode (headless) veya API Mode (HTTP client)

---

## 9. Güvenlik Notları

1. XSS varsa CSRF kırılır.
2. Token gizli değildir; yalnızca bütünlük doğrular.
3. SameSite tek başına yeterli değildir.
4. Origin kontrolü devre dışı bırakılmamalıdır.
5. Fetch Metadata bypass edilemez kabul edilmemelidir (legacy browser).
6. Clock skew toleransı uygulanmalıdır.
7. Token TTL kısa tutulmalıdır (10–30 dk).
8. Constant-time MAC doğrulaması zorunludur.
9. Token loglanmamalıdır.
10. Token URL parametresinde taşınmamalıdır.

---

## 10. Test Stratejisi

- Cross-origin POST simülasyonu
- SameSite bypass edge-case
- Key rotation
- Clock skew
- Malformed token fuzzing
- Replay testi
- Constant-time side-channel ölçümü
- High concurrency stateless doğrulama

---

## 11. Performans Hedefi

- O(1) doğrulama
- No I/O
- No storage
- Token doğrulama < 50µs
- Memory footprint minimal

---

## 12. Geliştirme Planı

Faz 1 — Core

- Token encode/decode
- HMAC doğrulama
- TTL
- Context binding

Faz 2 — Policy Engine

- Fetch Metadata
- Origin/Referer
- Method / Content-Type

Faz 3 — Adapters

- Express
- Fastify
- Hono
- Oak
- Elysia
- Native fetch

Faz 4 — Security Hardening

- Constant-time
- Fuzzing
- Key rotation
- Side-channel test

Faz 5 — Docs & Threat Model

- Misuse scenarios
- Security boundaries
- Deployment guidance

---

## 13. Araştırma Referansları / Citation

CSRF ve modern savunma:

- Barth, Jackson, Mitchell — Robust Defenses for CSRF (Stanford)
- OWASP CSRF Prevention Cheat Sheet
- RFC 6454 — The Origin Header
- RFC 6265bis — Cookies: HTTP State Management Mechanism
- W3C Fetch Metadata Request Headers
- Google Web Fundamentals — SameSite Cookies Explained
- Chrome Security — Defense in Depth for CSRF
- Mozilla Web Security Guidelines

Token & kriptografi:

- NIST SP 800-107 — HMAC Security
- RFC 2104 — HMAC
- RFC 4648 — Base64url
- OWASP Cryptographic Storage Cheat Sheet

Side-channel & constant-time:

- Kocher — Timing Attacks
- OWASP Side Channel Attack Guidance

Stateless security models:

- JWT BCP — RFC 8725 (token misuse ve binding konuları)
- Macaroons — Context-bound token yaklaşımı

---

## 14. Geçerlilik ve Güvenlik Argümanı

Bu model, klasik synchronizer token yaklaşımına göre:

- Storage gerektirmez
- Horizontal scale uyumlu
- Edge/serverless uyumlu
- Modern tarayıcı sinyallerini kullanır
- Token çalınsa bile bağlam dışı kullanımı sınırlar
- Replay yüzeyini zaman penceresi ile daraltır
- Defense-in-depth uygular

Güvenlik, tek mekanizmaya değil katmanların birleşimine dayanır.

---

## 15. Açık Araştırma Alanları

- Fetch Metadata olmayan legacy browser davranışı
- Token binding vs session binding doğruluk oranı
- SameSite bypass varyasyonları
- HTTP/3 ve service worker etkileri
- Browser privacy partitioning etkisi
- WebView davranışları
- Cross-origin iframe + credential mode edge-case

Bu alanlar için gerçek dünya testleri önerilir.

---

Bu doküman, modern web güvenliği bağlamında üretilecek stateless, kriptografik ve çok katmanlı bir CSRF savunma kütüphanesi için teknik temel ve referans çerçevesi sağlar. Geliştirme süreci sırasında tehdit modeli ve politika varsayımları yeniden doğrulanmalıdır.

---

# Part II: Token Lifecycle
# Token Lifecycle Specification

**Versiyon:** 1.0
**Durum:** Formal Specification
**Hedef:** SPA + Multi-Tab + Rotation

---

## 1. Genel Bakış

Token lifecycle, CSRF korumasının **en kırılgan noktasıdır**. Bu spesifikasyon, token üretim, yenileme, senkronizasyon ve invalidation semantiğini tanımlar.

### Tasarım Prensipleri

1. **Per-Session Token** (per-request değil)
2. **Lazy Rotation** (proactive değil)
3. **Hard Expiry** (sliding TTL değil)
4. **Multi-Tab Sync** (BroadcastChannel / storage)
5. **Silent Refresh** (user interaction gerektirmez)

---

## 2. Generation Modeli

### 2.1 Token Generation Timing

**Per-Session Model (Önerilen):**

```
Session Start → Generate Token
Token Expiry → Silent Refresh
Session End → Token Discard
```

**Alternatif (Per-Request):**

- Her request için yeni token → yüksek overhead
- **Reddedilme Nedeni:** Stateless modelde gereksiz complexity

### 2.2 Generation Trigger

**Initial Generation:**

- Session oluşturulduğunda (login, anonymous session)
- Token yok veya expired

**Refresh Generation:**

- TTL son %25'inde (örn: 20dk TTL → son 5dk)
- Client-initiated (background fetch)
- Server-initiated (response header: `X-CSRF-Token-Refresh: true`)

### 2.3 Generation Endpoint

**Dedicated Endpoint (Önerilen):**

```
GET /api/csrf/token
Response: { "token": "...", "expiresAt": 1234567890 }
```

**Inline Generation (Alternatif):**

- Her response'da `X-CSRF-Token` header
- **Trade-off:** Overhead vs convenience

---

## 3. Refresh Stratejisi

### 3.1 Refresh Window

**Parametreler:**

```javascript
{
  tokenTTL: 20 * 60 * 1000,        // 20 dakika
  refreshWindow: 0.25,              // Son %25 (5 dakika)
  refreshInterval: 60 * 1000,       // 1 dakika check
  graceWindow: 60 * 1000            // 60 saniye overlap
}
```

**Refresh Logic:**

```javascript
function shouldRefresh(token) {
  const now = Date.now()
  const expiresAt = token.expiresAt
  const ttl = expiresAt - token.issuedAt
  const remaining = expiresAt - now

  // Refresh window = son %25
  return remaining < ttl * 0.25
}
```

### 3.2 Silent Refresh

**Client-Side Implementation:**

```javascript
// Background refresh (user interaction gerektirmez)
async function silentRefresh() {
  try {
    const response = await fetch('/api/csrf/token', {
      credentials: 'same-origin',
    })
    const { token, expiresAt } = await response.json()

    // Storage'a yaz (multi-tab sync için)
    localStorage.setItem('csrf_token', token)
    localStorage.setItem('csrf_expires_at', expiresAt)

    // BroadcastChannel ile diğer tab'lara notify
    broadcastChannel.postMessage({ type: 'token_refresh', token, expiresAt })
  } catch (error) {
    // Fallback: next request'te 403 → force refresh
  }
}

// Periodic check
setInterval(() => {
  const token = getCurrentToken()
  if (shouldRefresh(token)) {
    silentRefresh()
  }
}, 60 * 1000) // Her 1 dakikada check
```

### 3.3 Grace Window

**Sorun:** Refresh sırasında eski token hala kullanılıyor olabilir (in-flight request).

**Çözüm:** 60 saniye grace window

```javascript
// Server-side validation
function validateToken(token) {
  const parsed = parseToken(token)
  const now = Date.now()

  // Hard expiry check
  if (now > parsed.expiresAt) {
    // Grace window check
    if (now - parsed.expiresAt < GRACE_WINDOW) {
      // Log warning ama allow
      logger.warn('Token in grace window', { kid: parsed.kid })
      return { valid: true, inGraceWindow: true }
    }
    return { valid: false, reason: 'expired' }
  }

  return { valid: true }
}
```

---

## 4. Multi-Tab Synchronization

### 4.1 Sorun

Kullanıcı aynı anda birden fazla tab açabilir:

- Tab A token refresh yapar
- Tab B eski token kullanır → 403

### 4.2 Çözüm: BroadcastChannel + Storage

**BroadcastChannel (Modern):**

```javascript
const channel = new BroadcastChannel('csrf_sync')

// Token refresh sonrası notify
channel.postMessage({
  type: 'token_refresh',
  token,
  expiresAt,
})

// Diğer tab'larda listen
channel.onmessage = (event) => {
  if (event.data.type === 'token_refresh') {
    updateLocalToken(event.data.token, event.data.expiresAt)
  }
}
```

**Storage Event (Fallback):**

```javascript
// localStorage değişikliğini dinle
window.addEventListener('storage', (event) => {
  if (event.key === 'csrf_token') {
    updateLocalToken(event.newValue)
  }
})
```

### 4.3 Race Condition Koruması

**Sorun:** İki tab aynı anda refresh yaparsa?

**Çözüm:** Leader election

```javascript
// Sadece bir tab refresh yapar
const isLeader = await navigator.locks.request(
  'csrf_refresh_lock',
  { ifAvailable: true },
  async (lock) => {
    if (lock) {
      await silentRefresh()
      return true
    }
    return false
  },
)
```

---

## 5. Token Invalidation

### 5.1 Logout Semantiği

**Stateless Model → Instant Revoke Yok**

**Kabul Edilen Davranış:**

```
Logout → Cookie delete
Token → TTL expire olana kadar geçerli (max 20dk)
Risk: Düşük (CSRF için cookie gerekir)
```

**Kullanıcı Beklentisi Yönetimi:**

- Dokümantasyonda açıkça belirt
- Security FAQ'de yer ver
- High-security ortamda short TTL (10dk)

### 5.2 Opsiyonel: Kid Bump (Mini Rotation)

**Logout sonrası immediate invalidation için:**

```javascript
// Logout endpoint
POST /api/auth/logout
Response: {
  success: true,
  csrfKidBump: true  // Client yeni token alsın
}

// Server-side
function logout(sessionId) {
  // Session sil
  deleteSession(sessionId);

  // Kid bump (opsiyonel)
  if (config.csrfKidBumpOnLogout) {
    rotateKey(); // kid++
  }
}
```

**Trade-off:**

- ✅ Immediate invalidation
- ❌ Tüm kullanıcılar etkilenir (kid global)

### 5.3 Opsiyonel: Revocation Filter

**High-security ortamlar için:**

```javascript
// Bloom filter / LRU cache
const revokedTokens = new LRUCache({
  max: 10000,
  ttl: 20 * 60 * 1000, // Token TTL ile aynı
})

// Logout
function logout(sessionId) {
  const sessionHash = hash(sessionId)
  revokedTokens.set(sessionHash, true)
}

// Validation
function validateToken(token, sessionId) {
  const sessionHash = hash(sessionId)
  if (revokedTokens.has(sessionHash)) {
    return { valid: false, reason: 'revoked' }
  }
  // Normal validation
}
```

**Özellikler:**

- Memory bounded (TTL ile)
- False positive tolere edilebilir
- Stateless core korunur

---

## 6. Error Handling

### 6.1 Token Expired

**Client-Side:**

```javascript
// 403 response → token expired
if (response.status === 403) {
  const newToken = await refreshToken()
  // Retry request
  return fetch(url, {
    ...options,
    headers: { 'X-CSRF-Token': newToken },
  })
}
```

**Server-Side:**

```javascript
// Expired token → 403 + refresh hint
return {
  status: 403,
  body: { error: 'CSRF validation failed' },
  headers: { 'X-CSRF-Token-Expired': 'true' },
}
```

### 6.2 Token Refresh Failure

**Fallback:**

```javascript
// Refresh başarısız → force logout
if (!(await refreshToken())) {
  // Session invalid olabilir
  forceLogout()
  redirectToLogin()
}
```

---

## 7. Implementation Checklist

### Server-Side

- [ ] Token generation endpoint (`GET /api/csrf/token`)
- [ ] TTL parametreleri (20dk default)
- [ ] Grace window validation (60s)
- [ ] Kid bump on logout (opsiyonel)
- [ ] Revocation filter (opsiyonel)

### Client-Side

- [ ] Silent refresh logic
- [ ] Refresh window check (son %25)
- [ ] Multi-tab sync (BroadcastChannel + storage)
- [ ] Leader election (race condition)
- [ ] Error handling (403 → retry)
- [ ] Logout token cleanup

### Testing

- [ ] Token expiry edge-case
- [ ] Multi-tab race condition
- [ ] Grace window overlap
- [ ] Refresh failure fallback
- [ ] Logout invalidation (kid bump)

---

## 8. Configuration Reference

```javascript
{
  // Token TTL
  tokenTTL: 20 * 60 * 1000,           // 20 dakika (default)

  // Refresh window (son %25)
  refreshWindow: 0.25,

  // Refresh check interval
  refreshInterval: 60 * 1000,         // 1 dakika

  // Grace window (overlap)
  graceWindow: 60 * 1000,             // 60 saniye

  // Logout behavior
  kidBumpOnLogout: false,             // Kid rotation on logout
  useRevocationFilter: false,         // Bloom filter / LRU

  // Multi-tab
  useBroadcastChannel: true,          // Modern browser
  useStorageEvent: true,              // Fallback

  // Endpoints
  tokenEndpoint: '/api/csrf/token',
  refreshEndpoint: '/api/csrf/token'  // Same endpoint
}
```

---

## 9. Security Considerations

### 9.1 Refresh Endpoint Security

**Kritik:** Refresh endpoint CSRF'e karşı korunmalı mı?

**Cevap:** Hayır, çünkü:

- GET request (state-changing değil)
- Same-origin only
- Cookie-based authentication

### 9.2 Token Storage

**localStorage vs sessionStorage:**

- **localStorage:** Multi-tab sync için gerekli
- **sessionStorage:** Tab-isolated, sync yok

**XSS Risk:**

- Token localStorage'da → XSS ile çalınabilir
- **Mitigation:** CSP, XSS prevention (CSRF kütüphanesi dışında)

### 9.3 Clock Skew

**Client-server clock farkı:**

- Client TTL check → server'dan farklı olabilir
- **Mitigation:** Server timestamp kullan (client clock'a güvenme)

```javascript
// Server timestamp kullan
const serverTime = response.headers.get('Date')
const expiresAt = new Date(serverTime).getTime() + tokenTTL
```

---

## 10. Sonuç

Bu spesifikasyon, **production-grade token lifecycle** için gerekli tüm semantiği tanımlar:

✅ **Per-session model** (overhead düşük)
✅ **Silent refresh** (UX etkisi yok)
✅ **Multi-tab sync** (race condition korunmalı)
✅ **Grace window** (in-flight request koruması)
✅ **Logout semantiği** (beklenti yönetimi)

**Bir sonraki adım:** One-shot token primitive (high-assurance endpoints için)

---

# Part III: One-Shot Token Primitive
# One-Shot Token Specification

**Versiyon:** 1.0
**Durum:** Formal Specification
**Hedef:** High-Assurance Request Authenticity

---

## 1. Motivasyon

Multi-use CSRF token'lar çoğu senaryo için yeterlidir. Ancak **high-risk endpoint'ler** için replay window kabul edilemez:

- Para transferi
- Hesap silme
- Yetki değişikliği
- İmza işlemleri
- Kritik konfigürasyon değişikliği

Bu endpoint'ler için **one-shot token** gereklidir: **tek kullanımlık, replay impossible**.

---

## 2. Tasarım Prensipleri

1. **Single-Use:** Token sadece bir kez kullanılabilir
2. **Bounded Cache:** Stateless core korunur (küçük TTL-bounded cache)
3. **Selective:** Sadece high-assurance endpoint'lerde kullanılır
4. **Backward Compatible:** Normal CSRF token ile birlikte çalışır

---

## 3. Token Format

### 3.1 Yapı

```
one_shot_token = base64url(
  nonce | ts | action | ctx | mac
)
```

**Alanlar:**

- **nonce:** 128-bit (crypto.getRandomValues) — **unique identifier**
- **ts:** unix timestamp (int64)
- **action:** endpoint identifier hash (SHA-256)
- **ctx:** context binding (session/user/origin hash)
- **mac:** HMAC-SHA256(secret, nonce|ts|action|ctx)

### 3.2 Action Binding

**Kritik:** Token belirli bir action'a bağlı olmalı.

```javascript
// Action identifier
const action = hash('POST:/api/account/delete')

// Token generation
const token = generateOneShotToken({
  action,
  sessionId,
  userId,
})
```

**Avantaj:** Token başka endpoint'te kullanılamaz (cross-action replay engellenir).

---

## 4. Generation

### 4.1 Generation Endpoint

**Dedicated Endpoint:**

```
POST /api/csrf/one-shot
Body: { "action": "POST:/api/account/delete" }
Response: {
  "token": "...",
  "expiresAt": 1234567890,
  "action": "POST:/api/account/delete"
}
```

**Security:**

- Same-origin only
- Authenticated request
- Rate limited (DoS prevention)

### 4.2 Generation Logic

```javascript
function generateOneShotToken(action, sessionId, userId) {
  // Nonce (unique identifier)
  const nonce = crypto.getRandomValues(new Uint8Array(16))

  // Timestamp
  const ts = Date.now()

  // Action hash
  const actionHash = hash(action)

  // Context binding
  const ctx = hash(sessionId + userId + origin)

  // MAC
  const mac = hmac(secret, nonce + ts + actionHash + ctx)

  // Encode
  const token = base64url(nonce + ts + actionHash + ctx + mac)

  // Cache nonce (TTL = 2-5 dakika)
  nonceCache.set(nonce, { ts, action, used: false }, TTL)

  return { token, expiresAt: ts + TTL }
}
```

### 4.3 Nonce Cache

**Bounded Cache (LRU / TTL):**

```javascript
const nonceCache = new LRUCache({
  max: 10000, // Max 10k concurrent one-shot token
  ttl: 5 * 60 * 1000, // 5 dakika TTL
})
```

**Özellikler:**

- Memory bounded (TTL ile)
- Stateless core korunur (cache geçici)
- High concurrency support

---

## 5. Validation

### 5.1 Validation Logic

```javascript
function validateOneShotToken(token, action, sessionId, userId) {
  // Parse token
  const parsed = parseToken(token)

  // TTL check
  const now = Date.now()
  if (now > parsed.ts + TTL) {
    return { valid: false, reason: 'expired' }
  }

  // MAC verify (constant-time)
  const expectedMac = hmac(secret, parsed.nonce + parsed.ts + parsed.actionHash + parsed.ctx)
  if (!crypto.timingSafeEqual(parsed.mac, expectedMac)) {
    return { valid: false, reason: 'invalid_mac' }
  }

  // Action binding check
  const actionHash = hash(action)
  if (parsed.actionHash !== actionHash) {
    return { valid: false, reason: 'action_mismatch' }
  }

  // Context binding check
  const ctx = hash(sessionId + userId + origin)
  if (parsed.ctx !== ctx) {
    return { valid: false, reason: 'context_mismatch' }
  }

  // Nonce check (replay prevention)
  const cached = nonceCache.get(parsed.nonce)
  if (!cached) {
    return { valid: false, reason: 'nonce_not_found' }
  }
  if (cached.used) {
    // CRITICAL: Replay attempt
    logger.error('One-shot token replay attempt', {
      nonce: parsed.nonce,
      action,
    })
    return { valid: false, reason: 'replay_attempt' }
  }

  // Mark as used (atomic operation)
  nonceCache.set(parsed.nonce, { ...cached, used: true }, TTL)

  return { valid: true }
}
```

### 5.2 Replay Prevention

**Kritik:** Nonce cache "used" flag ile replay engellenir.

**Race Condition Koruması:**

```javascript
// Atomic compare-and-swap
function markNonceAsUsed(nonce) {
  return nonceCache.compareAndSwap(
    nonce,
    (cached) => cached.used === false,
    (cached) => ({ ...cached, used: true }),
  )
}

// Validation içinde
if (!markNonceAsUsed(parsed.nonce)) {
  return { valid: false, reason: 'replay_attempt' }
}
```

---

## 6. Integration

### 6.1 Client-Side Usage

**Step 1: Request One-Shot Token**

```javascript
async function deleteAccount() {
  // 1. One-shot token al
  const { token } = await fetch('/api/csrf/one-shot', {
    method: 'POST',
    body: JSON.stringify({ action: 'POST:/api/account/delete' }),
    credentials: 'same-origin',
  }).then((r) => r.json())

  // 2. High-risk action'ı execute et
  const response = await fetch('/api/account/delete', {
    method: 'POST',
    headers: { 'X-CSRF-One-Shot-Token': token },
    credentials: 'same-origin',
  })

  return response
}
```

**Step 2: Token Kullanımı**

- Token sadece bir kez kullanılabilir
- Retry → yeni token gerekli

### 6.2 Server-Side Integration

**Middleware:**

```javascript
function oneShotTokenMiddleware(req, res, next) {
  // High-assurance endpoint check
  if (!isHighAssuranceEndpoint(req.path)) {
    return next() // Normal CSRF token yeterli
  }

  // One-shot token extract
  const token = req.headers['x-csrf-one-shot-token']
  if (!token) {
    return res.status(403).json({
      error: 'One-shot token required',
    })
  }

  // Validate
  const action = `${req.method}:${req.path}`
  const result = validateOneShotToken(token, action, req.sessionId, req.userId)

  if (!result.valid) {
    logger.warn('One-shot token validation failed', {
      reason: result.reason,
      action,
    })
    return res.status(403).json({
      error: 'CSRF validation failed',
    })
  }

  next()
}
```

---

## 7. Configuration

### 7.1 Endpoint Classification

**High-Assurance Endpoints:**

```javascript
const highAssuranceEndpoints = [
  'POST:/api/account/delete',
  'POST:/api/transfer/money',
  'PUT:/api/permissions/grant',
  'DELETE:/api/data/purge',
  'POST:/api/signature/sign',
]

function isHighAssuranceEndpoint(path) {
  return highAssuranceEndpoints.some((pattern) => matchPattern(pattern, path))
}
```

### 7.2 TTL Configuration

```javascript
{
  // One-shot token TTL
  oneShotTTL: 5 * 60 * 1000,      // 5 dakika (kısa)

  // Nonce cache
  nonceCacheSize: 10000,          // Max concurrent token
  nonceCacheTTL: 5 * 60 * 1000,   // TTL ile aynı

  // Rate limiting
  oneShotRateLimit: {
    windowMs: 60 * 1000,          // 1 dakika
    max: 10                       // Max 10 token/dakika
  }
}
```

---

## 8. Security Considerations

### 8.1 Nonce Cache Security

**Sorun:** Nonce cache memory attack yüzeyi mi?

**Cevap:** Hayır, çünkü:

- TTL bounded (5 dakika)
- Size bounded (10k max)
- LRU eviction
- Memory footprint: ~1MB (10k \* 100 byte)

### 8.2 Replay Window

**One-Shot vs Multi-Use:**

- **Multi-Use:** Replay window = TTL (20 dakika)
- **One-Shot:** Replay window = 0 (impossible)

### 8.3 DoS Risk

**Sorun:** Saldırgan çok sayıda one-shot token generate edebilir mi?

**Mitigation:**

- Rate limiting (10 token/dakika)
- Authenticated request
- Nonce cache size limit (10k)

### 8.4 Action Binding Bypass

**Sorun:** Token başka action'da kullanılabilir mi?

**Cevap:** Hayır, çünkü:

- Action hash token içinde
- Validation sırasında action match check

---

## 9. Performance Impact

### 9.1 Overhead

**Generation:**

- Nonce generation: ~1µs
- HMAC: ~50µs
- Cache write: ~10µs
- **Total:** ~60µs

**Validation:**

- Parse: ~10µs
- HMAC verify: ~50µs
- Cache read: ~10µs
- Cache update (mark used): ~10µs
- **Total:** ~80µs

**Sonuç:** Minimal overhead (high-assurance endpoint'ler için kabul edilebilir)

### 9.2 Memory Footprint

```
Nonce cache: 10k entries * 100 byte = 1MB
```

**Sonuç:** Negligible (modern server için)

---

## 10. Error Handling

### 10.1 Token Generation Failure

**Client-Side:**

```javascript
try {
  const { token } = await requestOneShotToken(action)
} catch (error) {
  // Rate limit exceeded
  if (error.status === 429) {
    showError('Too many requests, please wait')
  }
  // Server error
  else {
    showError('Unable to generate token, please try again')
  }
}
```

### 10.2 Validation Failure

**Server-Side:**

```javascript
if (result.reason === 'replay_attempt') {
  // CRITICAL: Security incident
  logger.error('One-shot token replay', {
    sessionId,
    userId,
    action,
  })
  // Opsiyonel: Session invalidate
  invalidateSession(sessionId)
}
```

---

## 11. Testing

### 11.1 Test Cases

**Functional:**

- [ ] Token generation success
- [ ] Token validation success
- [ ] Token single-use enforcement
- [ ] Replay attempt detection
- [ ] Action binding enforcement
- [ ] Context binding enforcement
- [ ] TTL expiry

**Security:**

- [ ] Replay attack (same token twice)
- [ ] Cross-action attack (token for different endpoint)
- [ ] Context mismatch (different session/user)
- [ ] Expired token rejection
- [ ] Invalid MAC rejection

**Performance:**

- [ ] High concurrency (1000 concurrent token)
- [ ] Nonce cache eviction (TTL)
- [ ] Memory footprint (10k token)

---

## 12. Migration Path

### 12.1 Backward Compatibility

**Aşamalı Rollout:**

1. **Phase 1:** One-shot token generation endpoint ekle
2. **Phase 2:** High-assurance endpoint'lerde opsiyonel olarak destekle
3. **Phase 3:** High-assurance endpoint'lerde zorunlu yap
4. **Phase 4:** Tüm high-risk endpoint'lere genişlet

### 12.2 Fallback Strategy

**Geçiş sırasında:**

```javascript
// One-shot token varsa kullan, yoksa normal CSRF token
if (req.headers['x-csrf-one-shot-token']) {
  validateOneShotToken(...);
} else if (req.headers['x-csrf-token']) {
  validateNormalToken(...);
} else {
  return 403;
}
```

---

## 13. Sonuç

One-shot token, **request authenticity primitive** seviyesinde güvenlik sağlar:

✅ **Replay impossible** (nonce cache ile)
✅ **Action binding** (cross-action replay engellenir)
✅ **Minimal overhead** (~80µs validation)
✅ **Bounded cache** (stateless core korunur)
✅ **Selective usage** (sadece high-assurance endpoint'ler)

**Sistem artık:**

- CSRF middleware → **Request authenticity framework**
- Token doğrulama → **Cryptographic proof of intent**

**Bir sonraki adım:** Monitoring & Security Telemetry Architecture

