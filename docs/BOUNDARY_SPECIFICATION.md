# Sigil — Core Boundary Specification

**Durum:** Normatif
**Kapsam:** `sigil-core` davranış sınırları
**Amaç:** Security primitive kalmasını garanti etmek

---

## 1. Sistem Tanımı

`sigil-core`, **stateless kriptografik request doğrulama primitive’idir.**
Hiçbir koşulda request lifecycle, session, client state veya uygulama akışını yönetmez.

Core’un görevi:

- Kriptografik doğrulama
- Bağlam bağlılığı (context binding)
- Replay kontrolü (opsiyonel)
- Deterministic doğrulama
- Sabit zamanlı (constant-time) güvenlik

Core **güvenlik mekanizmasıdır, politika motoru değildir.**

---

## 2. Core’un YAPMASI GEREKENLER (Allowed Surface)

Core yalnızca aşağıdaki davranışlara sahiptir:

### 2.1 Kriptografik Primitive

- Token üretimi
- Token doğrulama
- HMAC doğrulama
- HKDF anahtar türetme
- Constant-time karşılaştırma
- Deterministic failure path

### 2.2 Stateless Doğrulama

- TTL kontrolü
- Context binding doğrulama
- Opsiyonel replay (bounded, non-persistent)

### 2.3 Saf Fonksiyon Modeli

Core fonksiyonları:

- Deterministic
- Side-effect free (replay cache hariç)
- I/O bağımsız
- Runtime bağımsız
- Framework bağımsız

---

## 3. Core’un YAPMAMASI GEREKENLER (Hard Prohibitions)

Aşağıdaki davranışlar **kesinlikle core’a eklenemez.**

### 3.1 Lifecycle Yönetimi YASAK

Core:

- Token refresh yapmaz
- Token rotate etmez
- Session yönetmez
- Logout semantiği içermez
- Client sync yapmaz
- Multi-tab coordination yapmaz
- Broadcast / storage kullanmaz

### 3.2 State Orchestration YASAK

Core:

- Session store kullanmaz
- Distributed state yönetmez
- Persistence içermez
- Revocation list tutmaz (ephemeral replay hariç)
- Global state taşımaz

### 3.3 Policy Enforcement YASAK

Core:

- CSRF policy bilmez
- Browser header bilmez
- Origin / Fetch Metadata kontrolü yapmaz
- HTTP semantiği bilmez
- Client tipi bilmez
- Request transport bilmez

Bunlar **policy katmanına aittir.**

### 3.4 Runtime Coupling YASAK

Core:

- Express / Hono / Oak bilmez
- HTTP request nesnesi almaz
- Environment bilmez
- Config store içermez
- Logger içermez
- Metrics içermez

### 3.5 Operational Davranış YASAK

Core:

- Monitoring yapmaz
- Telemetry üretmez
- Rate limiting yapmaz
- Alert üretmez
- Incident handling içermez

---

## 4. Core’un İzin Verilen Tek State’i

Core yalnızca **ephemeral replay cache** tutabilir.

Sınırlar:

- TTL-bounded
- Memory-bounded
- Non-distributed
- Optional
- Fail-open allowed
- No persistence

Bu cache **güvenlik garantisi değil, optimizasyondur.**

---

## 5. Policy Katmanına Ait Davranışlar

Aşağıdakiler core dışındadır:

- CSRF preset
- Browser vs API ayrımı
- Fetch Metadata
- Origin doğrulama
- Token transport
- Lifecycle orchestration
- Refresh
- Logout davranışı
- Telemetry
- Distributed replay
- Rate limiting
- Observability
- Deployment logic

Bu davranışlar ayrı paketlerde bulunur.

---

## 6. Mimari Katman Sözleşmesi

```
sigil-core      → cryptographic primitive (stateless, pure)
sigil-policy    → validation policies (csrf, api, browser)
sigil-runtime   → framework adapters
sigil-ops       → telemetry & monitoring (optional)
sigil-extended  → distributed / advanced (optional)
```

Core tek başına çalışabilir.
Hiçbir üst katmana bağımlı değildir.

---

## 7. Tasarım İhlali Kriterleri

Aşağıdaki durumlar **boundary ihlalidir:**

- Core request nesnesi alıyorsa
- Core refresh yönetiyorsa
- Core distributed state tutuyorsa
- Core client davranışı biliyorsa
- Core policy içeriyorsa
- Core config / runtime bağımlılığı varsa
- Core I/O yapıyorsa
- Core observability içeriyorsa

Bu durumlar projeyi **framework’e dönüştürür.**

---

## 8. Genişleme Kuralları

Yeni özellik eklenirken:

Eğer özellik:

- Crypto primitive ise → core’a girebilir
- Stateless doğrulama ise → core’a girebilir
- Replay varyasyonu ise → core’a girebilir
- Side-channel önleme ise → core’a girebilir

Eğer özellik:

- Davranış orkestrasyonu ise → policy
- State yönetimi ise → extended
- Deployment ise → runtime
- Observability ise → ops
- Client davranışı ise → policy

→ Core’a giremez.

---

## 9. Core Tasarım İlkeleri

Core şu özellikleri korumalı:

- Küçük yüzey alanı
- Deterministic davranış
- Sabit zamanlı güvenlik
- Runtime bağımsızlık
- Framework bağımsızlık
- Stateless doğrulama
- Kriptografik bütünlük

Bu özellikler kaybolursa core kimliğini kaybeder.

---

## 10. Nihai Mimari Kimlik

`sigil-core`:

- CSRF middleware değildir
- Framework değildir
- Auth sistemi değildir
- Session sistemi değildir

`sigil-core`:

**Cryptographic Request Authenticity Primitive’tir.**
