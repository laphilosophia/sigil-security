# Sigil-Security: Operations Manual

**Versiyon:** 1.0  
**Durum:** Production-Ready  
**Kapsam:** Monitoring, Telemetry, Incident Response

---

**İçindekiler:**
- [Part I: Monitoring & Telemetry](#part-i-monitoring--telemetry)
- [Part II: Incident Response](#part-ii-incident-response)

---

# Part I: Monitoring & Telemetry
# Monitoring & Security Telemetry Architecture

**Versiyon:** 1.0
**Durum:** Formal Specification
**Hedef:** Production-Grade Observability

---

## 1. Motivasyon

CSRF sistemleri **sessiz çalışır**. İzlenmezse:

- Kırıldığını fark etmezsin
- Anomali detection impossible
- Incident response reaktif kalır
- Security posture görünmez

**Telemetry, güvenlik sisteminin sinir sistemidir.**

---

## 2. Metric Taxonomy

### 2.1 Security Metrics

**Validation Failures:**

```
csrf.validation.fail.total          Counter
csrf.validation.fail.rate           Gauge (per second)
csrf.validation.fail.by_reason      Counter (labels: reason)
```

**Reasons:**

- `expired` — Token TTL expired
- `invalid_mac` — HMAC verification failed
- `origin_mismatch` — Origin/Referer mismatch
- `context_mismatch` — Context binding failed
- `fetch_metadata_block` — Cross-site blocked
- `replay_attempt` — One-shot token replay
- `action_mismatch` — One-shot action binding failed
- `malformed` — Token parse failed

**Origin Validation:**

```
csrf.origin.mismatch.total          Counter
csrf.origin.mismatch.rate           Gauge
csrf.origin.cross_site.blocked      Counter
```

**Fetch Metadata:**

```
csrf.fetch_metadata.cross_site.blocked    Counter
csrf.fetch_metadata.missing               Counter
csrf.fetch_metadata.same_site             Counter
```

**Context Binding:**

```
csrf.context.binding.fail.total     Counter
csrf.context.binding.fail.rate      Gauge
csrf.context.binding.soft_fail      Counter
csrf.context.binding.fail_closed    Counter
```

**One-Shot Token:**

```
csrf.one_shot.replay_attempt.total  Counter (CRITICAL)
csrf.one_shot.action_mismatch       Counter
csrf.one_shot.nonce_not_found       Counter
```

### 2.2 Crypto & Runtime Metrics

**Key Management:**

```
csrf.key.rotation.events            Counter
csrf.key.rotation.failures          Counter
csrf.keyring.size                   Gauge
csrf.key.active_kid                 Gauge
```

**Crypto Operations:**

```
csrf.crypto.failures                Counter
csrf.mac.verify.duration            Histogram (µs)
csrf.token.parse.duration           Histogram (µs)
```

**Clock Skew:**

```
csrf.clock.skew.delta               Gauge (seconds)
csrf.clock.skew.violations          Counter
```

### 2.3 Performance Metrics

**Validation Performance:**

```
csrf.validation.duration            Histogram (µs)
csrf.validation.success.duration    Histogram (µs)
csrf.validation.fail.duration       Histogram (µs)
```

**Token Generation:**

```
csrf.token.generation.total         Counter
csrf.token.generation.duration      Histogram (µs)
csrf.one_shot.generation.total      Counter
csrf.one_shot.generation.duration   Histogram (µs)
```

**Nonce Cache (One-Shot):**

```
csrf.nonce_cache.size               Gauge
csrf.nonce_cache.evictions          Counter
csrf.nonce_cache.hit_rate           Gauge
```

### 2.4 Anomaly Metrics

**Suspicious Patterns:**

```
csrf.anomaly.duplicate_token        Counter
csrf.anomaly.multiple_sources       Counter
csrf.anomaly.token_length_anomaly   Counter
csrf.anomaly.timing_variance        Histogram
```

**Rate Anomalies:**

```
csrf.anomaly.validation_spike       Counter
csrf.anomaly.failure_spike          Counter
csrf.anomaly.generation_spike       Counter
```

---

## 3. Metric Collection

### 3.1 Instrumentation Points

**Validation Middleware:**

```javascript
async function csrfValidationMiddleware(req, res, next) {
  const startTime = performance.now()

  try {
    // Validation
    const result = await validateCSRF(req)

    // Metrics
    const duration = performance.now() - startTime
    metrics.histogram('csrf.validation.duration', duration)

    if (result.valid) {
      metrics.increment('csrf.validation.success.total')
      metrics.histogram('csrf.validation.success.duration', duration)
    } else {
      metrics.increment('csrf.validation.fail.total')
      metrics.increment(`csrf.validation.fail.by_reason.${result.reason}`)
      metrics.histogram('csrf.validation.fail.duration', duration)

      // Log failure
      logger.warn('CSRF validation failed', {
        reason: result.reason,
        path: req.path,
        method: req.method,
        origin: req.headers.origin,
        sessionId: req.sessionId,
      })
    }

    // Anomaly detection
    if (duration > TIMING_THRESHOLD) {
      metrics.increment('csrf.anomaly.timing_variance')
    }

    next(result.valid ? null : new Error('CSRF validation failed'))
  } catch (error) {
    metrics.increment('csrf.crypto.failures')
    throw error
  }
}
```

**Token Generation:**

```javascript
function generateToken(sessionId, userId) {
  const startTime = performance.now()

  try {
    const token = _generateToken(sessionId, userId)

    const duration = performance.now() - startTime
    metrics.increment('csrf.token.generation.total')
    metrics.histogram('csrf.token.generation.duration', duration)

    return token
  } catch (error) {
    metrics.increment('csrf.crypto.failures')
    throw error
  }
}
```

**Key Rotation:**

```javascript
function rotateKey() {
  try {
    const oldKid = currentKid
    const newKid = deriveNewKey()

    metrics.increment('csrf.key.rotation.events')
    metrics.gauge('csrf.key.active_kid', newKid)
    metrics.gauge('csrf.keyring.size', keyring.length)

    logger.info('Key rotation successful', { oldKid, newKid })
  } catch (error) {
    metrics.increment('csrf.key.rotation.failures')
    logger.error('Key rotation failed', { error })
    throw error
  }
}
```

---

## 4. Baseline & Anomaly Detection

### 4.1 Baseline Establishment

**Normal Operation Baseline:**

```javascript
// 7 gün normal trafik
const baseline = {
  validation: {
    successRate: 0.998, // %99.8 success
    failRate: 0.002, // %0.2 fail
    avgDuration: 75, // 75µs avg
    p95Duration: 120, // 120µs p95
    p99Duration: 200, // 200µs p99
  },

  failures: {
    expired: 0.001, // %0.1 (normal TTL expiry)
    invalidMac: 0.0001, // %0.01 (rare, suspicious)
    originMismatch: 0.0005, // %0.05 (legacy browser)
    contextMismatch: 0.0004, // %0.04 (session rotation)
  },
}
```

### 4.2 Anomaly Thresholds

**Deviation Thresholds:**

```javascript
const anomalyThresholds = {
  // Validation fail rate spike
  validationFailRate: {
    warning: baseline.failRate * 2, // 2x baseline
    critical: baseline.failRate * 5, // 5x baseline
  },

  // Invalid MAC spike (CRITICAL)
  invalidMacRate: {
    warning: baseline.failures.invalidMac * 3,
    critical: baseline.failures.invalidMac * 10,
  },

  // Timing variance
  timingVariance: {
    warning: baseline.validation.p95Duration * 1.5,
    critical: baseline.validation.p95Duration * 3,
  },

  // One-shot replay (ANY is critical)
  oneShotReplay: {
    warning: 1, // Single replay = warning
    critical: 5, // 5+ replay = critical
  },
}
```

### 4.3 Anomaly Detection Logic

```javascript
function detectAnomalies(metrics, baseline, thresholds) {
  const anomalies = []

  // Validation fail rate spike
  if (metrics.validationFailRate > thresholds.validationFailRate.critical) {
    anomalies.push({
      severity: 'critical',
      type: 'validation_fail_spike',
      current: metrics.validationFailRate,
      baseline: baseline.failRate,
      deviation: metrics.validationFailRate / baseline.failRate,
    })
  }

  // Invalid MAC spike (potential attack)
  if (metrics.invalidMacRate > thresholds.invalidMacRate.warning) {
    anomalies.push({
      severity: 'critical',
      type: 'invalid_mac_spike',
      current: metrics.invalidMacRate,
      baseline: baseline.failures.invalidMac,
      message: 'Potential token forgery attack',
    })
  }

  // One-shot replay (ALWAYS critical)
  if (metrics.oneShotReplayCount > 0) {
    anomalies.push({
      severity: 'critical',
      type: 'one_shot_replay',
      count: metrics.oneShotReplayCount,
      message: 'One-shot token replay detected',
    })
  }

  return anomalies
}
```

---

## 5. Alerting

### 5.1 Alert Rules

**Critical Alerts (Immediate):**

```yaml
- name: csrf_one_shot_replay
  condition: csrf.one_shot.replay_attempt.total > 0
  severity: critical
  message: 'One-shot token replay detected'
  action: page_oncall

- name: csrf_invalid_mac_spike
  condition: rate(csrf.validation.fail.by_reason{reason="invalid_mac"}[5m]) > 0.001
  severity: critical
  message: 'Invalid MAC spike - potential forgery attack'
  action: page_oncall

- name: csrf_key_rotation_failure
  condition: csrf.key.rotation.failures > 0
  severity: critical
  message: 'Key rotation failed'
  action: page_oncall
```

**Warning Alerts (Review):**

```yaml
- name: csrf_validation_fail_spike
  condition: rate(csrf.validation.fail.total[5m]) > baseline * 2
  severity: warning
  message: 'CSRF validation failure rate spike'
  action: notify_team

- name: csrf_origin_mismatch_spike
  condition: rate(csrf.origin.mismatch.total[5m]) > baseline * 3
  severity: warning
  message: 'Origin mismatch spike'
  action: notify_team

- name: csrf_clock_skew
  condition: abs(csrf.clock.skew.delta) > 300
  severity: warning
  message: 'Clock skew > 5 minutes'
  action: notify_ops
```

### 5.2 Alert Routing

```javascript
const alertRouting = {
  critical: {
    channels: ['pagerduty', 'slack-security', 'email-oncall'],
    escalation: {
      timeout: 5 * 60 * 1000, // 5 dakika
      levels: ['oncall', 'security-lead', 'cto'],
    },
  },

  warning: {
    channels: ['slack-security', 'email-team'],
    escalation: null,
  },

  info: {
    channels: ['slack-monitoring'],
    escalation: null,
  },
}
```

---

## 6. Dashboards

### 6.1 Security Dashboard

**Panels:**

1. **Validation Overview**
   - Success rate (gauge)
   - Fail rate (gauge)
   - Total validations (counter)
   - Fail by reason (pie chart)

2. **Security Incidents**
   - Invalid MAC attempts (time series)
   - One-shot replay attempts (time series)
   - Origin mismatch (time series)
   - Cross-site blocks (time series)

3. **Performance**
   - Validation duration (histogram)
   - P50/P95/P99 latency (gauge)
   - Timing variance (time series)

4. **Key Management**
   - Active kid (gauge)
   - Keyring size (gauge)
   - Rotation events (time series)
   - Rotation failures (counter)

### 6.2 Operational Dashboard

**Panels:**

1. **Token Lifecycle**
   - Token generation rate (time series)
   - Token expiry rate (time series)
   - Refresh rate (time series)
   - Grace window hits (time series)

2. **One-Shot Tokens**
   - Generation rate (time series)
   - Nonce cache size (gauge)
   - Nonce cache evictions (time series)
   - Replay attempts (counter)

3. **Client Behavior**
   - Browser mode vs API mode (pie chart)
   - Fetch Metadata presence (pie chart)
   - Legacy browser detection (time series)

---

## 7. Logging

### 7.1 Log Levels

**ERROR (Security Incident):**

```javascript
logger.error('One-shot token replay attempt', {
  nonce: parsed.nonce,
  action,
  sessionId,
  userId,
  ip: req.ip,
  userAgent: req.headers['user-agent'],
})
```

**WARN (Suspicious):**

```javascript
logger.warn('CSRF validation failed', {
  reason: result.reason,
  path: req.path,
  method: req.method,
  origin: req.headers.origin,
  referer: req.headers.referer,
  sessionId: req.sessionId,
})
```

**INFO (Operational):**

```javascript
logger.info('Key rotation successful', {
  oldKid,
  newKid,
  keyringSize: keyring.length,
})
```

### 7.2 Structured Logging

**Format:**

```json
{
  "timestamp": "2026-02-08T18:45:00Z",
  "level": "error",
  "message": "One-shot token replay attempt",
  "context": {
    "component": "csrf",
    "event": "replay_attempt",
    "nonce": "abc123...",
    "action": "POST:/api/account/delete",
    "sessionId": "sess_xyz",
    "userId": "user_123",
    "ip": "192.168.1.1",
    "userAgent": "Mozilla/5.0..."
  }
}
```

### 7.3 Log Retention

```javascript
const logRetention = {
  error: 90, // 90 gün (security incident)
  warn: 30, // 30 gün (suspicious)
  info: 7, // 7 gün (operational)
}
```

---

## 8. SIEM Integration

### 8.1 Security Events

**Export to SIEM:**

```javascript
const siemEvents = [
  'csrf.one_shot.replay_attempt',
  'csrf.validation.fail.invalid_mac',
  'csrf.origin.mismatch',
  'csrf.key.rotation.failures',
  'csrf.anomaly.validation_spike',
]

function exportToSIEM(event) {
  siem.send({
    eventType: event.type,
    severity: event.severity,
    timestamp: event.timestamp,
    source: 'csrf-middleware',
    details: event.context,
  })
}
```

### 8.2 Correlation Rules

**SIEM Correlation:**

```
Rule: Multiple CSRF failures from same IP
Condition: csrf.validation.fail.total > 10 in 5 minutes from same IP
Action: Block IP, notify security team

Rule: One-shot replay + session anomaly
Condition: csrf.one_shot.replay_attempt AND session.anomaly
Action: Invalidate session, page oncall

Rule: Invalid MAC spike + origin mismatch
Condition: csrf.validation.fail.invalid_mac > threshold AND csrf.origin.mismatch > threshold
Action: Potential attack, page oncall
```

---

## 9. Implementation Checklist

### Metrics

- [ ] Validation metrics (success/fail/duration)
- [ ] Security metrics (replay, MAC, origin)
- [ ] Crypto metrics (key rotation, failures)
- [ ] Performance metrics (latency, throughput)
- [ ] Anomaly metrics (spikes, variance)

### Alerting

- [ ] Critical alerts (replay, MAC spike, key rotation failure)
- [ ] Warning alerts (validation spike, origin mismatch)
- [ ] Alert routing (PagerDuty, Slack, email)

### Dashboards

- [ ] Security dashboard (incidents, validation)
- [ ] Operational dashboard (lifecycle, performance)
- [ ] Grafana/Datadog integration

### Logging

- [ ] Structured logging (JSON)
- [ ] Log levels (ERROR/WARN/INFO)
- [ ] Log retention (90/30/7 days)
- [ ] SIEM integration

---

## 10. Sonuç

Bu telemetry architecture, **production-grade observability** sağlar:

✅ **Comprehensive metrics** (security, crypto, performance, anomaly)
✅ **Baseline & anomaly detection** (deviation thresholds)
✅ **Critical alerting** (replay, MAC spike, key rotation failure)
✅ **Dashboards** (security, operational)
✅ **SIEM integration** (correlation rules)

**Sistem artık:**

- Silent operation → **Observable security**
- Reactive incident response → **Proactive anomaly detection**
- Unknown posture → **Quantified security metrics**

**Bir sonraki adım:** Incident Response Runbook

---

# Part II: Incident Response
# Incident Response Runbook

**Versiyon:** 1.0
**Durum:** Production Runbook
**Hedef:** Security Incident Response

---

## 1. Genel Bakış

Bu runbook, CSRF güvenlik sisteminde oluşabilecek **security incident'ler** için operasyonel prosedürleri tanımlar.

### Incident Kategorileri

1. **Key Compromise** (Kritik)
2. **Token Forgery Suspicion** (Kritik)
3. **Clock Skew Incident** (Operasyonel)
4. **One-Shot Replay Attack** (Kritik)
5. **Validation Spike** (Anomali)

---

## 2. Key Compromise

### 2.1 Senaryo 1: Signing Key Leak (kid-specific)

**Belirtiler:**

- Tek bir kid için invalid MAC rate spike
- Audit log'da suspicious token generation pattern
- External security report (bug bounty, pentest)

**Etki:**

- Saldırgan o kid ile valid token üretebilir
- Blast radius: Sadece o kid'li tokenlar

**Acil Müdahale (0-15 dakika):**

```bash
# 1. Compromised kid'i identify et
kid_compromised=5

# 2. Emergency rotation (kid bump)
curl -X POST https://api.example.com/internal/csrf/rotate-key \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"reason": "key_compromise", "invalidate_kid": '$kid_compromised'}'

# 3. Monitoring: Eski kid kullanımını izle
# Alert: csrf.validation.by_kid{kid=$kid_compromised} > 0
```

**Kısa Vadeli (15-60 dakika):**

1. **Forensic Analysis:**

   ```sql
   -- Compromised kid ile yapılan istekler
   SELECT timestamp, session_id, user_id, ip, path, method
   FROM csrf_validation_logs
   WHERE kid = $kid_compromised
     AND timestamp > $compromise_time
   ORDER BY timestamp DESC;
   ```

2. **Session Invalidation (Opsiyonel):**

   ```javascript
   // Suspicious session'ları invalidate et
   const suspiciousSessions = identifySuspiciousSessions(kid_compromised)
   suspiciousSessions.forEach((sessionId) => {
     invalidateSession(sessionId)
     notifyUser(sessionId, 'security_incident')
   })
   ```

3. **User Notification:**
   - Etkilenen kullanıcılara email
   - Force password reset (opsiyonel)

**Uzun Vadeli (1-24 saat):**

1. **Root Cause Analysis:**
   - Key nasıl sızdı? (log leak, memory dump, insider threat)
   - Vulnerability patch
   - Security posture review

2. **Audit Window:**

   ```javascript
   // Compromise öncesi 7 gün audit
   const auditWindow = {
     start: compromise_time - 7 * 24 * 60 * 60 * 1000,
     end: compromise_time,
   }

   // Anomali detection
   detectAnomalies(auditWindow, kid_compromised)
   ```

3. **Post-Mortem:**
   - Incident timeline
   - Impact assessment
   - Lessons learned
   - Action items

---

### 2.2 Senaryo 2: Master Secret Leak (Global)

**Belirtiler:**

- Tüm kid'ler için invalid MAC rate spike
- Master secret external exposure (GitHub leak, config dump)
- Multiple kid'lerde suspicious pattern

**Etki:**

- Saldırgan tüm kid'lerle valid token üretebilir
- Blast radius: **Tüm aktif tokenlar**

**Acil Müdahale (0-5 dakika):**

```bash
# CRITICAL: Immediate master secret rotation
curl -X POST https://api.example.com/internal/csrf/rotate-master-secret \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"reason": "master_secret_compromise", "invalidate_all": true}'

# Tüm kullanıcılar yeniden login gerekecek
```

**Kısa Vadeli (5-30 dakika):**

1. **Global Session Invalidation:**

   ```javascript
   // TÜM session'ları invalidate et
   invalidateAllSessions()

   // Kullanıcıları login page'e redirect
   broadcastMessage({
     type: 'force_logout',
     reason: 'security_incident',
   })
   ```

2. **Public Communication:**
   - Status page update
   - User notification (email, in-app)
   - Security advisory

3. **Monitoring:**
   ```javascript
   // Yeni master secret ile token generation izle
   metrics.watch('csrf.token.generation.total')
   metrics.watch('csrf.validation.success.rate')
   ```

**Uzun Vadeli (1-7 gün):**

1. **Forensic Investigation:**
   - Master secret nasıl sızdı?
   - Exposure scope (public? limited?)
   - Attacker capability assessment

2. **Security Hardening:**
   - Secret management review (Vault, KMS)
   - Access control audit
   - Rotation automation

3. **Compliance:**
   - Legal notification (GDPR, vb.)
   - Insurance claim
   - Regulatory reporting

---

## 3. Token Forgery Suspicion

### 3.1 Belirtiler

**Metrics:**

```
csrf.validation.fail.by_reason{reason="invalid_mac"} > threshold
```

**Threshold:**

- Warning: Baseline \* 3
- Critical: Baseline \* 10

**Örnek:**

```
Baseline: 0.01% invalid MAC rate
Warning: 0.03% (3x)
Critical: 0.1% (10x)
```

### 3.2 Acil Müdahale (0-15 dakika)

**1. Verify Alert:**

```bash
# Son 5 dakika invalid MAC count
curl https://api.example.com/internal/metrics/query \
  -d 'query=rate(csrf_validation_fail_by_reason{reason="invalid_mac"}[5m])'

# Spike confirm edildi mi?
```

**2. Identify Pattern:**

```sql
-- Invalid MAC attempt'leri analiz et
SELECT ip, user_agent, COUNT(*) as attempts
FROM csrf_validation_logs
WHERE reason = 'invalid_mac'
  AND timestamp > NOW() - INTERVAL '5 minutes'
GROUP BY ip, user_agent
ORDER BY attempts DESC
LIMIT 20;
```

**3. IP Blocking (Opsiyonel):**

```bash
# Suspicious IP'leri block et
for ip in $suspicious_ips; do
  iptables -A INPUT -s $ip -j DROP
  # veya WAF rule
done
```

### 3.3 Kısa Vadeli (15-60 dakika)

**1. Token Analysis:**

```javascript
// Invalid MAC token'ları collect et
const invalidTokens = collectInvalidMacTokens(last5Minutes)

// Pattern detection
const patterns = {
  commonPrefix: detectCommonPrefix(invalidTokens),
  timingPattern: detectTimingPattern(invalidTokens),
  sourcePattern: detectSourcePattern(invalidTokens),
}

// Forgery technique inference
if (patterns.commonPrefix) {
  logger.warn('Potential token prefix attack')
}
```

**2. Rate Limiting:**

```javascript
// Aggressive rate limiting
updateRateLimits({
  tokenGeneration: { max: 5, windowMs: 60000 }, // 5/min
  validation: { max: 20, windowMs: 60000 }, // 20/min
})
```

**3. Monitoring Intensify:**

```javascript
// Real-time monitoring
setInterval(() => {
  const invalidMacRate = getMetric('csrf.validation.fail.invalid_mac.rate')
  if (invalidMacRate > CRITICAL_THRESHOLD) {
    pageOncall('Invalid MAC spike continues')
  }
}, 60000) // Her 1 dakika
```

### 3.4 Uzun Vadeli (1-7 gün)

**1. Forensic Analysis:**

- Token structure analysis (brute-force? timing attack?)
- Crypto implementation review
- Side-channel vulnerability check

**2. Security Audit:**

- Constant-time implementation verify
- HMAC library audit
- Key management review

---

## 4. Clock Skew Incident

### 4.1 Belirtiler

**Metrics:**

```
abs(csrf.clock.skew.delta) > 300  // 5 dakika
```

**Logs:**

```
WARN: Clock skew detected: server_time=X, client_time=Y, delta=300s
```

### 4.2 Acil Müdahale (0-15 dakika)

**1. Identify Scope:**

```bash
# Hangi sunucular etkilendi?
curl https://api.example.com/internal/health/clock-skew

# Output:
# server-1: +320s
# server-2: +5s
# server-3: -280s
```

**2. Temporary Mitigation:**

```javascript
// TTL tolerance artır (geçici)
updateConfig({
  ttlTolerance: 600, // 10 dakika (normal: 300)
})

// Grace window artır
updateConfig({
  graceWindow: 120000, // 2 dakika (normal: 60s)
})
```

**3. User Impact:**

```sql
-- Kaç kullanıcı etkilendi?
SELECT COUNT(DISTINCT session_id)
FROM csrf_validation_logs
WHERE reason = 'expired'
  AND timestamp > NOW() - INTERVAL '15 minutes';
```

### 4.3 Kısa Vadeli (15-60 dakika)

**1. NTP Sync:**

```bash
# Etkilenen sunucularda NTP resync
for server in $affected_servers; do
  ssh $server "systemctl restart ntp"
  ssh $server "ntpq -p"  # Verify sync
done
```

**2. Monitoring:**

```javascript
// Clock skew monitoring
setInterval(() => {
  const skew = getClockSkew()
  if (Math.abs(skew) > 60) {
    // 1 dakika
    logger.warn('Clock skew detected', { skew })
  }
}, 60000)
```

**3. Rollback Tolerance:**

```javascript
// Tolerance'ı normal seviyeye geri al
updateConfig({
  ttlTolerance: 300, // 5 dakika
  graceWindow: 60000, // 60s
})
```

### 4.4 Uzun Vadeli (1-7 gün)

**1. Root Cause:**

- NTP server failure?
- VM clock drift?
- Timezone misconfiguration?

**2. Prevention:**

- NTP monitoring alert
- Automated NTP sync check
- Clock skew dashboard

---

## 5. One-Shot Replay Attack

### 5.1 Belirtiler

**Metrics:**

```
csrf.one_shot.replay_attempt.total > 0  // ANY = CRITICAL
```

**Logs:**

```
ERROR: One-shot token replay attempt
  nonce: abc123...
  action: POST:/api/account/delete
  session_id: sess_xyz
  user_id: user_123
  ip: 192.168.1.1
```

### 5.2 Acil Müdahale (0-5 dakika)

**1. Immediate Session Invalidation:**

```javascript
// Etkilenen session'ı invalidate et
const { sessionId, userId } = replayAttempt

invalidateSession(sessionId)

// User'a notify
notifyUser(userId, {
  type: 'security_alert',
  message: 'Suspicious activity detected. Please change your password.',
})
```

**2. IP Blocking:**

```bash
# Saldırgan IP'yi block et
iptables -A INPUT -s $attacker_ip -j DROP
```

**3. Forensic Snapshot:**

```javascript
// Incident snapshot
const snapshot = {
  timestamp: Date.now(),
  nonce: replayAttempt.nonce,
  action: replayAttempt.action,
  sessionId: replayAttempt.sessionId,
  userId: replayAttempt.userId,
  ip: replayAttempt.ip,
  userAgent: replayAttempt.userAgent,

  // Context
  recentActivity: getUserActivity(userId, last30Minutes),
  deviceHistory: getDeviceHistory(userId),
  locationHistory: getLocationHistory(userId),
}

saveForensicSnapshot(snapshot)
```

### 5.3 Kısa Vadeli (5-60 dakika)

**1. User Investigation:**

```javascript
// Kullanıcı compromise mi?
const investigation = {
  // Son 24 saat aktivite
  recentLogins: getLogins(userId, last24Hours),

  // Şüpheli davranış
  suspiciousActions: detectSuspiciousActions(userId),

  // Device fingerprint
  knownDevices: getKnownDevices(userId),
  unknownDevices: detectUnknownDevices(userId),
}

if (investigation.suspiciousActions.length > 0) {
  // Account compromise olabilir
  lockAccount(userId)
  forcePasswordReset(userId)
}
```

**2. Attack Vector Analysis:**

```javascript
// Token nasıl replay edildi?
const attackVector = {
  // XSS?
  xssVulnerability: checkXSSVulnerability(),

  // MitM?
  tlsDowngrade: checkTLSDowngrade(sessionId),

  // Malware?
  deviceCompromise: checkDeviceCompromise(userId),
}
```

**3. Escalation:**

```javascript
// Security team'e escalate
pageSecurityTeam({
  severity: 'critical',
  incident: 'one_shot_replay',
  userId,
  snapshot,
})
```

### 5.4 Uzun Vadeli (1-7 gün)

**1. Security Review:**

- XSS vulnerability scan
- Token storage review (localStorage vs memory)
- CSP policy audit

**2. User Communication:**

- Security incident notification
- Password reset enforcement
- 2FA recommendation

---

## 6. Validation Spike

### 6.1 Belirtiler

**Metrics:**

```
rate(csrf.validation.fail.total[5m]) > baseline * 2
```

### 6.2 Acil Müdahale (0-15 dakika)

**1. Identify Cause:**

```javascript
// Spike nedeni?
const spikeAnalysis = {
  // Deployment?
  recentDeployments: getRecentDeployments(last30Minutes),

  // Traffic spike?
  trafficIncrease: getTrafficIncrease(last30Minutes),

  // Bot attack?
  botActivity: detectBotActivity(),

  // Key rotation?
  keyRotationEvents: getKeyRotationEvents(last30Minutes),
}
```

**2. Mitigation:**

```javascript
// Nedene göre mitigation
if (spikeAnalysis.botActivity) {
  enableAggressiveRateLimiting()
  enableCaptcha()
}

if (spikeAnalysis.recentDeployments.length > 0) {
  // Deployment rollback?
  considerRollback()
}
```

---

## 7. Escalation Matrix

### Severity Levels

**Critical (P0):**

- One-shot replay attack
- Master secret leak
- Invalid MAC spike (10x baseline)

**High (P1):**

- Signing key leak
- Token forgery suspicion
- Validation spike (5x baseline)

**Medium (P2):**

- Clock skew (>5 dakika)
- Validation spike (2x baseline)

**Low (P3):**

- Minor clock skew (<5 dakika)
- Isolated validation failures

### Escalation Path

```
P0: Immediate page → Security oncall → CISO
P1: Page within 15min → Security team → Engineering lead
P2: Slack alert → Security team
P3: Email alert → Engineering team
```

---

## 8. Communication Templates

### 8.1 Internal (Security Team)

```
SUBJECT: [P0] CSRF One-Shot Replay Attack Detected

INCIDENT: One-shot token replay attempt
TIME: 2026-02-08 18:50 UTC
SEVERITY: Critical (P0)

DETAILS:
- User ID: user_123
- Session ID: sess_xyz
- IP: 192.168.1.1
- Action: POST:/api/account/delete

IMMEDIATE ACTIONS TAKEN:
- Session invalidated
- IP blocked
- User notified

NEXT STEPS:
- Forensic analysis
- User investigation
- Security review

ONCALL: @security-oncall
```

### 8.2 External (User)

```
SUBJECT: Security Alert - Suspicious Activity Detected

Dear User,

We detected suspicious activity on your account and have taken
immediate action to protect your security.

WHAT HAPPENED:
We detected an unusual request pattern that may indicate
unauthorized access.

WHAT WE DID:
- Logged you out of all devices
- Blocked the suspicious IP address
- Secured your account

WHAT YOU SHOULD DO:
1. Change your password immediately
2. Review recent account activity
3. Enable two-factor authentication

If you have questions, contact security@example.com

Best regards,
Security Team
```

---

## 9. Post-Incident Checklist

### Immediate (0-24 saat)

- [ ] Incident timeline documented
- [ ] Root cause identified
- [ ] Affected users notified
- [ ] Forensic data collected
- [ ] Mitigation deployed

### Short-term (1-7 gün)

- [ ] Post-mortem completed
- [ ] Action items assigned
- [ ] Security patches deployed
- [ ] Monitoring enhanced
- [ ] Runbook updated

### Long-term (1-4 hafta)

- [ ] Vulnerability remediated
- [ ] Security audit completed
- [ ] Team training conducted
- [ ] Compliance reporting
- [ ] Lessons learned shared

---

## 10. Runbook Maintenance

**Review Frequency:** Quarterly

**Update Triggers:**

- Security incident (post-mortem)
- Architecture change
- New attack vector
- Tool/process change

**Ownership:** Security Team

**Last Updated:** 2026-02-08

