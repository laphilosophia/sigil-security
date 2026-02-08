# Sigil-Security: Operations Manual

**Version:** 1.0
**Status:** Production-Ready
**Scope:** Monitoring, Telemetry, Incident Response

---

**Table of Contents:**

- [Part I: Monitoring & Telemetry](#part-i-monitoring--telemetry)
- [Part II: Incident Response](#part-ii-incident-response)

---

# Part I: Monitoring & Telemetry

## 1. Motivation

CSRF systems primarily operate in the background. Without proper monitoring:

- Potential breaches may go undetected.
- Anomaly detection becomes impossible.
- Incident response remains reactive.
- The overall security posture stays invisible.

**Telemetry is the nervous system of any security architecture.**

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

- `expired` — Token TTL has expired.
- `invalid_mac` — HMAC verification failed.
- `origin_mismatch` — Origin or Referer header mismatch.
- `context_mismatch` — Context binding validation failed.
- `fetch_metadata_block` — Blocked based on Fetch Metadata (cross-site).
- `replay_attempt` — Detected replay of a one-shot token.
- `action_mismatch` — Action binding failure for a one-shot token.
- `malformed` — Token parsing failed.

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

**One-Shot Tokens:**

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

**Cryptographic Operations:**

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

**Nonce Cache (for One-Shot Tokens):**

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
    // Perform validation
    const result = await validateCSRF(req)

    // Capture timing metrics
    const duration = performance.now() - startTime
    metrics.histogram('csrf.validation.duration', duration)

    if (result.valid) {
      metrics.increment('csrf.validation.success.total')
      metrics.histogram('csrf.validation.success.duration', duration)
    } else {
      metrics.increment('csrf.validation.fail.total')
      metrics.increment(`csrf.validation.fail.by_reason.${result.reason}`)
      metrics.histogram('csrf.validation.fail.duration', duration)

      // Log failure details
      logger.warn('CSRF validation failed', {
        reason: result.reason,
        path: req.path,
        method: req.method,
        origin: req.headers.origin,
        sessionId: req.sessionId,
      })
    }

    // Measure timing variance for anomaly detection
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

## 4. Baselines & Anomaly Detection

### 4.1 Establishing Baselines

**Normal Operation Baseline (established over 7 days):**

```javascript
const baseline = {
  validation: {
    successRate: 0.998, // 99.8% success
    failRate: 0.002, // 0.2% failure
    avgDuration: 75, // 75µs average
    p95Duration: 120, // 120µs p95
    p99Duration: 200, // 200µs p99
  },

  failures: {
    expired: 0.001, // 0.1% (typical TTL expiry)
    invalidMac: 0.0001, // 0.01% (rare, suspicious)
    originMismatch: 0.0005, // 0.05% (client/browser specific)
    contextMismatch: 0.0004, // 0.04% (session rotation overlap)
  },
}
```

### 4.2 Anomaly Thresholds

**Deviation Thresholds:**

```javascript
const anomalyThresholds = {
  // Spike in validation failure rate
  validationFailRate: {
    warning: baseline.failRate * 2, // 2x baseline
    critical: baseline.failRate * 5, // 5x baseline
  },

  // Spike in invalid MACs (CRITICAL)
  invalidMacRate: {
    warning: baseline.failures.invalidMac * 3,
    critical: baseline.failures.invalidMac * 10,
  },

  // Latency variance
  timingVariance: {
    warning: baseline.validation.p95Duration * 1.5,
    critical: baseline.validation.p95Duration * 3,
  },

  // One-shot replay detection (MUST alert)
  oneShotReplay: {
    warning: 1, // Any single replay is a warning
    critical: 5, // 5+ replays is critical
  },
}
```

### 4.3 Anomaly Detection Logic

```javascript
function detectAnomalies(metrics, baseline, thresholds) {
  const anomalies = []

  // Check for spikes in validation failure rate
  if (metrics.validationFailRate > thresholds.validationFailRate.critical) {
    anomalies.push({
      severity: 'critical',
      type: 'validation_fail_spike',
      current: metrics.validationFailRate,
      baseline: baseline.failRate,
      deviation: metrics.validationFailRate / baseline.failRate,
    })
  }

  // Check for potential token forgery (invalid MAC spike)
  if (metrics.invalidMacRate > thresholds.invalidMacRate.warning) {
    anomalies.push({
      severity: 'critical',
      type: 'invalid_mac_spike',
      current: metrics.invalidMacRate,
      baseline: baseline.failures.invalidMac,
      message: 'Detected potential token forgery attack',
    })
  }

  // Monitor for one-shot token replays
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

**Critical Alerts (Immediate Attention):**

```yaml
- name: csrf_one_shot_replay
  condition: csrf.one_shot.replay_attempt.total > 0
  severity: critical
  message: 'One-shot token replay detected'
  action: page_oncall

- name: csrf_invalid_mac_spike
  condition: rate(csrf.validation.fail.by_reason{reason="invalid_mac"}[5m]) > 0.001
  severity: critical
  message: 'Invalid MAC spike - potential token forgery attempt'
  action: page_oncall

- name: csrf_key_rotation_failure
  condition: csrf.key.rotation.failures > 0
  severity: critical
  message: 'Key rotation operation failed'
  action: page_oncall
```

**Warning Alerts (Maintenance Review):**

```yaml
- name: csrf_validation_fail_spike
  condition: rate(csrf.validation.fail.total[5m]) > baseline * 2
  severity: warning
  message: 'Increase in CSRF validation failures'
  action: notify_team

- name: csrf_origin_mismatch_spike
  condition: rate(csrf.origin.mismatch.total[5m]) > baseline * 3
  severity: warning
  message: 'Detected spike in origin mismatches'
  action: notify_team

- name: csrf_clock_skew
  condition: abs(csrf.clock.skew.delta) > 300
  severity: warning
  message: 'Clock skew exceeds 5 minutes'
  action: notify_ops
```

### 5.2 Alert Routing

```javascript
const alertRouting = {
  critical: {
    channels: ['pagerduty', 'slack-security', 'oncall-email'],
    escalation: {
      timeout: 5 * 60 * 1000, // 5 minutes
      levels: ['on-call engineer', 'security lead', 'CTO'],
    },
  },

  warning: {
    channels: ['slack-security', 'team-email'],
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

**Visual Panels:**

1. **Validation Overview:**
   - Success rate (gauge)
   - Failure rate (gauge)
   - Total validations (counter)
   - Failures by reason (breakdown chart)

2. **Security Incidents:**
   - Invalid MAC attempts (timeline)
   - One-shot replay attempts (timeline)
   - Origin mismatches (timeline)
   - Cross-site block events (timeline)

3. **Performance Metrics:**
   - Validation duration (distribution histogram)
   - P50/P95/P99 latency (gauge)
   - Timing variance across requests (timeline)

4. **Key Management Status:**
   - Current active Key ID (kid)
   - Active keyring size
   - Rotation events (timeline)
   - Failures in rotation (counter)

### 6.2 Operational Dashboard

**Visual Panels:**

1. **Token Lifecycle:**
   - Token generation rate
   - Token expiry rate
   - Token refresh frequency
   - Requests served within the grace window

2. **One-Shot Tokens:**
   - Generation rate for one-shot tokens
   - Nonce cache utilization (size/capacity)
   - Nonce cache eviction frequency
   - Replay attempts detected

3. **Client Behavior:**
   - Browser mode vs. API mode distribution
   - Presence of Fetch Metadata headers
   - Legacy browser traffic patterns

---

## 7. Logging

### 7.1 Log Severity Levels

**ERROR (Security Incident):**

```javascript
logger.error('One-shot token replay attempt detected', {
  nonce: parsed.nonce,
  action,
  sessionId,
  userId,
  ip: req.ip,
  userAgent: req.headers['user-agent'],
})
```

**WARN (Suspicious Activity):**

```javascript
logger.warn('CSRF validation failure', {
  reason: result.reason,
  path: req.path,
  method: req.method,
  origin: req.headers.origin,
  referer: req.headers.referer,
  sessionId: req.sessionId,
})
```

**INFO (Operational Events):**

```javascript
logger.info('Key rotation completed successfully', {
  oldKid,
  newKid,
  keyringSize: keyring.length,
})
```

### 7.2 Structured Logging

**Standard Format:**

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

### 7.3 Log Retention Policy

```javascript
const logRetention = {
  error: 90, // 90 days (for forensic investigations)
  warn: 30, // 30 days (for trend analysis)
  info: 7, // 7 days (for operational troubleshooting)
}
```

---

## 8. SIEM Integration

### 8.1 Critical Security Events

**Events Exported to SIEM:**

- `csrf.one_shot.replay_attempt`
- `csrf.validation.fail.invalid_mac`
- `csrf.origin.mismatch`
- `csrf.key.rotation.failures`
- `csrf.anomaly.validation_spike`

### 8.2 SIEM Correlation Rules

- **Rule:** Multiple CSRF failures from a single IP.
  - _Condition:_ More than 10 failures in 5 minutes from the same source.
  - _Action:_ Block IP at WAF level, notify security operations.

- **Rule:** One-shot replay accompanied by session anomaly.
  - _Condition:_ Detected replay AND flagged session activity.
  - _Action:_ Automatically invalidate the session, alert on-call.

- **Rule:** Invalid MAC spike concurrent with origin mismatches.
  - _Condition:_ Both metrics exceeding high-threshold limits.
  - _Action:_ High-severity incident alert, potential attack in progress.

---

## 9. Implementation Checklist

### Metrics Delivery

- [ ] Validation success/failure metrics
- [ ] Security event counters (replay, MAC, origin)
- [ ] Cryptographic health indicators (key rotation, derivation errors)
- [ ] Latency histograms and throughput gauges

### Alerting System

- [ ] P0 alerts: one-shot replay, forgery attempts, rotation failure
- [ ] P1 alerts: unexpected failure spikes, origin violations
- [ ] Integration with PagerDuty, Slack, or similar notification tools

### Observability

- [ ] Security-focused Grafana/Datadog dashboards
- [ ] Operation-focused performance dashboards

### Logging Strategy

- [ ] Implementation of JSON structured logs
- [ ] Configuration of retention periods per severity
- [ ] Direct export pipelines for SIEM consumption

---

## 10. Conclusion

This telemetry architecture ensures **production-grade observability** for the CSRF defense layer:

✅ **Comprehensive metrics** covering security, cryptography, and performance.
✅ **Baseline monitoring** and automated anomaly detection.
✅ **Immediate alerting** for high-risk security events.
✅ **Decision-support dashboards** for both security and operations teams.
✅ **Native SIEM support** for advanced threat correlation.

**Next step:** Incident Response Runbook.

---

# Part II: Incident Response

## 1. Overview

This runbook defines the operational procedures for addressing **security incidents** that may occur within the Sigil CSRF security system.

### Incident Categories

1. **Key Compromise** (Critical)
2. **Token Forgery Suspicion** (Critical)
3. **Clock Skew Incident** (Operational)
4. **One-Shot Replay Attack** (Critical)
5. **Validation Spike** (Anomaly)

---

## 2. Key Compromise

### 2.1 Scenario 1: Signing Key Leak (kid-specific)

**Symptoms:**

- Spike in invalid MAC rates for a specific Key ID (kid).
- Suspicious token generation patterns identified in audit logs.
- External security reports (e.g., bug bounty, penetration test).

**Impact:**

- An attacker can generate valid tokens using the leaked kid.
- **Blast Radius:** Limited to tokens generated with the compromised kid.

**Immediate Response (0-15 minutes):**

```bash
# 1. Identify the compromised kid
kid_compromised=5

# 2. Trigger an emergency rotation (kid bump)
curl -X POST https://api.example.com/internal/csrf/rotate-key \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"reason": "key_compromise", "invalidate_kid": '$kid_compromised'}'

# 3. Monitor for continued use of the old kid
# Alert: csrf.validation.by_kid{kid=$kid_compromised} > 0
```

**Short-Term Response (15-60 minutes):**

1. **Forensic Analysis:**

   ```sql
   -- Analyze requests made using the compromised kid
   SELECT timestamp, session_id, user_id, ip, path, method
   FROM csrf_validation_logs
   WHERE kid = $kid_compromised
     AND timestamp > $compromise_time
   ORDER BY timestamp DESC;
   ```

2. **Session Invalidation (Optional):**

   ```javascript
   // Invalidate sessions associated with suspicious activity
   const suspiciousSessions = identifySuspiciousSessions(kid_compromised)
   suspiciousSessions.forEach((sessionId) => {
     invalidateSession(sessionId)
     notifyUser(sessionId, 'security_incident')
   })
   ```

3. **User Notification:**
   - Email affected users.
   - Consider a forced password reset if deemed necessary.

**Long-Term Response (1-24 hours):**

1. **Root Cause Analysis:** Determine the leak vector (e.g., log leak, memory dump, insider threat) and patch.
2. **Audit Period:** Review the 7 days prior to the compromise for anomalies.
3. **Post-Mortem:** Document the incident timeline, impact, and lessons learned.

---

### 2.2 Scenario 2: Master Secret Leak (Global)

**Symptoms:**

- Spikes in invalid MAC rates across all Key IDs.
- Master secret exposed externally (e.g., GitHub leak, configuration dump).
- Suspicious activity observed across multiple kids.

**Impact:**

- Attacker can generate valid tokens for any kid.
- **Blast Radius:** **All currently active tokens.**

**Immediate Response (0-5 minutes):**

```bash
# CRITICAL: Immediate master secret rotation
curl -X POST https://api.example.com/internal/csrf/rotate-master-secret \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"reason": "master_secret_compromise", "invalidate_all": true}'

# All users will be required to re-authenticate.
```

**Short-Term Response (5-30 minutes):**

1. **Global Session Invalidation:**

   ```javascript
   // Invalidate ALL sessions
   invalidateAllSessions()

   // Force users to the login page
   broadcastMessage({
     type: 'force_logout',
     reason: 'security_incident',
   })
   ```

2. **Public Communication:**
   - Update the status page.
   - Distribute security advisories.

3. **Monitoring:** Monitor for successful token generation and validation using the new master secret.

**Long-Term Response (1-7 days):**

1. **Forensic Investigation:** Determine how the master secret was exposed.
2. **Security Hardening:** Review secret management (Vault, KMS), access controls, and rotation automation.
3. **Compliance:** Comply with legal and regulatory reporting requirements (e.g., GDPR).

---

## 3. Token Forgery Suspicion

### 3.1 Symptoms

**Metrics:**

```
csrf.validation.fail.by_reason{reason="invalid_mac"} > threshold
```

**Thresholds:**

- Warning: 3x Baseline
- Critical: 10x Baseline

### 3.2 Immediate Response (0-15 minutes)

1. **Verify Alert:** Confirm the spike via metric queries.
2. **Identify Patterns:** Analyze logs for suspicious patterns in IP addresses or User-Agent strings.
3. **IP Blocking:** Optionally block highly suspicious IP addresses at the WAF or firewall.

### 3.3 Short-Term Response (15-60 minutes)

1. **Token Analysis:** Collect and analyze invalid tokens for common prefixes, timing patterns, or source similarities.
2. **Rate Limiting:** Implement aggressive rate limits on token generation and validation.
3. **Intensify Monitoring:** Move to real-time monitoring of validation failure rates.

### 3.4 Long-Term Response (1-7 days)

1. **Forensic Analysis:** Determine the forgery technique used (e.g., brute-force, timing attack).
2. **Security Audit:** Re-verify constant-time implementation and audit the HMAC library used.

---

## 4. Clock Skew Incident

### 4.1 Symptoms

**Metrics:**

```
abs(csrf.clock.skew.delta) > 300  // Greater than 5 minutes
```

**Logs:**
`WARN: Clock skew detected: server_time=X, client_time=Y, delta=300s`

### 4.2 Immediate Response (0-15 minutes)

1. **Identify Scope:** Determine which servers are affected.
2. **Temporary Mitigation:** Temporarily increase TTL tolerance and the grace window to minimize user disruption.
3. **Assess User Impact:** Gauge how many users are experiencing expiration-related failures.

### 4.3 Short-Term Response (15-60 minutes)

1. **NTP Sync:** Force an NTP resynchronization on affected servers.
2. **Monitoring:** Closely monitor the delta until it returns to normal levels.
3. **Restore Tolerance:** Revert TTL and grace window settings to their original values.

### 4.4 Long-Term Response (1-7 days)

1. **Root Cause:** Investigate for NTP server failure, VM clock drift, or misconfiguration.
2. **Prevention:** Implement automated NTP health checks and clock skew alerting.

---

## 5. One-Shot Replay Attack

### 5.1 Symptoms

**Metrics:**
`csrf.one_shot.replay_attempt.total > 0` (Any value is CRITICAL)

**Logs:**
`ERROR: One-shot token replay attempt detected for nonce: abc123..., user: user_123`

### 5.2 Immediate Response (0-5 minutes)

1. **Immediate Session Invalidation:** Invalidate the session associated with the replay attempt and notify the user.
2. **IP Blocking:** Block the attacker's source IP address.
3. **Forensic Snapshot:** Capture a comprehensive forensic record of the incident.

### 5.3 Short-Term Response (5-60 minutes)

1. **User Investigation:** Determine if the user's account has been compromised. Check login history and device fingerprints.
2. **Attack Vector Analysis:** Analyze how the token was replayed (e.g., XSS, MitM, device compromise).
3. **Escalation:** Formally escalate to the security operations center (SOC).

### 5.4 Long-Term Response (1-7 days)

1. **Security Review:** Perform XSS vulnerability scans and audit token storage and CSP policies.
2. **User Communication:** Enforce password resets and recommend enabling 2FA for affected users.

---

## 6. Validation Spike

### 6.1 Symptoms

**Metrics:**
`rate(csrf.validation.fail.total[5m]) > baseline * 2`

### 6.2 Immediate Response (0-15 minutes)

1. **Identify Cause:** Check for recent deployments, traffic spikes, bot activity, or key rotation events.
2. **Mitigation:** Enable aggressive rate limiting or CAPTCHAs if bot activity is detected. Consider rolling back if related to a recent deployment.

---

## 7. Escalation Matrix

### Severity Levels

- **Critical (P0):** One-shot replay, Master secret leak, Invalid MAC spike (10x).
- **High (P1):** Signing key leak, Token forgery suspicion, Validation spike (5x).
- **Medium (P2):** Clock skew (>5 min), Validation spike (2x).
- **Low (P3):** Minor clock skew, Isolated validation failures.

---

## 8. Communication Templates

### 8.1 Internal (Security Operations)

- Subject: [P0] Critical CSRF Incident Detected
- Detail specific user, session, IP, and action impact.

### 8.2 External (End User)

- Subject: Security Alert - Your Account Has Been Secured
- Inform user of suspicious activity and provide clear steps for remediation (e.g., password reset).

---

## 9. Post-Incident Checklist

### Immediate (0-24 hours)

- [ ] Document the incident timeline and identify the root cause.
- [ ] Notify affected users and collect forensic data.

### Short-Term (1-7 days)

- [ ] Complete the formal post-mortem.
- [ ] Update monitoring thresholds and the IR runbook based on findings.

### Long-Term (1-4 weeks)

- [ ] Remediate underlying vulnerabilities.
- [ ] Conduct team training and share lessons learned across the organization.

---

## 10. Runbook Maintenance

- **Review Frequency:** Quarterly.
- **Update Triggers:** Post-mortem findings, architecture changes, or new attack vectors.
- **Ownership:** Security Operations Team.

---
