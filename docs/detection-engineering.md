# Detection Engineering

## 1. Introduction

This document describes the detection logic implemented in SIEM v1.

The detection engine analyses structured Linux system events and identifies suspicious activity using custom detection rules and event correlation.

The current implementation focuses on authentication monitoring, particularly SSH and sudo authentication failures.

## 2. Detection Architecture

```text
Structured Events
       |
       v
 Detection Engine
       |
       +----------------------+
       |                      |
       v                      v
 Individual Detection    Correlation Detection
       |                      |
       v                      v
 Single Event Alerts     Repeated Activity Alerts
       |                      |
       +----------+-----------+
                  |
                  v
             Alert Manager
                  |
                  v
             SQLite Storage
```

The detection engine uses two approaches:

- **Event-based detection:** Evaluates individual events against detection rules.
- **Correlation-based detection:** Analyses recent event history to identify repeated suspicious activity.

## 3. Implemented Detection Rules

| Rule ID | Description | Severity |
|---|---|---|
| `HIGH_PRIORITY_EVENT` | Detects system events with high journal priority | HIGH |
| `FAILED_SSH_AUTHENTICATION` | Detects failed SSH authentication | HIGH |
| `FAILED_SUDO_AUTHENTICATION` | Detects failed sudo authentication | HIGH |
| `REPEATED_FAILED_SSH` | Detects repeated SSH authentication failures | CRITICAL |
| `REPEATED_FAILED_SUDO` | Detects repeated sudo authentication failures | CRITICAL |

## 4. SSH Authentication Detection

### Rule: FAILED_SSH_AUTHENTICATION

**Objective:** Identify failed SSH authentication attempts.

The detection logic examines event process information and log messages to identify SSH-related authentication failures.

It checks for:

- SSH-related process information, such as `sshd`.
- PAM authentication failure messages.
- Failed password messages.

**Severity:** HIGH

### Rule: REPEATED_FAILED_SSH

**Objective:** Identify repeated SSH authentication failures within a short period.

The correlation logic examines recent event history and counts matching failed SSH authentication events.

| Parameter | Value |
|---|---|
| Time window | 5 minutes |
| Threshold | 3 failed attempts |
| Severity | CRITICAL |

The rule generates a critical alert when the threshold is reached.

## 5. Sudo Authentication Detection

### Rule: FAILED_SUDO_AUTHENTICATION

**Objective:** Identify failed sudo authentication attempts.

The detection logic examines sudo-related process information and authentication failure messages.

It identifies events containing sudo authentication failure information.

**Severity:** HIGH

### Rule: REPEATED_FAILED_SUDO

**Objective:** Identify repeated sudo authentication failures within a short period.

The correlation logic analyses recent event history and counts matching failed sudo authentication events.

| Parameter | Value |
|---|---|
| Time window | 5 minutes |
| Threshold | 3 failed attempts |
| Severity | CRITICAL |

A critical alert is generated when the threshold is reached.

## 6. High-Priority Event Detection

### Rule: HIGH_PRIORITY_EVENT

**Objective:** Identify Linux journal events with high system priority.

The detection engine evaluates the event priority field and generates a HIGH severity alert when the priority value is 2 or lower.

This provides basic visibility into important system events beyond authentication monitoring.

## 7. Event Correlation

Correlation allows the SIEM to identify patterns across multiple events instead of treating every event independently.

SIEM v1 maintains a rolling history of up to 100 events.

The repeated authentication rules use this history to evaluate whether multiple failed attempts occur within the configured five-minute window.

This helps identify repeated activity that may be less meaningful when viewed as individual events.

## 8. Alert Severity

The current detection engine uses the following severity levels:

| Severity | Meaning |
|---|---|
| HIGH | Suspicious or important security activity |
| CRITICAL | Repeated authentication activity meeting a correlation threshold |

Severity is assigned by the detection rules and passed to the alert manager.

## 9. Alert Deduplication

The alert manager uses SHA-256 fingerprints to identify matching detection results.

The fingerprint is generated from:

- Detection rule.
- Hostname.
- Process.
- Detection message.

A five-minute cooldown is used to suppress matching alerts generated within the cooldown period.

This reduces repeated storage of identical alerts.

## 10. Testing and Validation

Detection logic has been tested using:

- Synthetic SSH authentication failure events.
- Synthetic repeated sudo authentication events.
- Controlled failed SSH login attempts.
- Controlled sudo authentication failure attempts.
- Repeated authentication event correlation tests.

The repeated sudo correlation function has been validated using synthetic events. Live repeated sudo correlation should be treated as requiring further end-to-end verification.

Testing is performed in controlled environments using systems under my control.

## 11. Current Limitations and Future Improvements

The current detection engine is an initial implementation.

Potential improvements include:

- Additional authentication and system activity detection rules.
- Improved event correlation and context enrichment.
- More comprehensive false-positive testing.
- MITRE ATT&CK technique mapping.
- Configurable detection thresholds and time windows.
- Improved alert investigation context.
- Automated detection rule testing.

## 12. Detection Engineering Status

**Current status:** Initial detection engine implemented.

SIEM v1 supports individual event detection, repeated authentication correlation, severity assignment, and alert deduplication.

Future development will expand detection coverage and improve correlation capabilities.

---

*Cyber Defense Platform — SIEM v1 Technical Documentation.*