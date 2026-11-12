# SIEM Data Flow

## 1. Introduction

This document describes how security events move through SIEM v1, from initial log collection to storage, detection, alert generation, and dashboard presentation.

The SIEM uses a continuous processing pipeline built with Python.

## 2. High-Level Data Flow

```text
Linux System Logs
       |
       v
   Log Collector
       |
       v
   Event Parser
       |
       v
   Event Pipeline
       |
       +--------------------+
       |                    |
       v                    v
  SQLite Storage      Detection Engine
                            |
                            v
                      Alert Manager
                            |
                            v
                       Alert Storage
                            |
                            v
                         FastAPI
                            |
                            v
                      SOC Dashboard
```

## 3. Stage 1 — Log Collection

The collector uses `journalctl` to retrieve live Linux system log entries.

The command used is:

```bash
journalctl -f -n 0 -o json
```

**Command options:**

| Option | Purpose |
|---|---|
| `-f` | Follow new journal entries |
| `-n 0` | Start without displaying previous entries |
| `-o json` | Output entries in JSON format |

Each incoming log entry is passed to the parser as a raw JSON string.

## 4. Stage 2 — Event Parsing

The parser converts raw journal JSON into a structured event.

It extracts relevant information, including:

- Timestamp
- Hostname
- Process name
- Process ID
- Severity
- Message
- Source

Journal timestamps are converted from microseconds into UTC ISO 8601 format.

Malformed JSON entries are rejected rather than passed into the processing pipeline.

## 5. Stage 3 — Event Processing

The pipeline coordinates the processing of incoming events.

For each parsed event, it:

1. Adds the event to recent in-memory history.
2. Stores the event in the SQLite database.
3. Runs individual detection rules.
4. Evaluates correlation rules against recent event history.
5. Sends detection results to the alert manager.

The pipeline maintains a rolling event history with a maximum size of 100 events.

## 6. Stage 4 — Event Storage

Parsed events are stored in the SQLite database.

The database provides persistent storage for security events and supports queries for recent activity and event statistics.

Each event contains structured fields such as its timestamp, hostname, process, severity, message, and source.

## 7. Stage 5 — Detection Engine

The detection engine analyses events using custom detection rules.

### Individual Event Detection

Individual detection rules evaluate one event at a time.

Examples include:

- Failed SSH authentication.
- Failed sudo authentication.
- High-priority system events.

### Correlation Detection

Correlation rules analyse recent event history to identify repeated suspicious activity.

Examples include:

- Repeated failed SSH authentication attempts.
- Repeated failed sudo authentication attempts.

The repeated authentication rules use a five-minute time window and a threshold of three failed attempts.

## 8. Stage 6 — Alert Management

When a detection rule identifies suspicious activity, its result is passed to the alert manager.

The alert manager:

1. Generates an alert timestamp.
2. Creates a SHA-256 fingerprint from the detection details.
3. Checks for an existing matching alert within the cooldown period.
4. Stores the alert if it is not suppressed.

The current deduplication cooldown is five minutes.

## 9. Stage 7 — API Layer

FastAPI exposes stored SIEM information through REST endpoints.

The API provides access to:

- Recent security events.
- Recent alerts.
- Event and alert statistics.
- Hourly event activity.

The dashboard retrieves this information through HTTP requests.

## 10. Stage 8 — SOC Dashboard

The dashboard provides a visual interface for security monitoring and investigation.

It displays:

- Recent security alerts.
- Event investigation records.
- Event activity over the previous 24 hours.
- Event and alert statistics.
- System and API connectivity status.

The dashboard automatically refreshes its data at regular intervals.

## 11. Example Event Lifecycle

A controlled failed SSH authentication attempt demonstrates the processing flow:

```text
Failed SSH Login
       |
       v
journalctl records the event
       |
       v
Collector receives the log
       |
       v
Parser extracts event fields
       |
       v
Pipeline stores the event
       |
       v
Detection Engine identifies failure
       |
       v
Alert Manager generates an alert
       |
       v
Alert stored in SQLite
       |
       v
FastAPI exposes the alert
       |
       v
SOC Dashboard displays the alert
```

Repeated failed authentication attempts can also trigger correlation-based alerts.

## 12. Data Flow Summary

| Stage | Component | Output |
|---|---|---|
| 1 | Collector | Raw journal entries |
| 2 | Parser | Structured events |
| 3 | Pipeline | Processed events |
| 4 | Database | Stored events |
| 5 | Detection Engine | Detection results |
| 6 | Alert Manager | Generated alerts |
| 7 | FastAPI | API responses |
| 8 | Dashboard | Visualised security activity |

---

*Cyber Defense Platform — SIEM v1 Technical Documentation.*