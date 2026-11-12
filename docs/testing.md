# SIEM Testing and Validation

## 1. Introduction

This document describes the testing and validation performed on SIEM v1.

Testing focuses on verifying individual components and ensuring that security events travel through the complete SIEM processing pipeline.

All security testing is conducted in controlled environments using systems under my control.

## 2. Testing Objectives

The primary testing objectives are:

- Verify live Linux log collection.
- Validate event parsing and normalisation.
- Confirm persistent event storage.
- Verify individual detection rules.
- Test repeated authentication event correlation.
- Validate alert generation and deduplication.
- Confirm API endpoint functionality.
- Verify dashboard connectivity and data presentation.
- Test the complete event-processing workflow.

## 3. Component Testing

### 3.1 Log Collector

**Objective:** Verify that the collector receives live Linux journal events.

Run from the project root:

```bash
python -m siem.collector.collector
```

In another terminal, generate a test event:

```bash
logger "SIEM collector test event"
```

**Expected result:**

The collector receives the newly generated journal entry.

**Verified:** Live journal event collection.

### 3.2 Event Parser

**Objective:** Verify that raw JSON journal entries are converted into structured events.

Testing includes:

- Valid JSON input.
- Extraction of expected event fields.
- Timestamp conversion.
- Malformed JSON handling.

**Expected result:**

Valid entries are converted into structured event records, while malformed entries are rejected.

### 3.3 Database

**Objective:** Verify persistent storage of events and alerts.

Testing includes:

- Database creation.
- Event insertion.
- Alert insertion.
- Retrieval of recent events.
- Retrieval of recent alerts.
- Statistics queries.

**Expected result:**

Events and alerts are stored and can be retrieved through database functions.

## 4. Detection Engine Testing

### 4.1 SSH Authentication Detection

**Objective:** Verify detection of failed SSH authentication attempts.

**Test procedure:**

Generate controlled failed SSH authentication attempts against a test environment.

**Expected result:**

The detection engine generates a `FAILED_SSH_AUTHENTICATION` alert.

**Verified:** Controlled SSH authentication failure detection.

### 4.2 Repeated SSH Authentication Detection

**Objective:** Verify correlation of repeated failed SSH authentication attempts.

**Test procedure:**

Generate multiple failed SSH authentication events within the configured five-minute window.

**Expected result:**

The detection engine generates a `REPEATED_FAILED_SSH` alert when the threshold is reached.

**Verified:** Repeated SSH authentication correlation through controlled testing.

### 4.3 Sudo Authentication Detection

**Objective:** Verify detection of failed sudo authentication attempts.

**Test procedure:**

Generate a controlled sudo authentication failure in the test environment.

**Expected result:**

The detection engine generates a `FAILED_SUDO_AUTHENTICATION` alert.

**Verified:** Individual sudo authentication failure detection.

### 4.4 Repeated Sudo Authentication Detection

**Objective:** Verify correlation of repeated failed sudo authentication events.

**Test procedure:**

Provide synthetic sudo authentication failure events to the correlation detection function.

**Expected result:**

Three matching failed events within the configured five-minute window produce a `REPEATED_FAILED_SUDO` alert.

**Verified:** Synthetic event correlation test.

**Further validation required:** Complete live end-to-end verification of repeated sudo authentication correlation.

## 5. Alert Management Testing

**Objective:** Verify alert creation and deduplication.

Testing includes:

- Alert timestamp generation.
- SHA-256 fingerprint generation.
- Matching fingerprint checks.
- Five-minute cooldown behaviour.
- Alert persistence.

**Expected result:**

New alerts are stored, while matching alerts within the cooldown period are suppressed.

## 6. API Testing

**Objective:** Verify that the FastAPI backend exposes SIEM data correctly.

The following endpoints are tested:

| Endpoint | Test |
|---|---|
| `GET /` | API status |
| `GET /events` | Event retrieval |
| `GET /alerts` | Alert retrieval |
| `GET /statistics` | Event and alert statistics |
| `GET /statistics/activity` | Hourly event activity |

Example:

```bash
curl http://127.0.0.1:8000/events
```

**Expected result:**

The API returns stored SIEM information in JSON format.

**Verified:** API retrieval of stored security events.

## 7. Dashboard Testing

**Objective:** Verify communication between the dashboard and the FastAPI backend.

Testing includes:

- API connectivity.
- Dashboard online status.
- Security alert presentation.
- Event investigation records.
- Event activity visualisation.
- Automatic data refresh.
- Search and filtering.

**Expected result:**

The dashboard retrieves and displays information from the SIEM API.

**Verified:** Dashboard connectivity and rendering.

## 8. End-to-End Testing

**Objective:** Verify the complete SIEM event-processing workflow.

Generate a Linux journal event:

```bash
logger "SIEM FINAL END TO END TEST"
```

Inspect stored events through the API:

```bash
curl http://127.0.0.1:8000/events
```

**Expected processing flow:**

```text
Test Event
    |
    v
Linux Journal
    |
    v
Collector
    |
    v
Parser
    |
    v
Pipeline
    |
    v
SQLite Database
    |
    v
FastAPI
    |
    v
API Response
```

**Verified:** The generated test event was collected, parsed, stored in SQLite, and retrieved through the API.

## 9. Test Results Summary

| Component | Result |
|---|---|
| Log Collector | Verified |
| Event Parser | Tested |
| Database Storage | Verified |
| SSH Failure Detection | Verified |
| Repeated SSH Detection | Verified |
| Sudo Failure Detection | Verified |
| Repeated Sudo Correlation | Synthetic test verified; live validation pending |
| Alert Management | Tested |
| FastAPI | Verified |
| SOC Dashboard | Verified |
| End-to-End Event Flow | Verified |

## 10. Future Testing Improvements

Future testing will focus on:

- Automated unit tests.
- Automated integration tests.
- Additional malformed and incomplete event testing.
- False-positive evaluation.
- Detection rule regression testing.
- Database recovery and reliability testing.
- API security testing.
- Performance testing under higher event volumes.
- Complete live repeated sudo correlation validation.

## 11. Conclusion

SIEM v1 has undergone component-level and end-to-end testing.

The core workflow has been verified, including live log collection, event processing, database storage, detection, API retrieval, and dashboard presentation.

Further testing will expand reliability, detection coverage, and security validation as the platform develops.

---

*Cyber Defense Platform — SIEM v1 Technical Documentation.*