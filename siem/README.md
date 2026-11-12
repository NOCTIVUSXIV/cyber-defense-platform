# SIEM v1 — Security Information and Event Management

A custom-built SIEM system developed as the first core component of the Cyber Defense Platform.

SIEM v1 collects Linux system logs, parses and stores security events, detects suspicious authentication activity, generates alerts, and provides a dashboard for security monitoring and investigation.

## Overview

The objective of this project is to understand and implement the core components of a SIEM system rather than relying entirely on existing security monitoring platforms.

The system is built with Python and uses Linux `journalctl` as its primary log source.

## Architecture

```text
Linux System Logs
       |
       v
   Collector
       |
       v
     Parser
       |
       v
   SQLite Database
       |
       v
 Detection Engine
       |
       v
   Alert Manager
       |
       v
    FastAPI
       |
       v
   SOC Dashboard
```

## Core Components

### 1. Log Collector

- Collects live Linux system logs using `journalctl`.
- Reads journal entries in JSON format.
- Streams events into the processing pipeline.

### 2. Event Parser

- Parses JSON log entries.
- Extracts relevant event fields.
- Normalises timestamps into UTC ISO 8601 format.
- Handles malformed log entries.

**Extracted fields include:**

- Timestamp
- Hostname
- Process
- Process ID
- Severity
- Message
- Source

### 3. Database

Uses SQLite for persistent event and alert storage.

**Events table:**
- Event ID
- Timestamp
- Hostname
- Process
- PID
- Severity
- Message
- Source

**Alerts table:**
- Alert ID
- Event timestamp
- Alert timestamp
- Detection rule
- Severity
- Message
- Hostname
- Process
- Fingerprint

The database also provides queries for recent events, alerts, severity statistics, and event activity.

### 4. Detection Engine

Analyses parsed events and identifies suspicious activity using custom detection rules.

**Implemented detection rules:**

| Detection Rule | Description | Severity |
|---|---|---|
| `HIGH_PRIORITY_EVENT` | Identifies high-priority system events | HIGH |
| `FAILED_SSH_AUTHENTICATION` | Detects failed SSH authentication attempts | HIGH |
| `FAILED_SUDO_AUTHENTICATION` | Detects failed sudo authentication attempts | HIGH |
| `REPEATED_FAILED_SSH` | Identifies repeated SSH authentication failures within a five-minute window | CRITICAL |
| `REPEATED_FAILED_SUDO` | Identifies repeated sudo authentication failures within a five-minute window | CRITICAL |

The detection engine supports both individual event analysis and correlation across recent event history.

### 5. Alert Manager

- Generates alerts from detection results.
- Assigns timestamps to generated alerts.
- Creates SHA-256 fingerprints for alert identification.
- Uses a five-minute cooldown to suppress duplicate alerts with matching fingerprints.

### 6. Processing Pipeline

The pipeline connects the collector, parser, database, detection engine, and alert manager.

It continuously:

1. Collects incoming log events.
2. Parses and normalises events.
3. Stores events in SQLite.
4. Maintains recent event history.
5. Runs individual detection rules.
6. Evaluates correlated authentication activity.
7. Generates and stores alerts.

### 7. REST API

Built with FastAPI to expose SIEM data to the dashboard.

| Endpoint | Function |
|---|---|
| `GET /` | API status |
| `GET /events` | Retrieve recent events |
| `GET /alerts` | Retrieve recent alerts |
| `GET /statistics` | Retrieve event and alert statistics |
| `GET /statistics/activity` | Retrieve hourly event activity |

### 8. SOC Dashboard

A web-based interface for monitoring and investigating security activity.

**Features:**

- Live API connection and system status.
- Recent security alerts.
- Event investigation table.
- Event search and filtering.
- Automatic dashboard refresh.
- Event activity visualisation.
- Event and alert statistics.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core SIEM implementation |
| Linux / Arch Linux | Log source and development environment |
| `journalctl` | Log collection |
| SQLite | Persistent storage |
| FastAPI | REST API |
| HTML | Dashboard structure |
| CSS | Dashboard styling |
| JavaScript | Dashboard functionality |
| Git / GitHub | Version control |

## Running the SIEM

Run commands from the root of the repository.

**1. Activate the virtual environment**

```bash
source .venv/bin/activate
```

**2. Start the SIEM pipeline**

```bash
python -m siem.pipeline
```

**3. Start the API in a separate terminal**

```bash
python -m siem.api.api
```

**4. Start the dashboard web server in another terminal**

```bash
python -m http.server 8080
```

Open the dashboard:

```text
http://127.0.0.1:8080/dashboard/index.html
```

The API runs locally at:

```text
http://127.0.0.1:8000
```

## Project Structure

```text
siem/
├── collector/
│   └── collector.py
├── parser/
│   └── parser.py
├── database/
│   └── database.py
├── detection/
│   └── detection.py
├── alerts/
│   └── alert_manager.py
├── api/
│   └── api.py
├── pipeline.py
└── README.md
```

## Testing

The SIEM has been tested through:

- Live Linux journal event collection.
- Event parsing and database storage.
- Controlled SSH authentication failure attempts.
- Sudo authentication failure detection.
- Synthetic repeated authentication event testing.
- Alert generation and deduplication.
- REST API data retrieval.
- Dashboard connectivity and rendering.
- End-to-end event flow verification.

Testing is performed in a controlled environment using systems under my control.

## Current Status

**SIEM v1 — Core implementation completed.**

Documentation, final verification, and release preparation are underway.

Future development will focus on expanding detection coverage, improving investigation capabilities, and integrating additional security components into the Cyber Defense Platform.

---

*Part of the Cyber Defense Platform — Built from the ground up. Designed for defense.*