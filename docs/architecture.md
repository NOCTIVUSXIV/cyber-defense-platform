# System Architecture

## 1. Introduction

The Cyber Defense Platform is a modular cybersecurity system designed to monitor, detect, investigate, and respond to security threats.

The platform is being developed incrementally, with each security component designed to operate independently while contributing to a unified defense architecture.

The first implemented component is a custom Security Information and Event Management (SIEM) system.

## 2. Platform Architecture

The long-term platform is organised into the following major components:

```text
Cyber Defense Platform
│
├── SIEM
│   ├── Log Collection
│   ├── Event Parsing
│   ├── Event Storage
│   ├── Detection Engine
│   └── Alert Management
│
├── EDR
│   ├── Endpoint Monitoring
│   ├── Process Monitoring
│   └── Endpoint Response
│
├── Network Monitoring
│   ├── Traffic Collection
│   └── Network Analysis
│
├── IDS / IPS
│   ├── Intrusion Detection
│   └── Intrusion Prevention
│
├── Threat Intelligence
│   └── Threat Data Enrichment
│
├── SOC Dashboard
│   ├── Security Monitoring
│   └── Investigation Interface
│
└── Incident Response / Automation
    ├── Response Workflows
    └── Automated Actions
```

The architecture is modular so that additional security capabilities can be developed and integrated over time.

## 3. Current Implementation: SIEM v1

SIEM v1 is the first operational subsystem of the platform.

Its primary responsibility is to collect Linux system logs, process security events, identify suspicious activity, and generate alerts.

### SIEM Component Architecture

```text
Linux System
     │
     ▼
Log Collector
     │
     ▼
Event Parser
     │
     ▼
SQLite Database
     │
     ▼
Detection Engine
     │
     ▼
Alert Manager
     │
     ▼
FastAPI
     │
     ▼
SOC Dashboard
```

### Component Responsibilities

| Component | Responsibility |
|---|---|
| Collector | Retrieves live Linux journal events |
| Parser | Converts raw JSON logs into structured events |
| Database | Stores events and generated alerts |
| Detection Engine | Evaluates events against detection rules |
| Alert Manager | Creates alerts and handles deduplication |
| Pipeline | Coordinates event processing |
| FastAPI | Exposes SIEM data through REST endpoints |
| Dashboard | Displays events, alerts, and statistics |

## 4. Technology Architecture

The current implementation uses the following technologies:

| Technology | Architectural Role |
|---|---|
| Python | Core application logic |
| Linux / Arch Linux | Operating system and log source |
| journalctl | System log collection |
| SQLite | Persistent data storage |
| FastAPI | Backend REST API |
| HTML | Dashboard structure |
| CSS | Dashboard presentation |
| JavaScript | Dashboard interaction |
| Git / GitHub | Source control and project management |

## 5. Data Processing Architecture

The SIEM follows a continuous event-processing model.

1. The collector reads new journal entries.
2. The parser converts raw log data into structured events.
3. The pipeline stores parsed events in SQLite.
4. The detection engine evaluates individual events.
5. Correlation logic analyses recent event history.
6. The alert manager creates alerts and applies deduplication.
7. FastAPI provides access to stored events, alerts, and statistics.
8. The dashboard retrieves and displays the information.

## 6. Design Principles

### Modularity

Each subsystem has a defined responsibility and can be developed independently.

### Separation of Concerns

Log collection, parsing, storage, detection, alert management, and presentation are handled by separate components.

### Extensibility

The platform is designed to support additional detection rules, monitoring capabilities, and response mechanisms.

### Transparency

Core security functionality is implemented directly to develop an understanding of the underlying technologies and processes.

### Controlled Testing

Security testing and attack simulations are conducted in controlled environments using systems under my control.

## 7. Future Architecture

Future development will extend the current SIEM architecture with:

- Endpoint monitoring through EDR.
- Network traffic visibility and analysis.
- Network intrusion detection and prevention.
- Threat intelligence integration.
- Centralised security investigation.
- Incident response and automation.

These components are planned extensions and are not yet part of the implemented SIEM v1 system.

## 8. Architecture Status

| Component | Status |
|---|---|
| SIEM v1 | Core implementation completed |
| EDR | Planned |
| Network Monitoring | Planned |
| IDS / IPS | Planned |
| Threat Intelligence | Planned |
| Incident Response | Planned |
| Full Platform Integration | Planned |

---

*Cyber Defense Platform — Built from the ground up. Designed for defense.*