# Cyber Defense Platform

A modular cybersecurity defense platform built from the ground up, designed to monitor, detect, investigate, and respond to security threats.

## Overview

Cyber Defense Platform is a cybersecurity engineering project focused on developing practical security monitoring and defense capabilities through hands-on implementation.

The platform is being developed as a collection of integrated security components, beginning with a custom-built Security Information and Event Management (SIEM) system.

## Architecture

```text
Cyber Defense Platform
│
├── SIEM
├── EDR
├── IDS / IPS
├── Detection Engine
├── SOC Dashboard
├── Threat Intelligence
└── Incident Response / Automation
```

## Current Development

### SIEM v1

The first major component is a custom SIEM designed to collect Linux system logs, analyse security events, identify suspicious activity, and generate alerts.

**Implemented capabilities:**

- Live Linux log collection using `journalctl`.
- Event parsing and normalisation.
- SQLite event and alert storage.
- SSH authentication failure detection.
- Sudo authentication failure detection.
- Repeated authentication failure correlation.
- Alert fingerprinting and cooldown.
- REST API built with FastAPI.
- SOC dashboard for event monitoring and investigation.
- Event statistics and activity visualisation.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core development |
| Linux / Arch Linux | Development and log source |
| SQLite | Event and alert storage |
| FastAPI | Backend API |
| HTML | Dashboard structure |
| CSS | Dashboard styling |
| JavaScript | Dashboard functionality |
| Git and GitHub | Version control |

## Security Monitoring Workflow

```text
WATCH
  |
  v
DETECT
  |
  v
INVESTIGATE
  |
  v
DISPLAY
  |
  v
RESPOND
```

## Development Roadmap

- ✅ **SIEM v1** — Core log collection, detection, alerting, API and dashboard.
- 🔄 **Detection Engineering** — Expand detection rules and threat coverage.
- ⬜ **EDR** — Endpoint monitoring and response.
- ⬜ **Network Monitoring** — Network activity visibility.
- ⬜ **IDS / IPS** — Network intrusion detection and prevention.
- ⬜ **Threat Intelligence** — Threat data integration and enrichment.
- ⬜ **Incident Response** — Automated response workflows.
- ⬜ **Platform Integration** — Integrate individual components into one platform.

**Status key:**
- ✅ Completed
- 🔄 In progress
- ⬜ Planned

## Project Philosophy

- Build core security components from the ground up.
- Understand underlying technologies instead of relying entirely on existing security platforms.
- Develop and test in controlled environments.
- Prioritise modularity, reliability, and practical security engineering.
- Document technical decisions and implementation.

## Project Status

The initial SIEM implementation has reached its core development milestone. Documentation, final verification, and release preparation are underway.

## Repository Structure

```text
cyber-defense-platform/
├── README.md
├── docs/
├── siem/
├── edr/
├── ids/
├── detection-engine/
├── dashboard/
├── threat-intelligence/
└── response/
```

---

**Cyber Defense Platform**

*Built from the ground up. Designed for defense.*