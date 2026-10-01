<p align="center">
  <img src="./assets/a_wide_cinematic_cyber_tech_themed_banner_hero_i.png" alt="NextDNS Sentinel banner" width="100%">
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?labelColor=555" alt="MIT License"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-yellow?labelColor=555&logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/storage-SQLite-003B57?labelColor=555&logo=sqlite&logoColor=white" alt="SQLite">
  <img src="https://img.shields.io/badge/interface-Web%20Dashboard-6f42c1?labelColor=555" alt="Web Dashboard">
  <img src="https://img.shields.io/badge/alerts-Telegram-26A5E4?labelColor=555" alt="Telegram">
</p>

# <img src="./assets/icons/sentinel.svg" alt="" width="32" height="32" align="absmiddle"> NextDNS Sentinel

**Local-first NextDNS monitoring, alerting, security intelligence, and configuration control.**

NextDNS Sentinel is a lightweight defensive monitoring utility for **NextDNS profiles you own or administer**. It continuously polls DNS logs, correlates activity with profile denylists, tracks devices and configuration changes, evaluates alert risk, maintains security incidents, and provides a local SOC-style dashboard with optional Telegram notifications.

> **Built around a simple principle:** keep operational data local, protect stored secrets, make security events explainable, and give the operator direct control over monitoring and response.

---

## <img src="./assets/icons/overview.svg" alt="" width="24" height="24" align="absmiddle"> Table of Contents

- [Highlights](#highlights)
- [Feature Set](#feature-set)
- [Architecture](#architecture)
- [Detection & Response Flow](#detection--response-flow)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Dashboard](#dashboard)
- [Alert & Intelligence Engine](#alert--intelligence-engine)
- [Device & Domain Intelligence](#device--domain-intelligence)
- [Configuration Management](#configuration-management)
- [Operations & Recovery](#operations--recovery)
- [Security Model](#security-model)
- [Data & Storage](#data--storage)
- [CLI Usage](#cli-usage)
- [Project Structure](#project-structure)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [License](#license)

---

## <img src="./assets/icons/features.svg" alt="" width="24" height="24" align="absmiddle"> Highlights

| Area | What Sentinel provides |
|---|---|
| **Monitoring** | Multi-profile polling, pagination, overlap-aware checkpoints, duplicate protection |
| **Detection** | Denylist matching, event fingerprints, device activity, inactivity detection |
| **Risk** | Severity/risk scoring, domain intelligence, anomaly detection, historical risk views |
| **Incidents** | Automatic correlation, incident lifecycle, investigation timeline, MTTR metrics |
| **Configuration** | Profile API controls, configuration snapshots, diffs, audit history, safe undo |
| **Response** | Telegram alerts, delivery history, escalation rules, suppression and maintenance modes |
| **Operations** | Health diagnostics, self-monitoring, rate-limit telemetry, retention and database maintenance |
| **Recovery** | SQLite backup/restore, integrity validation, pre-restore rollback copy |
| **Control** | Local web dashboard, Control Center, Safe Mode, optional API authentication |
| **Portability** | JSON settings export/import without exporting secrets |

---

## <img src="./assets/icons/monitor.svg" alt="" width="24" height="24" align="absmiddle"> Why Sentinel?

Sentinel is designed as a **local-first security control plane** around the NextDNS API.

It does not require a hosted backend or a separate database server:

- **NextDNS** is the provider-side source of profiles, configuration, denylists, and DNS logs.
- **Sentinel** performs monitoring, matching, correlation, risk analysis, configuration tracking, and response logic.
- **SQLite** provides local persistence.
- **Telegram** is an optional notification channel.
- **The Web Dashboard** is the operator interface.

This makes the project suitable for personal security monitoring, home/lab environments, and defensive visibility over NextDNS configurations you are authorized to manage.

---

## <img src="./assets/icons/process.svg" alt="" width="24" height="24" align="absmiddle"> Architecture

```text
                         NextDNS API
                             |
              +--------------+--------------+
              |              |              |
           Profiles       Denylist         Logs
              |              |              |
              +--------------+--------------+
                             |
                             v
                 +-------------------------+
                 |     NextDNS Sentinel    |
                 |                         |
                 | Monitor / Matcher       |
                 | Risk / Correlation      |
                 | Incidents / Baselines   |
                 | Config / Audit / Rules  |
                 +-----------+-------------+
                             |
          +------------------+------------------+
          |                  |                  |
          v                  v                  v
     SQLite Store       Telegram API       Web Dashboard
          |                  |                  |
          v                  v                  v
     Audit / History      Alerts         Control Center
```

Everything above the SQLite boundary is designed to run locally with the NextDNS API and optional Telegram delivery.

---

## <img src="./assets/icons/features.svg" alt="" width="24" height="24" align="absmiddle"> Feature Set

### <img src="./assets/icons/monitor.svg" alt="" width="20" height="20" align="absmiddle"> Monitoring & Detection

- Multi-profile monitoring with independent workers.
- NextDNS profile discovery through the API.
- DNS log polling with pagination and cursor handling.
- Persistent polling checkpoints.
- Poll overlap to reduce missed events between cycles.
- Deterministic event fingerprints and duplicate protection.
- Exact, parent-domain, and wildcard-style denylist matching.
- Client IP and DNS event context when supplied by NextDNS.
- Device tracking from observed DNS activity.
- Device inactivity detection and dedicated inactivity alerts.
- Profile health, last successful poll, and latest monitor errors.

### <img src="./assets/icons/security.svg" alt="" width="20" height="20" align="absmiddle"> Alerting & Response

- Alert severity and risk metadata.
- Alert correlation into security incidents.
- Incident states:
  - Open
  - Investigating
  - Resolved
  - Ignored
- Investigation timelines.
- New/Seen alert state.
- Telegram delivery history.
- Notification retry handling.
- Alert suppression and cooldowns.
- Maintenance mode for controlled operational windows.
- Alert rules for filtering, suppression, and escalation.
- Escalation reporting through Telegram.
- Bulk-operation reporting with per-profile results.
- Configuration-change and configuration-undo alerts.

### <img src="./assets/icons/features.svg" alt="" width="20" height="20" align="absmiddle"> Security Intelligence

- Domain intelligence and risk context.
- Historical risk analysis.
- Baseline tracking by profile and hour.
- Anomaly detection against observed activity.
- Incident metrics and mean-time-to-resolve tracking.
- Search across Sentinel's stored security data.
- Security-focused event metadata for investigation.

### <img src="./assets/icons/dashboard.svg" alt="" width="20" height="20" align="absmiddle"> Dashboard & Control Center

The dashboard provides a single local control surface for:

- Profile management.
- Monitoring start/stop.
- Telegram configuration and testing.
- Recent alerts.
- Alert severity and risk.
- Profile health.
- Device activity.
- Security incidents.
- Investigation details.
- Domain intelligence.
- Search Everything.
- Audit and delivery history.
- Bulk operation history.
- Control Center.
- Alert Rules.
- Maintenance / Suppression.
- Safe Mode.
- Diagnostics.
- Incident metrics.
- Rate-limit telemetry.
- Database retention.
- Configuration diff.
- Settings export/import.
- Database backup/restore.

The dashboard refreshes operational data automatically and also provides explicit refresh controls.

### <img src="./assets/icons/config.svg" alt="" width="20" height="20" align="absmiddle"> Configuration & API Controls

Sentinel can work with NextDNS profile configuration through API-backed controls, including scoped areas such as:

- Profile configuration.
- Security settings.
- Privacy settings.
- Parental-control configuration.
- Profile settings.

Configuration changes are recorded with before/after state where supported, and Sentinel can safely undo a recorded change only when the live configuration still matches the expected post-change state.

### <img src="./assets/icons/security.svg" alt="" width="20" height="20" align="absmiddle"> Security & Reliability

- Fernet encryption for locally stored API keys and Telegram secrets.
- Automatic local secret generation.
- Environment-variable secret override.
- Localhost-first dashboard binding.
- Optional API authentication.
- Safe Mode to block protected configuration mutations.
- SQLite integrity validation before restore.
- Pre-restore database rollback copy.
- Database retention and maintenance.
- API retry/backoff handling.
- NextDNS rate-limit telemetry.
- Sentinel health heartbeat and diagnostics.
- Graceful monitoring shutdown.

---

## <img src="./assets/icons/process.svg" alt="" width="24" height="24" align="absmiddle"> Detection & Response Flow

```text
                 NextDNS DNS Logs
                         |
                         v
                 Event Extraction
                         |
                         v
                 Denylist Matching
                         |
                         v
                 Event Fingerprint
                         |
               +---------+---------+
               |                   |
          Duplicate            New Event
               |                   |
             Ignore                 v
                             Risk / Severity
                                   |
                              Correlation
                                   |
                         +---------+---------+
                         |                   |
                      Suppress            Alert
                         |                   |
                         |             +-----+-----+
                         |             |           |
                         |          Dashboard   Telegram
                         |             |
                         |          Incident
                         |             |
                         +------- Audit / History
```

Rules, maintenance windows, and suppressions can affect notification behavior without deleting the underlying security event from local history.

---

## <img src="./assets/icons/requirements.svg" alt="" width="24" height="24" align="absmiddle"> Requirements

| Requirement | Purpose |
|---|---|
| Python **3.10+** | Runtime |
| NextDNS API access | Profiles, configuration, denylists, and logs |
| Telegram Bot + Chat ID | Optional alert delivery |
| `cryptography` | Fernet encryption |
| SQLite | Included with Python |

---

## <img src="./assets/icons/install.svg" alt="" width="24" height="24" align="absmiddle"> Installation

### 1. Clone the repository

```bash
git clone https://github.com/eldqyqy2007/nextdns-sentinel.git
cd nextdns-sentinel
```

### 2. Create a virtual environment

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## <img src="./assets/icons/usage.svg" alt="" width="24" height="24" align="absmiddle"> Quick Start

Start Sentinel:

```bash
python nextdns_sentinel.py
```

Then open:

```text
http://127.0.0.1:5000
```

On first launch:

1. Open the local dashboard.
2. Add a NextDNS profile.
3. Enter the NextDNS Account API key.
4. Select the profile discovered from the API.
5. Configure Telegram if notifications are required.
6. Start monitoring.
7. Use the Control Center for rules, maintenance, suppression, diagnostics, and operational controls.

Sentinel can automatically start monitoring configured active profiles when the dashboard starts.

---

## <img src="./assets/icons/config.svg" alt="" width="24" height="24" align="absmiddle"> Configuration

### Local encryption key

Sentinel no longer requires manual creation of a Fernet key for the normal setup.

If `NEXTDNS_SENTINEL_SECRET_KEY` is not provided, Sentinel automatically generates a Fernet key and stores it locally:

```text
data/.sentinel_secret
```

The key is reused across launches so encrypted credentials remain readable.

You can override the secret-file location with:

```text
NEXTDNS_SENTINEL_SECRET_FILE
```

> **Important:** losing the Fernet key makes the locally encrypted credentials unrecoverable.

### Environment variables

| Variable | Default | Purpose |
|---|---:|---|
| `NEXTDNS_SENTINEL_SECRET_KEY` | Auto-generated if absent | Fernet key for encrypted credentials |
| `NEXTDNS_SENTINEL_SECRET_FILE` | `data/.sentinel_secret` | Secret-file location |
| `NEXTDNS_SENTINEL_DB` | `data/sentinel.db` | SQLite database path |
| `NEXTDNS_SENTINEL_CONFIG` | `config.json` | Configuration path |
| `NEXTDNS_SENTINEL_INTERVAL` | `15` | Poll interval in seconds |
| `NEXTDNS_SENTINEL_INITIAL_LOOKBACK` | `60` | Initial log lookback |
| `NEXTDNS_SENTINEL_POLL_OVERLAP_MS` | `5000` | Poll overlap |
| `NEXTDNS_SENTINEL_ALERT_COOLDOWN` | `300` | Alert cooldown |
| `NEXTDNS_SENTINEL_API_RETRIES` | `3` | API retry attempts |
| `NEXTDNS_SENTINEL_NOTIFICATION_RETRY_BASE` | `30` | Initial notification retry delay |
| `NEXTDNS_SENTINEL_NOTIFICATION_RETRY_MAX` | `900` | Maximum notification retry delay |
| `NEXTDNS_SENTINEL_MAX_NOTIFICATION_ATTEMPTS` | `10` | Maximum notification attempts |
| `NEXTDNS_SENTINEL_ALERT_RETENTION_DAYS` | `90` | Alert retention period |
| `NEXTDNS_SENTINEL_HTTP_TIMEOUT` | `10` | HTTP timeout |
| `NEXTDNS_SENTINEL_HOST` | `127.0.0.1` | Dashboard bind address |
| `NEXTDNS_SENTINEL_PORT` | `5000` | Dashboard port |
| `NEXTDNS_SENTINEL_LOG_LEVEL` | `INFO` | Logging level |

---

## <img src="./assets/icons/dashboard.svg" alt="" width="24" height="24" align="absmiddle"> Dashboard

The Sentinel dashboard is organized around operational visibility rather than a single alert table.

### Core monitoring

- Alert Activity
- Top Domains
- Profile Health
- Device Activity
- Event Timeline
- Recent Alerts

### Security Operations

- Risk & Incident Overview
- Security Incidents
- Investigation Timeline
- Domain Intelligence
- Search Everything
- Audit Center
- Telegram Delivery Center
- Bulk Operations History

### Control Center

The Control Center groups operational actions in one place:

- Alert Rules
- Maintenance Mode
- Alert Suppression
- Safe Mode
- Diagnostics
- Incident Metrics
- Rate-Limit History
- Database Retention
- Configuration Diff
- Risk / Baseline views
- Settings Export / Import
- API Authentication controls

This keeps advanced controls available without requiring manual database edits or separate configuration files.

---

## <img src="./assets/icons/security.svg" alt="" width="24" height="24" align="absmiddle"> Alert & Intelligence Engine

### Severity & Risk

Alerts are enriched with security metadata so operators can distinguish ordinary events from higher-risk activity.

### Correlation

Related alerts can be grouped into incidents instead of treating every event as an isolated notification.

### Smart Suppression

Suppression can be applied through:

- Alert fingerprints.
- Cooldown periods.
- Maintenance windows.
- Alert rules.

Suppression affects notification behavior while preserving the underlying event history.

### Rules

Rules can match event context such as profile, domain, device, and alert type and can be used for actions such as suppression or escalation.

### Baseline & Anomaly Detection

Sentinel maintains historical activity baselines and compares observed activity against those patterns to provide anomaly context.

---

## <img src="./assets/icons/project.svg" alt="" width="24" height="24" align="absmiddle"> Device & Domain Intelligence

### Device activity

DNS events can update device state with information available from NextDNS, including:

- Device ID
- Device name
- Device model
- Client IP
- Last activity
- Last observed domain
- Activity status

Sentinel can also generate an inactivity alert when a monitored device stops producing recent DNS activity.

> An inactivity event means **no recent DNS activity was observed**. It does not prove that DNS was explicitly disabled on the device.

### Domain intelligence

Domain-related alert context can include:

- Domain reputation/risk metadata stored by Sentinel.
- Alert frequency.
- Correlation context.
- Historical activity.
- Anomaly information.

---

## <img src="./assets/icons/config.svg" alt="" width="24" height="24" align="absmiddle"> Configuration Management

Sentinel tracks configuration changes so operators can understand what changed and when.

### Configuration history

Changes can include:

- Before state.
- After state.
- Change type.
- Timestamp.
- Undo state.

### Configuration Diff

The dashboard can display field-level differences between recorded configuration states.

### Safe Undo

Undo is intentionally guarded:

1. Sentinel records the original and expected new state.
2. When undo is requested, Sentinel checks the live profile.
3. If the profile still matches the recorded post-change state, Sentinel applies only the changed fields.
4. If the configuration changed again, the undo is refused instead of overwriting newer changes.

This prevents an old undo action from silently reverting newer administrator changes.

---

## <img src="./assets/icons/storage.svg" alt="" width="24" height="24" align="absmiddle"> Operations & Recovery

### Health & Diagnostics

Sentinel maintains a local heartbeat and exposes health information covering operational components such as:

- Database availability.
- Required schema.
- Alert storage.
- Monitor heartbeat.
- Operational state.

### Rate-limit intelligence

When NextDNS returns HTTP 429 responses, Sentinel records rate-limit telemetry including endpoint and retry information when available.

### Database maintenance

The Control Center can remove data older than a selected retention period and perform SQLite maintenance.

### Backup & Restore

Sentinel provides SQLite backup and restore through the dashboard.

Before restoring:

- The uploaded database is validated with SQLite integrity checks.
- A rollback copy of the current database is created.
- The monitor is stopped during replacement when necessary.
- The restored database is reopened through Sentinel.

### Settings Export / Import

Operational settings and alert rules can be exported to JSON.

Secrets such as API keys and tokens are intentionally excluded from the settings export.

---

## <img src="./assets/icons/security.svg" alt="" width="24" height="24" align="absmiddle"> Security Model

- Use Sentinel only with NextDNS profiles you own or administer.
- NextDNS API keys are encrypted locally using Fernet.
- Telegram credentials are encrypted locally.
- The Fernet key is stored separately from encrypted credential values.
- The local secret file and database should never be committed to Git.
- SQLite itself is **not** fully encrypted; Fernet protects supported credential fields.
- The dashboard binds to localhost by default.
- Sentinel supports optional API authentication for protected API access.
- Safe Mode can block protected configuration mutations.
- Destructive operations in the dashboard use confirmation prompts where appropriate.
- Database restore performs integrity validation and creates a rollback copy.
- Do not expose Sentinel directly to the public internet without adding appropriate network-level protections.

---

## <img src="./assets/icons/project.svg" alt="" width="24" height="24" align="absmiddle"> Data & Storage

Default local data:

```text
data/
├── sentinel.db
└── .sentinel_secret
```

SQLite contains Sentinel's local operational state, including areas such as:

- Profiles and encrypted credentials.
- Alert history.
- Alert metadata.
- Incidents and incident relationships.
- Device state.
- Domain intelligence.
- Baseline/anomaly data.
- Audit history.
- Delivery history.
- Bulk operation history.
- Configuration snapshots and changes.
- Sentinel health.
- Suppression and maintenance state.
- Rate-limit telemetry.
- Retention records.

---

## <img src="./assets/icons/usage.svg" alt="" width="24" height="24" align="absmiddle"> CLI Usage

### Standard mode

```bash
python nextdns_sentinel.py
```

Starts the normal local dashboard and monitoring workflow.

### Monitor only

```bash
python nextdns_sentinel.py --monitor
```

Runs monitoring without starting the dashboard.

### Dashboard mode

```bash
python nextdns_sentinel.py --dashboard
```

Starts the dashboard explicitly.

### Custom host / port

```bash
python nextdns_sentinel.py --dashboard --host 127.0.0.1 --port 5000
```

For non-localhost binding, apply appropriate network controls and authentication before exposing the service beyond the local machine.

---

## <img src="./assets/icons/project.svg" alt="" width="24" height="24" align="absmiddle"> Project Structure

The application logic is intentionally consolidated into the main Python file.

```text
nextdns-sentinel/
├── assets/
│   ├── banner/
│   └── icons/
├── config.example.json
├── nextdns_sentinel.py
├── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

> **Single-file application design:** Sentinel's monitoring, intelligence, incident, audit, dashboard, configuration, recovery, and operational logic lives in `nextdns_sentinel.py`.

---

## <img src="./assets/icons/limits.svg" alt="" width="24" height="24" align="absmiddle"> Limitations

- NextDNS's API is subject to provider-side availability, behavior, and API changes.
- NextDNS API behavior may change because the API is subject to Beta/API evolution.
- Monitoring is polling-based rather than a provider-side streaming connection.
- Very high-volume profiles may require a shorter polling interval.
- Inactivity detection means Sentinel observed no recent DNS activity; it cannot by itself prove the device explicitly disabled DNS or switched to another resolver.
- NextDNS API data does not provide Sentinel with a reliable human actor identity for every external configuration change.
- Telegram delivery is optional and best-effort; monitoring continues if notification delivery fails.
- SQLite is local persistence and is not a distributed database.
- Losing the Fernet key makes encrypted stored credentials unrecoverable.
- No real NextDNS account is bundled with the project, so live provider behavior must be tested with credentials you control.

---

## <img src="./assets/icons/contributing.svg" alt="" width="24" height="24" align="absmiddle"> Contributing

Issues and pull requests are welcome.

Before contributing:

- Do not commit NextDNS API keys.
- Do not commit Telegram bot tokens or private chat IDs.
- Do not upload private DNS logs.
- Do not include real credentials in screenshots, tests, or examples.
- Keep changes focused and document security-sensitive behavior.

---

## <img src="./assets/icons/license.svg" alt="" width="24" height="24" align="absmiddle"> License

This project is licensed under the [MIT License](LICENSE).
