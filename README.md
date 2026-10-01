<p align="center">
  <img src="./assets/a_wide_cinematic_cyber_tech_themed_banner_hero_i.png" alt="NextDNS Sentinel banner" width="100%">
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?labelColor=555" alt="license: MIT"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-yellow?labelColor=555&logo=python&logoColor=white" alt="python: 3.10+">
  <img src="https://img.shields.io/badge/storage-SQLite-003B57?labelColor=555&logo=sqlite&logoColor=white" alt="storage: SQLite">
  <img src="https://img.shields.io/badge/interface-Web%20Dashboard-6f42c1?labelColor=555" alt="Web dashboard">
  <img src="https://img.shields.io/badge/alerts-Telegram-26A5E4?labelColor=555" alt="Telegram alerts">
</p>

# <img src="./assets/icons/sentinel.svg" alt="" width="32" height="32" align="absmiddle"> NextDNS Sentinel

A local-first monitoring utility for **NextDNS profiles you own or administer**. It polls DNS logs, matches observed domains against each profile's custom denylist, stores matched events locally in SQLite, and can send Telegram alerts without requiring a hosted backend.

> **Design principle:** operational data stays local, secrets stay outside Git, and the dashboard stays local by default.

## <img src="./assets/icons/overview.svg" alt="" width="24" height="24" align="absmiddle"> Table of contents

- [Why this tool](#why-this-tool)
- [Features](#features)
- [Architecture](#architecture)
- [Detection flow](#detection-flow)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Web dashboard](#web-dashboard)
- [Data and storage](#data-and-storage)
- [Security model](#security-model)
- [Project structure](#project-structure)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [License](#license)

---

## <img src="./assets/icons/monitor.svg" alt="" width="24" height="24" align="absmiddle"> Why this tool

Sentinel is built for defensive visibility over NextDNS configurations you are authorized to manage. It is intentionally local-first: NextDNS is the data source, SQLite is the local persistence layer, Telegram is optional alert transport, and the dashboard is a local view.

## <img src="./assets/icons/features.svg" alt="" width="24" height="24" align="absmiddle"> Features

- **Multi-profile monitoring** with independent worker threads.
- **Denylist matching** for exact domains, parent domains, and wildcard-style entries.
- **Overlap-aware polling** with a persistent checkpoint based on the completed API polling window to reduce missed events between cycles.
- **Duplicate protection** using deterministic event fingerprints.
- **Alert cooldown** to reduce repeated Telegram notifications for the same profile/domain.
- **Richer event context** including status, reasons, matched domain, and client IP when supplied by NextDNS.
- **Local SQLite storage** with application-layer Fernet encryption for stored API keys.
- **Resilient API client** with retry/backoff handling for network errors, rate limits, and server errors.
- **Local control dashboard** with first-run setup, profile management, monitor controls, statistics, recent alerts, and health status.
- **Web-based profile management** for adding, updating, enabling, disabling, and deleting monitored NextDNS profiles.
- **Web-based Telegram setup** with credential validation, encrypted local storage, test notifications, and disable controls.
- **Automatic local secret generation** when no Fernet key is supplied, with persistent reuse across launches.
- **Environment-variable overrides** remain available for advanced deployments and automation.
- **Localhost-first dashboard binding** with graceful monitor-worker shutdown.

## <img src="./assets/icons/process.svg" alt="" width="24" height="24" align="absmiddle"> Architecture

```text
                         NextDNS API
                             |
              +--------------+--------------+
              |              |
           Denylist         Logs
              |              |
              +--------------+--------------+
                             |
                             v
                  +----------------------+
                  |   NextDNS Sentinel   |
                  |  Monitor + Matcher   |
                  +----------+-----------+
                             |
              +--------------+--------------+
              |                             |
              v                             v
       Local SQLite DB                 Telegram API
              |                             |
              v                             v
       Local Web Dashboard             Alerts
```

## <img src="./assets/icons/process.svg" alt="" width="24" height="24" align="absmiddle"> Detection flow

```text
NextDNS Logs
     |
     v
Domain Extraction
     |
     v
Custom Denylist
     |
     v
Domain Matching
     |
     v
Event Fingerprint
   /       \
Duplicate   New Event
   |           |
 Ignore     SQLite
               |
          +----+----+
          |         |
       Telegram   Dashboard
```

## <img src="./assets/icons/requirements.svg" alt="" width="24" height="24" align="absmiddle"> Requirements

| Requirement | Purpose |
|---|---|
| Python 3.10+ | Runtime |
| NextDNS API access | Profile, denylist, and log monitoring |
| Telegram bot + chat ID | Optional alerts |
| `cryptography` | Fernet API-key encryption |
| SQLite | Included with Python |

## <img src="./assets/icons/install.svg" alt="" width="24" height="24" align="absmiddle"> Installation

```bash
git clone https://github.com/eldqyqy2007/nextdns-sentinel.git
cd nextdns-sentinel
python -m venv .venv
```

Linux/macOS:
```bash
source .venv/bin/activate
```

Windows PowerShell:
```powershell
.venv\\Scripts\\Activate.ps1
```

Install dependencies:
```bash
pip install -r requirements.txt
```

## <img src="./assets/icons/config.svg" alt="" width="24" height="24" align="absmiddle"> Configuration

The normal setup no longer requires manually creating or exporting a Fernet key.

Start the application:
```bash
python nextdns_sentinel.py
```

On first launch, the local dashboard lets you add a NextDNS profile and API key. If `NEXTDNS_SENTINEL_SECRET_KEY` is not already set, Sentinel automatically generates a Fernet key and stores it locally in:

```text
data/.sentinel_secret
```

The generated key is reused on later launches so previously encrypted credentials remain readable. You can override the key-file location with `NEXTDNS_SENTINEL_SECRET_FILE`.

For advanced or automated deployments, environment variables can still be used. The environment-provided Fernet key takes precedence over the local key file.

Keep the secret key outside Git and back it up securely. Losing the key makes stored encrypted credentials unrecoverable.

### Configuration reference

| Variable | Default | Purpose |
|---|---:|---|
| `NEXTDNS_SENTINEL_SECRET_KEY` | auto-generated if absent | Fernet key for encrypted local credentials; environment value takes precedence |
| `NEXTDNS_SENTINEL_SECRET_FILE` | `data/.sentinel_secret` | Local Fernet key file when no environment key is supplied |
| `NEXTDNS_SENTINEL_DB` | `data/sentinel.db` | SQLite path |
| `NEXTDNS_SENTINEL_CONFIG` | `config.json` | Config path |
| `NEXTDNS_SENTINEL_INTERVAL` | `15` | Poll interval in seconds |
| `NEXTDNS_SENTINEL_INITIAL_LOOKBACK` | `60` | First poll lookback |
| `NEXTDNS_SENTINEL_POLL_OVERLAP_MS` | `5000` | Poll overlap |
| `NEXTDNS_SENTINEL_ALERT_COOLDOWN` | `300` | Telegram cooldown per profile/domain |
| `NEXTDNS_SENTINEL_API_RETRIES` | `3` | API retry attempts |
| `NEXTDNS_SENTINEL_NOTIFICATION_RETRY_BASE` | `30` | Initial notification retry delay in seconds |
| `NEXTDNS_SENTINEL_NOTIFICATION_RETRY_MAX` | `900` | Maximum notification retry delay in seconds |
| `NEXTDNS_SENTINEL_MAX_NOTIFICATION_ATTEMPTS` | `10` | Maximum notification attempts per alert |
| `NEXTDNS_SENTINEL_ALERT_RETENTION_DAYS` | `90` | Retention period for completed alerts |
| `NEXTDNS_SENTINEL_HTTP_TIMEOUT` | `10` | HTTP timeout |
| `NEXTDNS_SENTINEL_HOST` | `127.0.0.1` | Dashboard bind address |
| `NEXTDNS_SENTINEL_PORT` | `5000` | Dashboard port |
| `NEXTDNS_SENTINEL_LOG_LEVEL` | `INFO` | Log level |
| `NEXTDNS_SENTINEL_HOST` | `127.0.0.1` | Dashboard bind address |
| `NEXTDNS_SENTINEL_PORT` | `5000` | Dashboard port |

## <img src="./assets/icons/usage.svg" alt="" width="24" height="24" align="absmiddle"> Usage

### Recommended: one-command workflow

Start Sentinel with:

```bash
python nextdns_sentinel.py
```

The application starts the local dashboard at:

```text
http://127.0.0.1:5000
```

From the dashboard you can:

1. Add a NextDNS profile and API key.
2. Start or stop monitoring.
3. Enable, disable, update, or delete profiles.
4. Configure Telegram alerts and send a test notification.
5. View cached denylist entries, statistics, monitor health, and recent alerts.

If profiles are already configured and active, Sentinel automatically starts monitoring when the dashboard launches.

### Advanced CLI modes

Start monitoring without the dashboard:

```bash
python nextdns_sentinel.py --monitor
```

Start the dashboard explicitly:

```bash
python nextdns_sentinel.py --dashboard
```

Custom dashboard host/port:

```bash
python nextdns_sentinel.py --dashboard --host 127.0.0.1 --port 5000
```

If you intentionally bind to a non-localhost address, add network controls/authentication outside this lightweight dashboard. The application itself does not provide dashboard authentication.

## <img src="./assets/icons/dashboard.svg" alt="" width="24" height="24" align="absmiddle"> Web dashboard

The dashboard is the primary control surface for Sentinel. It provides:

- First-run NextDNS profile setup.
- Profile management: add/update, enable/disable, and delete.
- Start/stop controls for the monitoring workers.
- Telegram configuration, validation, test notifications, and disable controls.
- Cached denylist viewing per profile.
- Account counts, denylist size, alert count, monitor health, last successful poll, and latest monitor error.
- Recent detection events with event time, matched domain, status, reason, notification state, retry attempts, and client IP when available.

Event data is rendered through safe DOM operations rather than inserted as raw HTML.

## <img src="./assets/icons/storage.svg" alt="" width="24" height="24" align="absmiddle"> Data and storage

```text
data/
├── sentinel.db
└── .sentinel_secret
```

SQLite stores profile metadata, encrypted API keys, denylist snapshots, alert history, event fingerprints, and monitor state. Existing databases are migrated for the added event fields/state table.

## <img src="./assets/icons/security.svg" alt="" width="24" height="24" align="absmiddle"> Security model

- Monitor only profiles you own or administer.
- API keys can be entered through the local dashboard and are encrypted before local storage.
- Telegram credentials can be configured through the local dashboard and are encrypted before local storage.
- A Fernet key is generated automatically when one is not supplied through the environment and is stored in the local secret file.
- Do not commit `config.json`, databases, logs, secrets, or private DNS data.
- The Fernet key protects stored API-key values; it does **not** encrypt the whole SQLite database.
- The dashboard defaults to localhost and has no authentication layer.
- Non-localhost binding produces a warning.

## <img src="./assets/icons/project.svg" alt="" width="24" height="24" align="absmiddle"> Project structure

```text
nextdns-sentinel/
├── assets/
│   ├── banner...
│   └── icons/
├── config.example.json
├── nextdns_sentinel.py
├── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

## <img src="./assets/icons/limits.svg" alt="" width="24" height="24" align="absmiddle"> Limitations

- NextDNS API availability and response format can change.
- Polling is not a provider-side streaming connection.
- Log polling uses the provider's paginated API with up to 1000 records per request and follows cursors when additional pages exist. Very high-volume profiles may still require a shorter interval.
- SQLite is local persistence, not a distributed database.
- Telegram is best-effort; monitoring continues if notification delivery fails.
- Losing the Fernet key makes stored encrypted credentials unrecoverable.
- The dashboard is lightweight and intentionally does not implement user authentication.

## <img src="./assets/icons/contributing.svg" alt="" width="24" height="24" align="absmiddle"> Contributing

Issues and pull requests are welcome. Never include API keys, Telegram bot tokens, private chat IDs, private DNS logs, or sensitive profile information in issues or commits.

## <img src="./assets/icons/license.svg" alt="" width="24" height="24" align="absmiddle"> License

This project is licensed under the [MIT License](LICENSE).
