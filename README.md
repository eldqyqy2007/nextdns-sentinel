<p align="center">
  <img src="./assets/a_wide_cinematic_cyber_tech_themed_banner_hero_i.png" alt="NextDNS Sentinel banner" width="100%">
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?labelColor=555" alt="license: MIT"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-yellow?labelColor=555&logo=python&logoColor=white" alt="python: 3.10+">
  <img src="https://img.shields.io/badge/storage-SQLite-003B57?labelColor=555&logo=sqlite&logoColor=white" alt="storage: SQLite">
  <img src="https://img.shields.io/badge/interface-CLI%20%2B%20Web-6f42c1?labelColor=555" alt="CLI and Web">
  <img src="https://img.shields.io/badge/alerts-Telegram-26A5E4?labelColor=555" alt="Telegram alerts">
  <img src="https://img.shields.io/github/actions/workflow/status/eldqyqy2007/nextdns-sentinel/tests.yml?label=tests" alt="tests">
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
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## <img src="./assets/icons/monitor.svg" alt="" width="24" height="24" align="absmiddle"> Why this tool

Sentinel is built for defensive visibility over NextDNS configurations you are authorized to manage. It is intentionally local-first: NextDNS is the data source, SQLite is the local persistence layer, Telegram is optional alert transport, and the dashboard is a local view.

## <img src="./assets/icons/features.svg" alt="" width="24" height="24" align="absmiddle"> Features

- **Multi-profile monitoring** with independent worker threads.
- **Denylist matching** for exact domains, parent domains, and wildcard-style entries.
- **Overlap-aware polling** with persistent last-poll state to reduce missed events between cycles.
- **Duplicate protection** using deterministic event fingerprints.
- **Alert cooldown** to reduce repeated Telegram notifications for the same profile/domain.
- **Richer event context** including status, reasons, matched domain, and client IP when supplied by NextDNS.
- **Local SQLite storage** with application-layer Fernet encryption for stored API keys.
- **Resilient API client** with retry/backoff handling for network errors, rate limits, and server errors.
- **Local dashboard** with statistics, recent alerts, and monitor health.
- **Environment-based secrets** and localhost-first dashboard binding.
- **Graceful shutdown** for monitor workers.
- **Automated tests** and GitHub Actions CI.

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

Copy the example:
```bash
cp config.example.json config.json
```

Generate a Fernet key:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Set the generated value as `NEXTDNS_SENTINEL_SECRET_KEY`. Then configure the environment variables referenced by `config.json`:

```bash
export NEXTDNS_SENTINEL_SECRET_KEY="your-fernet-key"
export NEXTDNS_PROFILE_1_API_KEY="your-nextdns-api-key"
export TELEGRAM_BOT_TOKEN="your-telegram-bot-token"
export TELEGRAM_CHAT_ID="your-telegram-chat-id"
```

Keep the Fernet key outside Git and back it up securely. Losing it means stored API keys cannot be decrypted.

### Configuration reference

| Variable | Default | Purpose |
|---|---:|---|
| `NEXTDNS_SENTINEL_SECRET_KEY` | — | Fernet key for stored API keys |
| `NEXTDNS_SENTINEL_DB` | `data/sentinel.db` | SQLite path |
| `NEXTDNS_SENTINEL_CONFIG` | `config.json` | Config path |
| `NEXTDNS_SENTINEL_INTERVAL` | `15` | Poll interval in seconds |
| `NEXTDNS_SENTINEL_INITIAL_LOOKBACK` | `60` | First poll lookback |
| `NEXTDNS_SENTINEL_POLL_OVERLAP_MS` | `5000` | Poll overlap |
| `NEXTDNS_SENTINEL_ALERT_COOLDOWN` | `300` | Telegram cooldown per profile/domain |
| `NEXTDNS_SENTINEL_API_RETRIES` | `3` | API retry attempts |
| `NEXTDNS_SENTINEL_HTTP_TIMEOUT` | `10` | HTTP timeout |
| `NEXTDNS_SENTINEL_HOST` | `127.0.0.1` | Dashboard bind address |
| `NEXTDNS_SENTINEL_PORT` | `5000` | Dashboard port |
| `NEXTDNS_SENTINEL_LOG_LEVEL` | `INFO` | Log level |

## <img src="./assets/icons/usage.svg" alt="" width="24" height="24" align="absmiddle"> Usage

Monitor:
```bash
python nextdns_sentinel.py --monitor
```

Dashboard:
```bash
python nextdns_sentinel.py --dashboard
```

Default dashboard: `http://127.0.0.1:5000`.

If you intentionally bind to a non-localhost address, add network controls/authentication outside this lightweight dashboard. The application itself does not provide dashboard authentication.

## <img src="./assets/icons/dashboard.svg" alt="" width="24" height="24" align="absmiddle"> Web dashboard

The dashboard shows account counts, denylist size, alert count, monitor health, last successful poll/error, and recent events including matched domain, status, reason, and client IP when available.

It uses DOM-safe rendering for event data rather than inserting API values as raw HTML.

## <img src="./assets/icons/storage.svg" alt="" width="24" height="24" align="absmiddle"> Data and storage

```text
data/
└── sentinel.db
```

SQLite stores profile metadata, encrypted API keys, denylist snapshots, alert history, event fingerprints, and monitor state. Existing databases are migrated for the added event fields/state table.

## <img src="./assets/icons/security.svg" alt="" width="24" height="24" align="absmiddle"> Security model

- Monitor only profiles you own or administer.
- API keys enter through environment variables and are encrypted before local storage.
- Telegram credentials remain environment-based.
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
- The logs endpoint currently requests up to 100 records per cycle; very high-volume profiles may require a shorter interval or future pagination/cursor support.
- SQLite is local persistence, not a distributed database.
- Telegram is best-effort; monitoring continues if notification delivery fails.
- Losing the Fernet key makes stored API keys unrecoverable.
- The dashboard is lightweight and intentionally does not implement user authentication.

## <img src="./assets/icons/process.svg" alt="" width="24" height="24" align="absmiddle"> Roadmap

- [x] Resilient API polling and duplicate protection
- [x] Event context and local monitor health
- [x] Dashboard-safe rendering
- [ ] Pagination/cursor support for very high-volume logs
- [ ] Optional authenticated dashboard
- [ ] Alert aggregation and richer dashboard analytics

## <img src="./assets/icons/contributing.svg" alt="" width="24" height="24" align="absmiddle"> Contributing

Issues and pull requests are welcome. Never include API keys, Telegram bot tokens, private chat IDs, private DNS logs, or sensitive profile information in issues or commits.

## <img src="./assets/icons/license.svg" alt="" width="24" height="24" align="absmiddle"> License

This project is licensed under the [MIT License](LICENSE).
