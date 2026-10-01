# <img src="./assets/icons/sentinel.svg" alt="" width="32" height="32" align="absmiddle"> NextDNS Sentinel

<p align="center">
  <img src="./assets/a_wide_cinematic_cyber_tech_themed_banner_hero_i.png" alt="NextDNS Sentinel banner" width="100%">
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?labelColor=555" alt="license: MIT"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-yellow?labelColor=555&logo=python&logoColor=white" alt="python: 3.10+">
  <img src="https://img.shields.io/badge/storage-SQLite-003B57?labelColor=555&logo=sqlite&logoColor=white" alt="storage: SQLite">
  <img src="https://img.shields.io/badge/interface-CLI%20%2B%20Web-6f42c1?labelColor=555" alt="CLI and Web">
  <img src="https://img.shields.io/badge/alerts-Telegram-26A5E4?labelColor=555" alt="Telegram alerts">
</p>

**NextDNS Sentinel** is a local-first monitoring utility for **NextDNS profiles you own or administer**. It continuously polls NextDNS DNS logs, compares observed domains against each profile's custom denylist, records matches in a local SQLite database, and can send Telegram notifications when a new match is detected.

It is designed to work as a **single-file application**: the main monitoring, storage, API client, alerting, and dashboard logic lives in `nextdns_sentinel.py`. No hosted backend is required.

> **Design principle:** keep operational data local, keep secrets outside Git, and expose the dashboard locally by default.

## <img src="./assets/icons/overview.svg" alt="" width="24" height="24" align="absmiddle"> Table of contents

- [What it does](#what-it-does)
- [How it works](#how-it-works)
- [Features](#features)
- [Architecture](#architecture)
- [Detection flow](#detection-flow)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Configuration reference](#configuration-reference)
- [Running the tool](#running-the-tool)
- [Web dashboard](#web-dashboard)
- [Alerts](#alerts)
- [Database and persistence](#database-and-persistence)
- [Reliability and error handling](#reliability-and-error-handling)
- [Security](#security)
- [Project structure](#project-structure)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## <img src="./assets/icons/monitor.svg" alt="" width="24" height="24" align="absmiddle"> What it does

Sentinel connects to the NextDNS API for every configured profile and performs four main jobs:

1. **Loads the profile's custom denylist.**
2. **Polls recent DNS logs** at a configurable interval.
3. **Detects domains that match the denylist**, including exact, parent-domain, and wildcard-style matches.
4. **Stores and optionally alerts on matches**, while preventing duplicate database records and reducing repeated Telegram notifications.

The application also provides a small local web dashboard for viewing current statistics, monitor health, and recent alerts.

### Typical use case

If a domain such as `example.com` is present in a profile's denylist and a monitored DNS log contains `sub.example.com`, Sentinel can recognize the parent-domain relationship, store the event, and send a Telegram alert.

---

## <img src="./assets/icons/process.svg" alt="" width="24" height="24" align="absmiddle"> How it works

For each active account, Sentinel runs an independent monitoring worker:

```text
                    NextDNS API
                        |
          +-------------+-------------+
          |             |             |
       Profile       Denylist        Logs
          |             |             |
          +-------------+-------------+
                        |
                        v
              NextDNS Sentinel Worker
                        |
               Normalize the domain
                        |
                        v
                 Denylist matching
                        |
              +---------+---------+
              |                   |
           No match            Match
              |                   |
            Ignore          Create event key
                                  |
                           +------+------+
                           |             |
                       Duplicate      New event
                           |             |
                         Ignore       SQLite
                                         |
                                  +------+------+
                                  |             |
                               Telegram      Dashboard
```

The monitor keeps the last polling timestamp in SQLite. On the next cycle it queries from slightly before that timestamp using an overlap window. This helps reduce the chance of missing events that arrive around polling boundaries.

---

## <img src="./assets/icons/features.svg" alt="" width="24" height="24" align="absmiddle"> Features

### Multi-profile monitoring

The configuration can contain multiple NextDNS profiles. Active profiles are loaded from the local database and monitored independently in separate daemon threads.

Each profile has its own:

- Profile ID
- Account name
- Optional profile name
- API key
- Active/inactive state
- Denylist snapshot
- Polling state
- Alert history

### Denylist matching

Sentinel normalizes domains to lowercase and removes trailing dots before comparison.

It supports:

- **Exact match**
  - Denylist: `example.com`
  - Event: `example.com`

- **Parent-domain match**
  - Denylist: `example.com`
  - Event: `api.example.com`

- **Wildcard-style match**
  - Denylist: `*.example.com`
  - Event: `api.example.com`

This makes the matching logic useful for both direct and subdomain DNS activity.

### Persistent polling state

The monitor stores the latest polling timestamp in the `monitor_state` SQLite table.

Each cycle uses:

- `NEXTDNS_SENTINEL_INITIAL_LOOKBACK` on the first poll
- `NEXTDNS_SENTINEL_POLL_OVERLAP_MS` for subsequent polls

The overlap intentionally causes a small amount of re-reading. Deterministic event fingerprints then prevent the same event from being inserted twice.

### Duplicate protection

Every matching log is converted into a deterministic SHA-256 fingerprint based on:

- The profile ID
- The complete normalized JSON representation of the log event

The resulting value is stored as a unique `event_key` in SQLite.

If the same event is encountered again, SQLite rejects the duplicate and Sentinel continues normally.

### Alert cooldown

Duplicate database events and repeated notifications are handled separately.

Sentinel always uses the event fingerprint to decide whether an event has already been stored. In addition, it checks the configured cooldown window for the same profile/domain before sending Telegram notifications.

This means polling overlap can safely be used without generating a Telegram message every time an already-seen domain appears inside the overlap window.

### Rich event context

When available from NextDNS, Sentinel stores and displays:

- Queried domain
- Matched denylist domain
- DNS status
- Reason(s)
- Client IP
- Timestamp
- Account name

### Local SQLite storage

SQLite is used as the local persistence layer. The database contains profile metadata, encrypted API keys, denylist snapshots, alerts, unique event fingerprints, and monitor health state.

### Encrypted API-key storage

API keys are read from environment variables and encrypted with Fernet before being stored in SQLite.

The encryption key itself is supplied through `NEXTDNS_SENTINEL_SECRET_KEY` and is never written into the repository by Sentinel.

### Resilient NextDNS API client

The API client handles:

- Network failures
- HTTP 429 rate limiting
- HTTP 5xx server errors
- Other non-success HTTP responses
- Configurable retries
- Exponential backoff
- Request timeouts

For HTTP 429 responses, Sentinel also respects the `Retry-After` header when it is available.

### Telegram notifications

Telegram is optional. If a bot token and chat ID are configured, a notification can contain:

- Account
- Domain
- Matched denylist domain
- Status
- Reason
- Detection time
- Client IP when available

If Telegram delivery fails, monitoring continues.

### Local web dashboard

The built-in Flask dashboard provides:

- Account count
- Active account count
- Total alert count
- Denylist entry count
- Polling interval
- Last successful poll
- Last recorded monitor error
- Recent alert table

The dashboard refreshes automatically and uses DOM APIs with `textContent` instead of injecting event values as raw HTML.

### Graceful shutdown

When running the monitor interactively, `Ctrl+C` signals the worker threads to stop and waits briefly for them to exit cleanly.

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
                  +----------------------+
                  |   NextDNS Sentinel   |
                  |                      |
                  | API Client           |
                  | Domain Matcher       |
                  | Monitor Workers      |
                  | Alert Handler        |
                  | SQLite Store         |
                  | Flask Dashboard      |
                  +----------+-----------+
                             |
              +--------------+--------------+
              |                             |
              v                             v
       Local SQLite DB                 Telegram API
              |                             |
              v                             v
       Dashboard / History              Notifications
```

The project deliberately keeps these components inside the main Python file rather than splitting the application into multiple runtime modules.

---

## <img src="./assets/icons/requirements.svg" alt="" width="24" height="24" align="absmiddle"> Requirements

| Requirement | Purpose |
|---|---|
| Python 3.10+ | Runtime |
| NextDNS API access | Profiles, denylists, and DNS logs |
| SQLite | Local persistence; included with Python |
| Flask | Local web dashboard |
| Requests | HTTP communication with NextDNS and Telegram |
| Cryptography | Fernet encryption for stored API keys |
| Telegram bot + chat ID | Optional notifications |

The project dependencies are pinned to compatible major/minor ranges in `requirements.txt`.

---

## <img src="./assets/icons/install.svg" alt="" width="24" height="24" align="absmiddle"> Installation

Clone the repository:

```bash
git clone https://github.com/eldqyqy2007/nextdns-sentinel.git
cd nextdns-sentinel
```

Create a virtual environment:

```bash
python -m venv .venv
```

### Linux / macOS

```bash
source .venv/bin/activate
```

### Windows PowerShell

```powershell
.venv\\Scripts\\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## <img src="./assets/icons/config.svg" alt="" width="24" height="24" align="absmiddle"> Configuration

Sentinel uses a small JSON configuration file for account metadata and environment variables for secrets.

Start from the included example:

```bash
cp config.example.json config.json
```

On Windows, copy the file manually if `cp` is unavailable.

### Example configuration

```json
{
  "accounts": [
    {
      "profile_id": "YOUR_PROFILE_ID",
      "name": "Primary Profile",
      "profile_name": "My NextDNS Profile",
      "api_key_env": "NEXTDNS_PROFILE_1_API_KEY",
      "active": true
    }
  ],
  "telegram_token_env": "TELEGRAM_BOT_TOKEN",
  "telegram_chat_id_env": "TELEGRAM_CHAT_ID"
}
```

### What each account field means

| Field | Description |
|---|---|
| `profile_id` | The NextDNS profile identifier to monitor |
| `name` | Friendly name used in logs, dashboard data, and Telegram alerts |
| `profile_name` | Optional human-readable profile name |
| `api_key_env` | Name of the environment variable containing that profile's API key |
| `active` | Whether Sentinel should monitor the profile |

You can add multiple objects to the `accounts` array.

### Generate the encryption key

Run:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Set the generated value as `NEXTDNS_SENTINEL_SECRET_KEY`.

### Linux / macOS environment example

```bash
export NEXTDNS_SENTINEL_SECRET_KEY="your-fernet-key"
export NEXTDNS_PROFILE_1_API_KEY="your-nextdns-api-key"
export TELEGRAM_BOT_TOKEN="your-telegram-bot-token"
export TELEGRAM_CHAT_ID="your-telegram-chat-id"
```

### Windows PowerShell example

```powershell
$env:NEXTDNS_SENTINEL_SECRET_KEY="your-fernet-key"
$env:NEXTDNS_PROFILE_1_API_KEY="your-nextdns-api-key"
$env:TELEGRAM_BOT_TOKEN="your-telegram-bot-token"
$env:TELEGRAM_CHAT_ID="your-telegram-chat-id"
```

Keep the Fernet key, NextDNS API keys, and Telegram credentials outside Git.

> **Important:** losing the Fernet key means Sentinel cannot decrypt API keys already stored in the database.

---

## <img src="./assets/icons/config.svg" alt="" width="24" height="24" align="absmiddle"> Configuration reference

| Variable | Default | Purpose |
|---|---:|---|
| `NEXTDNS_SENTINEL_SECRET_KEY` | Required | Fernet key used for API-key encryption |
| `NEXTDNS_SENTINEL_DB` | `data/sentinel.db` | SQLite database path |
| `NEXTDNS_SENTINEL_CONFIG` | `config.json` | JSON configuration path |
| `NEXTDNS_SENTINEL_INTERVAL` | `15` | Poll interval in seconds; minimum 5 |
| `NEXTDNS_SENTINEL_INITIAL_LOOKBACK` | `60` | Initial log lookback in seconds; minimum 30 |
| `NEXTDNS_SENTINEL_POLL_OVERLAP_MS` | `5000` | Overlap added to later log queries |
| `NEXTDNS_SENTINEL_ALERT_COOLDOWN` | `300` | Notification cooldown per profile/domain |
| `NEXTDNS_SENTINEL_API_RETRIES` | `3` | Additional API retry attempts |
| `NEXTDNS_SENTINEL_HTTP_TIMEOUT` | `10` | HTTP request timeout in seconds |
| `NEXTDNS_SENTINEL_HOST` | `127.0.0.1` | Dashboard bind address |
| `NEXTDNS_SENTINEL_PORT` | `5000` | Dashboard port |
| `NEXTDNS_SENTINEL_LOG_LEVEL` | `INFO` | Python logging level |

### How the polling settings interact

For the first poll, Sentinel starts from approximately:

```text
current time - INITIAL_LOOKBACK
```

For later polls:

```text
last_poll_timestamp - POLL_OVERLAP_MS
```

The overlap helps avoid boundary misses. Duplicate protection prevents that overlap from creating duplicate alert records.

---

## <img src="./assets/icons/usage.svg" alt="" width="24" height="24" align="absmiddle"> Running the tool

### Start live monitoring

```bash
python nextdns_sentinel.py --monitor
```

Sentinel will:

1. Load active accounts from SQLite.
2. Create one monitoring worker per active profile.
3. Refresh the profile denylist periodically.
4. Query recent DNS logs.
5. Match domains against the denylist.
6. Store new matches.
7. Send Telegram alerts when configured and outside the cooldown window.
8. Record polling health and errors.
9. Continue monitoring until stopped.

Stop it with:

```text
Ctrl+C
```

### Start the dashboard

```bash
python nextdns_sentinel.py --dashboard
```

Default address:

```text
http://127.0.0.1:5000
```

### Custom dashboard address and port

```bash
python nextdns_sentinel.py --dashboard --host 127.0.0.1 --port 8080
```

If you bind to a non-localhost address, Sentinel prints a warning because the dashboard does not provide authentication.

### Show command help

```bash
python nextdns_sentinel.py --help
```

---

## <img src="./assets/icons/dashboard.svg" alt="" width="24" height="24" align="absmiddle"> Web dashboard

The dashboard is intentionally lightweight and local.

### Statistics

It exposes:

- Total configured accounts
- Active accounts
- Total stored alerts
- Total denylist entries
- Polling interval

### Monitor health

The health section reports:

- Last successful poll
- Most recent monitor error, when one exists

### Recent alerts

Each recent alert can show:

- Time
- Account
- Queried domain
- Matched denylist domain
- DNS status
- Reason

The dashboard API exposes:

```text
GET /api/stats
GET /api/alerts
```

The dashboard refreshes every five seconds.

### Dashboard security

The dashboard is bound to `127.0.0.1` by default.

If you intentionally expose it on another interface, place it behind appropriate network controls and authentication. The built-in dashboard is not intended to be an internet-facing authenticated management panel.

---

## <img src="./assets/icons/telegram.svg" alt="" width="24" height="24" align="absmiddle"> Alerts

Telegram notifications are optional.

When configured, a matching event can produce a message similar to:

```text
NextDNS Sentinel alert

Account: Primary Profile
Domain: sub.example.com
Matched: example.com
Status: blocked
Reason: Custom denylist match
Time: 2026-10-01T00:00:00+00:00
Client IP: 192.0.2.10
```

The exact fields depend on the information returned by NextDNS.

### Notification behavior

A database record is created for every new event fingerprint.

Telegram notification delivery is additionally subject to `NEXTDNS_SENTINEL_ALERT_COOLDOWN`.

If Telegram returns an error or rate limit response, Sentinel logs the failure and continues monitoring.

---

## <img src="./assets/icons/storage.svg" alt="" width="24" height="24" align="absmiddle"> Database and persistence

By default the database is:

```text
data/sentinel.db
```

### Main tables

#### `accounts`

Stores configured profile metadata and encrypted API keys.

#### `denylist`

Stores the latest locally cached denylist for each profile.

#### `alerts`

Stores detected matches, including:

- Profile ID
- Account name
- Queried domain
- Matched domain
- Reason
- Status
- Client IP
- Unique event fingerprint
- Creation time

#### `monitor_state`

Stores:

- Last polling timestamp
- Last successful poll time
- Last recorded error

### Database migration

When Sentinel starts, it checks the existing `alerts` schema and adds newly required columns when they are missing. This allows an existing local database to move forward without manually rebuilding it.

---

## <img src="./assets/icons/security.svg" alt="" width="24" height="24" align="absmiddle"> Security

Sentinel is designed for defensive monitoring of NextDNS profiles you are authorized to manage.

### Secrets

Secrets are supplied through environment variables rather than being hard-coded into the repository.

The main secret-handling flow is:

```text
Environment variable
        |
        v
   Python process
        |
        v
   Fernet encryption
        |
        v
    SQLite storage
```

The Fernet key itself stays outside the database and repository.

### Local-first design

Operational data is stored locally. Sentinel does not require a hosted application server or external database.

The external services used by the application are:

- NextDNS API for profile, denylist, and DNS-log data
- Telegram API only when alerts are configured

### Repository hygiene

Do not commit:

- `config.json`
- API keys
- Telegram bot tokens
- Telegram chat IDs
- SQLite databases
- Logs
- Private DNS data
- Fernet keys

The repository's `.gitignore` already excludes the main local secret/data files.

### Dashboard exposure

The dashboard has no authentication layer. Keep it on localhost unless you have deliberately added external access controls.

---

## <img src="./assets/icons/project.svg" alt="" width="24" height="24" align="absmiddle"> Project structure

The application intentionally keeps the runtime implementation in one main Python file.

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

### Main files

| File | Purpose |
|---|---|
| `nextdns_sentinel.py` | Complete application: API client, SQLite store, matching engine, monitor workers, Telegram alerts, Flask dashboard, CLI, and configuration loading |
| `config.example.json` | Safe configuration template showing the expected account structure |
| `requirements.txt` | Python dependencies |
| `.gitignore` | Prevents local secrets, databases, logs, and Python cache files from being committed |
| `LICENSE` | MIT license |
| `README.md` | Documentation |

There is no separate test suite or GitHub Actions workflow required to run the application.

---

## <img src="./assets/icons/limits.svg" alt="" width="24" height="24" align="absmiddle"> Limitations

- NextDNS API availability and response formats are outside the application's control.
- Monitoring is polling-based rather than a provider-side streaming connection.
- The logs request currently asks NextDNS for up to 100 records per polling cycle. Very high-volume profiles can reach this limit.
- When the API returns 100 records, Sentinel logs a warning so the operator knows the polling window may be larger than the returned page.
- Pagination/cursor handling is not currently implemented.
- SQLite is local persistence and is not intended to be a distributed database.
- Telegram delivery is best-effort.
- The dashboard does not include built-in authentication.
- Losing the Fernet key makes previously encrypted API keys unrecoverable.

For high-volume profiles, use a sufficiently short polling interval and monitor the application logs for the 100-record warning.

---

## <img src="./assets/icons/limits.svg" alt="" width="24" height="24" align="absmiddle"> Troubleshooting

### `NEXTDNS_SENTINEL_SECRET_KEY is required`

Generate a Fernet key and export it before starting Sentinel:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### Invalid Fernet key

Make sure `NEXTDNS_SENTINEL_SECRET_KEY` contains the complete value generated by Fernet and has not been modified.

### Stored API keys cannot be decrypted

The database was encrypted using a different Fernet key. Restore the original key.

### No active accounts configured

Check:

- `config.json`
- `profile_id`
- `name`
- `api_key_env`
- The corresponding API-key environment variable
- `active: true`

### Telegram alerts are not arriving

Check:

- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`
- Bot permissions
- Application logs for HTTP errors or rate limiting
- The configured alert cooldown

Remember that the cooldown intentionally suppresses repeated notifications for the same profile/domain.

### Too many API requests

Increase `NEXTDNS_SENTINEL_INTERVAL`, keep the number of monitored profiles reasonable, and avoid unnecessarily aggressive polling.

### Dashboard is inaccessible

Verify the host and port:

```bash
python nextdns_sentinel.py --dashboard --host 127.0.0.1 --port 5000
```

Then open:

```text
http://127.0.0.1:5000
```

---

## <img src="./assets/icons/contributing.svg" alt="" width="24" height="24" align="absmiddle"> Contributing

Issues and pull requests are welcome.

When contributing, do not include:

- NextDNS API keys
- Telegram bot tokens
- Private chat IDs
- Private DNS logs
- Private profile information
- Local databases containing sensitive data

Keep changes focused on the application's documented behavior and preserve the local-first security model.

---

## <img src="./assets/icons/license.svg" alt="" width="24" height="24" align="absmiddle"> License

This project is licensed under the [MIT License](LICENSE).
