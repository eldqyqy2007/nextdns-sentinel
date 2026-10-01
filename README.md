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

# <img src="./assets/icons/sentinel.svg" alt="" width="32" height="32" align="absmiddle"> NextDNS Sentinel

**NextDNS Sentinel** is a local-first monitoring utility for **NextDNS profiles you own or administer**. It polls DNS logs, matches domains against custom denylists, stores detected events locally in SQLite, and can send Telegram alerts.

The application is intentionally **single-file**: the monitoring engine, API client, matching logic, database layer, alerts, dashboard, and CLI are all contained in `nextdns_sentinel.py`.

> **Design principle:** keep operational data local, keep secrets outside Git, and expose the dashboard locally by default.

## <img src="./assets/icons/overview.svg" alt="" width="24" height="24" align="absmiddle"> Features

- **Multi-profile monitoring** with independent worker threads.
- **Denylist matching** for exact domains, parent domains, and wildcard-style entries.
- **Persistent polling state** with a small overlap window to reduce missed events.
- **Duplicate protection** using deterministic SHA-256 event fingerprints.
- **Alert cooldown** to reduce repeated Telegram notifications.
- **Rich event data** including matched domain, status, reason, client IP, and timestamp when available.
- **SQLite persistence** for accounts, denylist snapshots, alerts, and monitor state.
- **Fernet encryption** for stored NextDNS API keys.
- **API resilience** with timeouts, retries, exponential backoff, and handling for 429/5xx responses.
- **Local Flask dashboard** with statistics, health status, and recent alerts.
- **Environment-based secrets** and graceful shutdown.

## <img src="./assets/icons/process.svg" alt="" width="24" height="24" align="absmiddle"> How it works

```text
                 NextDNS API
                      |
          +-----------+-----------+
          |           |           |
       Profiles    Denylist      Logs
          |           |           |
          +-----------+-----------+
                      |
                      v
             NextDNS Sentinel
                      |
               Domain matching
                      |
                +-----+-----+
                |           |
              Match      No match
                |
          Event fingerprint
                |
          +-----+-----+
          |           |
       Duplicate    New event
          |           |
        Ignore      SQLite
                      |
               +------+------+
               |             |
            Telegram      Dashboard
```

For every active profile, Sentinel remembers the last polling point and queries from slightly before it on the next cycle. The overlap helps reduce boundary misses, while the unique event fingerprint prevents duplicate records.

## <img src="./assets/icons/requirements.svg" alt="" width="24" height="24" align="absmiddle"> Requirements

| Requirement | Purpose |
|---|---|
| Python 3.10+ | Runtime |
| NextDNS API access | Profiles, denylists, and DNS logs |
| Flask | Web dashboard |
| Requests | API communication |
| Cryptography | Fernet API-key encryption |
| SQLite | Local storage |
| Telegram bot + chat ID | Optional alerts |

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

Create your local configuration:

```bash
cp config.example.json config.json
```

Example:

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

Generate the encryption key:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Set the required secrets:

```bash
export NEXTDNS_SENTINEL_SECRET_KEY="your-fernet-key"
export NEXTDNS_PROFILE_1_API_KEY="your-nextdns-api-key"
export TELEGRAM_BOT_TOKEN="your-telegram-bot-token"
export TELEGRAM_CHAT_ID="your-telegram-chat-id"
```

Telegram variables are optional. Never commit `config.json`, API keys, tokens, Fernet keys, databases, or logs.

### Configuration reference

| Variable | Default | Purpose |
|---|---:|---|
| `NEXTDNS_SENTINEL_SECRET_KEY` | Required | Fernet encryption key |
| `NEXTDNS_SENTINEL_DB` | `data/sentinel.db` | SQLite database path |
| `NEXTDNS_SENTINEL_CONFIG` | `config.json` | Configuration path |
| `NEXTDNS_SENTINEL_INTERVAL` | `15` | Poll interval in seconds |
| `NEXTDNS_SENTINEL_INITIAL_LOOKBACK` | `60` | First-poll lookback |
| `NEXTDNS_SENTINEL_POLL_OVERLAP_MS` | `5000` | Poll overlap |
| `NEXTDNS_SENTINEL_ALERT_COOLDOWN` | `300` | Telegram cooldown |
| `NEXTDNS_SENTINEL_API_RETRIES` | `3` | API retries |
| `NEXTDNS_SENTINEL_HTTP_TIMEOUT` | `10` | HTTP timeout |
| `NEXTDNS_SENTINEL_HOST` | `127.0.0.1` | Dashboard host |
| `NEXTDNS_SENTINEL_PORT` | `5000` | Dashboard port |
| `NEXTDNS_SENTINEL_LOG_LEVEL` | `INFO` | Log level |

## <img src="./assets/icons/usage.svg" alt="" width="24" height="24" align="absmiddle"> Usage

Start monitoring:

```bash
python nextdns_sentinel.py --monitor
```

Start the dashboard:

```bash
python nextdns_sentinel.py --dashboard
```

Default dashboard:

```text
http://127.0.0.1:5000
```

Custom host/port:

```bash
python nextdns_sentinel.py --dashboard --host 127.0.0.1 --port 8080
```

Help:

```bash
python nextdns_sentinel.py --help
```

Press **Ctrl+C** to stop the monitor gracefully.

## <img src="./assets/icons/dashboard.svg" alt="" width="24" height="24" align="absmiddle"> Dashboard & Alerts

The local dashboard provides:

- Configured and active account counts
- Denylist entry count
- Total alert count
- Poll interval
- Last successful poll
- Latest monitor error
- Recent alerts with domain, matched domain, status, and reason

It refreshes automatically and safely renders event data using DOM APIs.

When Telegram is configured, alerts can include:

```text
Account: Primary Profile
Domain: sub.example.com
Matched: example.com
Status: blocked
Reason: Custom denylist match
Time: 2026-10-01T00:00:00+00:00
```

Telegram delivery is best-effort; monitoring continues if delivery fails.

## <img src="./assets/icons/storage.svg" alt="" width="24" height="24" align="absmiddle"> Storage & Security

The default database is:

```text
data/sentinel.db
```

SQLite stores:

- Account metadata and encrypted API keys
- Cached denylists
- Detected alerts and event fingerprints
- Monitor polling state and errors

API keys are encrypted with **Fernet** before storage. The Fernet key itself is supplied through `NEXTDNS_SENTINEL_SECRET_KEY` and is not stored by the application.

The dashboard binds to **localhost by default** and has no built-in authentication. If you expose it beyond localhost, use appropriate network controls and authentication.

## <img src="./assets/icons/security.svg" alt="" width="24" height="24" align="absmiddle"> Reliability & Limitations

Sentinel handles network errors, HTTP 429 rate limits, HTTP 5xx responses, retries, timeouts, and Telegram delivery failures.

Current limitations:

- NextDNS logs are polled rather than streamed.
- The logs request is limited to 100 records per cycle.
- Pagination/cursor support is not implemented.
- Telegram is optional and best-effort.
- The dashboard has no built-in authentication.
- Losing the Fernet key makes stored API keys unrecoverable.

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

The complete runtime implementation is contained in **`nextdns_sentinel.py`**. There are no separate test or workflow files required by the application.

## <img src="./assets/icons/license.svg" alt="" width="24" height="24" align="absmiddle"> License

This project is licensed under the [MIT License](LICENSE).
