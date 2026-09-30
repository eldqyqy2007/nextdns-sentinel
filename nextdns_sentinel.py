#!/usr/bin/env python3
"""
NextDNS Sentinel
Local-first monitoring for NextDNS custom denylist matches.

Designed for defensive monitoring of NextDNS profiles you own or administer.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, jsonify, render_template_string

APP_NAME = "NextDNS Sentinel"
DB_PATH = Path(os.getenv("NEXTDNS_SENTINEL_DB", "data/sentinel.db"))
CONFIG_PATH = Path(os.getenv("NEXTDNS_SENTINEL_CONFIG", "config.json"))
LOG_LEVEL = os.getenv("NEXTDNS_SENTINEL_LOG_LEVEL", "INFO").upper()
HTTP_TIMEOUT = float(os.getenv("NEXTDNS_SENTINEL_HTTP_TIMEOUT", "10"))
CHECK_INTERVAL = max(5, int(os.getenv("NEXTDNS_SENTINEL_INTERVAL", "15")))
INITIAL_LOOKBACK = max(30, int(os.getenv("NEXTDNS_SENTINEL_INITIAL_LOOKBACK", "60")))
POLL_OVERLAP_MS = max(0, int(os.getenv("NEXTDNS_SENTINEL_POLL_OVERLAP_MS", "5000")))
ALERT_COOLDOWN = max(0, int(os.getenv("NEXTDNS_SENTINEL_ALERT_COOLDOWN", "300")))
API_RETRIES = max(0, int(os.getenv("NEXTDNS_SENTINEL_API_RETRIES", "3")))
SECRET_KEY = os.getenv("NEXTDNS_SENTINEL_SECRET_KEY", "")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def setup_logging() -> None:
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="%(asctime)s | %(levelname)s | %(message)s",
    )


class NextDNSError(RuntimeError):
    """Raised when the NextDNS API returns a non-recoverable error."""


class Store:
    def __init__(self, path: Path) -> None:
        if not SECRET_KEY:
            raise RuntimeError("NEXTDNS_SENTINEL_SECRET_KEY is required.")
        try:
            self.cipher = Fernet(SECRET_KEY.encode())
        except ValueError as exc:
            raise RuntimeError("NEXTDNS_SENTINEL_SECRET_KEY is not a valid Fernet key.") from exc

        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS accounts (
                    profile_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    profile_name TEXT NOT NULL DEFAULT '',
                    api_key TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1,
                    added_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS denylist (
                    profile_id TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(profile_id, domain)
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    profile_id TEXT NOT NULL,
                    account_name TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    matched_domain TEXT NOT NULL DEFAULT '',
                    reason TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT '',
                    client_ip TEXT NOT NULL DEFAULT '',
                    event_key TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_created_at
                ON alerts(created_at);

                CREATE INDEX IF NOT EXISTS idx_alerts_domain_created
                ON alerts(profile_id, domain, created_at);

                CREATE TABLE IF NOT EXISTS monitor_state (
                    profile_id TEXT PRIMARY KEY,
                    last_poll_ms INTEGER NOT NULL DEFAULT 0,
                    last_success_at TEXT NOT NULL DEFAULT '',
                    last_error TEXT NOT NULL DEFAULT ''
                );
                """
            )
            self._migrate_alert_columns(db)

    @staticmethod
    def _migrate_alert_columns(db: sqlite3.Connection) -> None:
        columns = {row[1] for row in db.execute("PRAGMA table_info(alerts)")}
        if "matched_domain" not in columns:
            db.execute("ALTER TABLE alerts ADD COLUMN matched_domain TEXT NOT NULL DEFAULT ''")
        if "status" not in columns:
            db.execute("ALTER TABLE alerts ADD COLUMN status TEXT NOT NULL DEFAULT ''")

    def upsert_account(self, account: dict[str, Any]) -> None:
        with sqlite3.connect(self.path) as db:
            db.execute(
                """
                INSERT INTO accounts(profile_id,name,profile_name,api_key,active,added_at)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(profile_id) DO UPDATE SET
                    name=excluded.name,
                    profile_name=excluded.profile_name,
                    api_key=excluded.api_key,
                    active=excluded.active
                """,
                (
                    account["profile_id"],
                    account["name"],
                    account.get("profile_name", ""),
                    self.cipher.encrypt(account["api_key"].encode()).decode(),
                    int(account.get("active", True)),
                    account.get("added_at", utc_now()),
                ),
            )

    def accounts(self) -> list[dict[str, Any]]:
        with sqlite3.connect(self.path) as db:
            db.row_factory = sqlite3.Row
            rows = [
                dict(r)
                for r in db.execute(
                    "SELECT profile_id,name,profile_name,api_key,active,added_at FROM accounts"
                )
            ]

        accounts = []
        for row in rows:
            try:
                row["api_key"] = self.cipher.decrypt(row["api_key"].encode()).decode()
            except InvalidToken as exc:
                raise RuntimeError(
                    "Unable to decrypt a stored API key. Verify NEXTDNS_SENTINEL_SECRET_KEY."
                ) from exc
            accounts.append(row)
        return accounts

    def replace_denylist(self, profile_id: str, domains: list[str]) -> None:
        now = utc_now()
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM denylist WHERE profile_id=?", (profile_id,))
            db.executemany(
                "INSERT OR IGNORE INTO denylist(profile_id,domain,updated_at) VALUES(?,?,?)",
                [(profile_id, d, now) for d in sorted(set(domains))],
            )

    def add_alert(
        self,
        profile_id: str,
        account_name: str,
        domain: str,
        matched_domain: str,
        reason: str,
        status: str,
        client_ip: str,
        event_key: str,
    ) -> bool:
        try:
            with sqlite3.connect(self.path) as db:
                db.execute(
                    """
                    INSERT INTO alerts(
                        profile_id,account_name,domain,matched_domain,reason,status,
                        client_ip,event_key,created_at
                    )
                    VALUES(?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        profile_id,
                        account_name,
                        domain,
                        matched_domain,
                        reason,
                        status,
                        client_ip,
                        event_key,
                        utc_now(),
                    ),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def was_recently_alerted(
        self, profile_id: str, domain: str, cooldown_seconds: int
    ) -> bool:
        if cooldown_seconds <= 0:
            return False
        cutoff = datetime.fromtimestamp(
            time.time() - cooldown_seconds, timezone.utc
        ).isoformat()
        with sqlite3.connect(self.path) as db:
            row = db.execute(
                """
                SELECT 1 FROM alerts
                WHERE profile_id=? AND domain=? AND created_at>=?
                ORDER BY id DESC LIMIT 1
                """,
                (profile_id, domain, cutoff),
            ).fetchone()
        return row is not None

    def set_poll_state(
        self, profile_id: str, last_poll_ms: int, error: str = ""
    ) -> None:
        with sqlite3.connect(self.path) as db:
            db.execute(
                """
                INSERT INTO monitor_state(profile_id,last_poll_ms,last_success_at,last_error)
                VALUES(?,?,?,?)
                ON CONFLICT(profile_id) DO UPDATE SET
                    last_poll_ms=excluded.last_poll_ms,
                    last_success_at=excluded.last_success_at,
                    last_error=excluded.last_error
                """,
                (profile_id, last_poll_ms, utc_now() if not error else "", error),
            )

    def get_poll_ms(self, profile_id: str) -> int:
        with sqlite3.connect(self.path) as db:
            row = db.execute(
                "SELECT last_poll_ms FROM monitor_state WHERE profile_id=?",
                (profile_id,),
            ).fetchone()
        return int(row[0]) if row else 0

    def stats(self) -> dict[str, Any]:
        with sqlite3.connect(self.path) as db:
            accounts = db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
            active = db.execute(
                "SELECT COUNT(*) FROM accounts WHERE active=1"
            ).fetchone()[0]
            alerts = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            domains = db.execute("SELECT COUNT(*) FROM denylist").fetchone()[0]
            state = db.execute(
                """
                SELECT MAX(last_success_at), MAX(last_error)
                FROM monitor_state
                """
            ).fetchone()
            return {
                "accounts": accounts,
                "active_accounts": active,
                "alerts": alerts,
                "denylist_entries": domains,
                "last_success_at": state[0] or "",
                "last_error": state[1] or "",
                "poll_interval_seconds": CHECK_INTERVAL,
            }

    def recent_alerts(self, limit: int = 25) -> list[dict[str, Any]]:
        with sqlite3.connect(self.path) as db:
            db.row_factory = sqlite3.Row
            return [
                dict(r)
                for r in db.execute(
                    """
                    SELECT account_name,domain,matched_domain,reason,status,client_ip,created_at
                    FROM alerts ORDER BY id DESC LIMIT ?
                    """,
                    (limit,),
                )
            ]


class NextDNSClient:
    BASE = "https://api.nextdns.io"

    def __init__(self, api_key: str) -> None:
        self.session = requests.Session()
        self.session.headers.update(
            {"X-Api-Key": api_key, "Accept": "application/json"}
        )

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.BASE}{path}"
        last_error: Exception | None = None

        for attempt in range(API_RETRIES + 1):
            try:
                response = self.session.get(url, params=params, timeout=HTTP_TIMEOUT)
                if response.status_code == 429:
                    retry_after = response.headers.get("Retry-After", "")
                    delay = min(float(retry_after) if retry_after else 2 ** attempt, 60.0)
                    logging.warning(
                        "NextDNS rate limit (429) for %s; retrying in %.1fs",
                        path,
                        delay,
                    )
                    if attempt < API_RETRIES:
                        time.sleep(delay)
                        continue
                    raise NextDNSError("NextDNS API rate limit exceeded (HTTP 429).")

                if response.status_code >= 500:
                    delay = min(2 ** attempt, 30)
                    logging.warning(
                        "NextDNS server error (%s) for %s; retrying in %ss",
                        response.status_code,
                        path,
                        delay,
                    )
                    if attempt < API_RETRIES:
                        time.sleep(delay)
                        continue

                if not response.ok:
                    detail = response.text.strip()[:300]
                    raise NextDNSError(
                        f"NextDNS API returned HTTP {response.status_code} for {path}: {detail}"
                    )

                return response.json()
            except requests.RequestException as exc:
                last_error = exc
                if attempt >= API_RETRIES:
                    raise
                delay = min(2 ** attempt, 30)
                logging.warning(
                    "Network error for %s; retrying in %ss: %s", path, delay, exc
                )
                time.sleep(delay)

        raise NextDNSError(f"NextDNS request failed: {last_error}")

    def profiles(self) -> list[dict[str, Any]]:
        return self._get("/profiles").get("data", [])

    def denylist(self, profile_id: str) -> list[str]:
        values = self._get(f"/profiles/{profile_id}/denylist").get("data", [])
        domains: list[str] = []
        for item in values:
            value = item.get("id") or item.get("domain") or item.get("name")
            if value:
                domains.append(normalize_domain(str(value)))
        return domains

    def logs(self, profile_id: str, from_ms: int) -> list[dict[str, Any]]:
        values = self._get(
            f"/profiles/{profile_id}/logs",
            params={"limit": 100, "from": from_ms},
        ).get("data", [])
        if len(values) >= 100:
            logging.warning(
                "NextDNS returned 100 log entries for profile %s. "
                "The API limit may have been reached; reduce the polling interval "
                "or investigate pagination if your profile has high DNS volume.",
                profile_id,
            )
        return values


def normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def domain_matches(domain: str, denylist: set[str]) -> bool:
    domain = normalize_domain(domain)
    normalized = {normalize_domain(entry) for entry in denylist}
    if domain in normalized:
        return True

    labels = domain.split(".")
    for i in range(1, len(labels)):
        if ".".join(labels[i:]) in normalized:
            return True

    for entry in normalized:
        if entry.startswith("*.") and domain.endswith(entry[1:]):
            return True
    return False


def event_domain(log: dict[str, Any]) -> str:
    return normalize_domain(
        str(log.get("domain") or log.get("query") or log.get("name") or "")
    )


def matched_domain(log: dict[str, Any]) -> str:
    return normalize_domain(
        str(log.get("matched_name") or log.get("matchedDomain") or "")
    )


def event_status(log: dict[str, Any]) -> str:
    return str(log.get("status") or "").strip()


def event_reason(log: dict[str, Any]) -> str:
    reasons = log.get("reasons") or log.get("reason") or ""
    if isinstance(reasons, list):
        return ", ".join(str(x) for x in reasons if x)
    return str(reasons).strip()


def event_client_ip(log: dict[str, Any]) -> str:
    client = log.get("client")
    if isinstance(client, dict):
        return str(client.get("ip") or "").strip()
    return str(log.get("client_ip") or "").strip()


def event_key(profile_id: str, log: dict[str, Any]) -> str:
    raw = json.dumps(log, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(f"{profile_id}:{raw}".encode()).hexdigest()


def send_telegram(token: str, chat_id: str, message: str) -> bool:
    if not token or not chat_id:
        return False
    try:
        response = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data={"chat_id": chat_id, "text": message},
            timeout=HTTP_TIMEOUT,
        )
        if response.status_code == 429:
            logging.warning("Telegram rate limit (429); alert was not delivered.")
            return False
        if not response.ok:
            logging.error(
                "Telegram delivery failed: HTTP %s", response.status_code
            )
            return False
        return True
    except requests.RequestException:
        logging.exception("Telegram delivery failed")
        return False


@dataclass
class Sentinel:
    store: Store
    telegram_token: str = ""
    telegram_chat_id: str = ""
    stop_event: threading.Event | None = None

    def notify(
        self,
        account: dict[str, Any],
        domain: str,
        reason: str,
        status: str,
        matched: str,
        client_ip: str = "",
    ) -> None:
        message = (
            "NextDNS Sentinel alert\n\n"
            f"Account: {account['name']}\n"
            f"Domain: {domain}\n"
            f"Matched: {matched or 'n/a'}\n"
            f"Status: {status or 'n/a'}\n"
            f"Reason: {reason or 'Custom denylist match'}\n"
            f"Time: {utc_now()}"
        )
        if client_ip:
            message += f"\nClient IP: {client_ip}"
        if self.telegram_token and self.telegram_chat_id:
            send_telegram(self.telegram_token, self.telegram_chat_id, message)

    def monitor_account(self, account: dict[str, Any]) -> None:
        client = NextDNSClient(account["api_key"])
        profile_id = account["profile_id"]
        logging.info("Monitoring %s (%s)", account["name"], profile_id)
        denylist: set[str] = set()
        iteration = 0

        while not self.stop_event or not self.stop_event.is_set():
            try:
                iteration += 1
                if iteration == 1 or iteration % 20 == 0:
                    denylist = set(client.denylist(profile_id))
                    self.store.replace_denylist(profile_id, list(denylist))
                    logging.info(
                        "Loaded %d denylist entries for %s",
                        len(denylist),
                        account["name"],
                    )

                last_poll_ms = self.store.get_poll_ms(profile_id)
                now_ms = int(time.time() * 1000)
                from_ms = (
                    max(last_poll_ms - POLL_OVERLAP_MS, 0)
                    if last_poll_ms
                    else now_ms - INITIAL_LOOKBACK * 1000
                )

                logs = client.logs(profile_id, from_ms)
                for log in logs:
                    domain = event_domain(log)
                    if not domain or not domain_matches(domain, denylist):
                        continue

                    key = event_key(profile_id, log)
                    matched = matched_domain(log)
                    status = event_status(log)
                    reason = event_reason(log) or "Custom denylist match"
                    client_ip = event_client_ip(log)

                    recently_alerted = self.store.was_recently_alerted(
                        profile_id, domain, ALERT_COOLDOWN
                    )
                    if self.store.add_alert(
                        profile_id,
                        account["name"],
                        domain,
                        matched,
                        reason,
                        status,
                        client_ip,
                        key,
                    ):
                        logging.warning(
                            "Denylist match: %s -> %s",
                            account["name"],
                            domain,
                        )
                        if not recently_alerted:
                            self.notify(
                                account,
                                domain,
                                reason,
                                status,
                                matched,
                                client_ip,
                            )
                        else:
                            logging.info(
                                "Telegram notification suppressed by cooldown for %s",
                                domain,
                            )

                self.store.set_poll_state(profile_id, now_ms)
                if len(logs) < 100:
                    # With fewer than the API limit, the current window is complete.
                    pass
                if self.stop_event:
                    self.stop_event.wait(CHECK_INTERVAL)
                else:
                    time.sleep(CHECK_INTERVAL)

            except (requests.RequestException, NextDNSError) as exc:
                message = str(exc)
                logging.error(
                    "NextDNS API error for %s: %s", account["name"], message
                )
                self.store.set_poll_state(
                    profile_id, self.store.get_poll_ms(profile_id), message
                )
                if self.stop_event:
                    self.stop_event.wait(max(CHECK_INTERVAL, 10))
                else:
                    time.sleep(max(CHECK_INTERVAL, 10))
            except Exception:
                logging.exception(
                    "Unexpected monitoring error for %s", account["name"]
                )
                if self.stop_event:
                    self.stop_event.wait(max(CHECK_INTERVAL, 10))
                else:
                    time.sleep(max(CHECK_INTERVAL, 10))

    def run(self) -> None:
        accounts = [a for a in self.store.accounts() if a["active"]]
        if not accounts:
            raise RuntimeError("No active accounts configured.")

        stop_event = threading.Event()
        self.stop_event = stop_event
        threads = [
            threading.Thread(
                target=self.monitor_account,
                args=(account,),
                name=f"sentinel-{account['profile_id']}",
                daemon=True,
            )
            for account in accounts
        ]

        for thread in threads:
            thread.start()

        logging.info(
            "%s is monitoring %d account(s). Press Ctrl+C to stop.",
            APP_NAME,
            len(threads),
        )
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            logging.info("Stopping %s.", APP_NAME)
            stop_event.set()
            for thread in threads:
                thread.join(timeout=CHECK_INTERVAL + 5)


DASHBOARD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NextDNS Sentinel</title>
<style>
body{font-family:system-ui,sans-serif;background:#080b12;color:#e8edf7;margin:0;padding:32px}
main{max-width:1100px;margin:auto}
h1{margin-bottom:6px}.muted{color:#8c98aa}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;margin:28px 0}
.card{background:#101621;border:1px solid #202a3a;border-radius:14px;padding:20px}
.value{font-size:32px;font-weight:700}
table{width:100%;border-collapse:collapse;background:#101621;border-radius:14px;overflow:hidden}
th,td{text-align:left;padding:13px;border-bottom:1px solid #202a3a}
code{color:#9ed0ff}
.status{margin:12px 0;padding:10px 14px;border-radius:10px;background:#101621;border:1px solid #202a3a}
.error{color:#ffb4b4}
</style>
</head>
<body>
<main>
<h1>NextDNS Sentinel</h1>
<p class="muted">Local monitoring dashboard</p>
<div class="status" id="health">Loading monitor health...</div>
<div class="grid" id="stats"></div>
<h2>Recent alerts</h2>
<table>
<thead><tr>
<th>Time</th><th>Account</th><th>Domain</th><th>Matched</th><th>Status</th><th>Reason</th>
</tr></thead>
<tbody id="alerts"></tbody>
</table>
</main>
<script>
function cell(value, code=false){
  const el=document.createElement(code?'code':'span');
  el.textContent=value ?? '';
  return el;
}
async function refresh(){
  try{
    const s=await fetch('/api/stats').then(r=>r.json());
    const stats=document.querySelector('#stats');
    stats.replaceChildren();
    for(const [k,v] of Object.entries(s)){
      if(k==='last_success_at'||k==='last_error') continue;
      const card=document.createElement('div');
      card.className='card';
      const label=document.createElement('div');
      label.className='muted';
      label.textContent=k.replaceAll('_',' ');
      const value=document.createElement('div');
      value.className='value';
      value.textContent=v;
      card.append(label,value);
      stats.append(card);
    }
    const health=document.querySelector('#health');
    health.className='status';
    health.textContent=s.last_error
      ? 'Monitor error: '+s.last_error
      : 'Monitor healthy · Last successful poll: '+(s.last_success_at||'not available');
    if(s.last_error) health.classList.add('error');

    const alerts=await fetch('/api/alerts').then(r=>r.json());
    const body=document.querySelector('#alerts');
    body.replaceChildren();
    for(const x of alerts){
      const tr=document.createElement('tr');
      for(const [key,code] of [
        ['created_at',false],['account_name',false],['domain',true],
        ['matched_domain',true],['status',false],['reason',false]
      ]){
        const td=document.createElement('td');
        td.append(cell(x[key],code));
        tr.append(td);
      }
      body.append(tr);
    }
  }catch(error){
    const health=document.querySelector('#health');
    health.className='status error';
    health.textContent='Dashboard refresh failed: '+error;
  }
}
refresh();
setInterval(refresh,5000);
</script>
</body>
</html>"""


def create_app(store: Store) -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def index() -> str:
        return render_template_string(DASHBOARD)

    @app.get("/api/stats")
    def api_stats() -> Any:
        return jsonify(store.stats())

    @app.get("/api/alerts")
    def api_alerts() -> Any:
        return jsonify(store.recent_alerts())

    return app


def load_config() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        return {}
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON in {CONFIG_PATH}: {exc}") from exc


def bootstrap_accounts(store: Store, config: dict[str, Any]) -> None:
    for account in config.get("accounts", []):
        api_key_env = account.get("api_key_env", "")
        api_key = os.getenv(api_key_env)
        if not api_key:
            logging.warning(
                "Missing API key environment variable for %s",
                account.get("name", "account"),
            )
            continue

        store.upsert_account(
            {
                "profile_id": account["profile_id"],
                "name": account["name"],
                "profile_name": account.get("profile_name", ""),
                "api_key": api_key,
                "active": account.get("active", True),
                "added_at": account.get("added_at", utc_now()),
            }
        )


def main() -> None:
    setup_logging()
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--monitor", action="store_true", help="Start live monitoring")
    parser.add_argument("--dashboard", action="store_true", help="Start the local dashboard")
    parser.add_argument("--host", default=os.getenv("NEXTDNS_SENTINEL_HOST", "127.0.0.1"))
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("NEXTDNS_SENTINEL_PORT", "5000")),
    )
    args = parser.parse_args()

    store = Store(DB_PATH)
    config = load_config()
    bootstrap_accounts(store, config)
    telegram_token = os.getenv(
        config.get("telegram_token_env", "TELEGRAM_BOT_TOKEN"), ""
    )
    telegram_chat_id = os.getenv(
        config.get("telegram_chat_id_env", "TELEGRAM_CHAT_ID"), ""
    )
    sentinel = Sentinel(store, telegram_token, telegram_chat_id)

    if args.dashboard:
        if args.host not in {"127.0.0.1", "localhost", "::1"}:
            logging.warning(
                "Dashboard is exposed beyond localhost. "
                "This application does not provide dashboard authentication."
            )
        create_app(store).run(host=args.host, port=args.port, debug=False)
    elif args.monitor:
        sentinel.run()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
