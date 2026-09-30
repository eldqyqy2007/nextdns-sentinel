#!/usr/bin/env python3
"""
NextDNS Sentinel
Real-time monitoring for NextDNS custom denylist matches.

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
from flask import Flask, jsonify, render_template_string

APP_NAME = "NextDNS Sentinel"
DB_PATH = Path(os.getenv("NEXTDNS_SENTINEL_DB", "data/sentinel.db"))
CONFIG_PATH = Path(os.getenv("NEXTDNS_SENTINEL_CONFIG", "config.json"))
LOG_LEVEL = os.getenv("NEXTDNS_SENTINEL_LOG_LEVEL", "INFO").upper()
HTTP_TIMEOUT = float(os.getenv("NEXTDNS_SENTINEL_HTTP_TIMEOUT", "10"))
CHECK_INTERVAL = int(os.getenv("NEXTDNS_SENTINEL_INTERVAL", "15"))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def setup_logging() -> None:
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="%(asctime)s | %(levelname)s | %(message)s",
    )


class Store:
    def __init__(self, path: Path) -> None:
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
                    reason TEXT NOT NULL,
                    client_ip TEXT NOT NULL DEFAULT '',
                    event_key TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_created_at
                ON alerts(created_at);
                """
            )

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
                    account["profile_id"], account["name"], account.get("profile_name", ""),
                    account["api_key"], int(account.get("active", True)),
                    account.get("added_at", utc_now()),
                ),
            )

    def accounts(self) -> list[dict[str, Any]]:
        with sqlite3.connect(self.path) as db:
            db.row_factory = sqlite3.Row
            return [dict(r) for r in db.execute(
                "SELECT profile_id,name,profile_name,api_key,active,added_at FROM accounts"
            )]

    def replace_denylist(self, profile_id: str, domains: list[str]) -> None:
        now = utc_now()
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM denylist WHERE profile_id=?", (profile_id,))
            db.executemany(
                "INSERT OR IGNORE INTO denylist(profile_id,domain,updated_at) VALUES(?,?,?)",
                [(profile_id, d, now) for d in sorted(set(domains))],
            )

    def add_alert(
        self, profile_id: str, account_name: str, domain: str,
        reason: str, client_ip: str, event_key: str,
    ) -> bool:
        try:
            with sqlite3.connect(self.path) as db:
                db.execute(
                    """
                    INSERT INTO alerts(profile_id,account_name,domain,reason,client_ip,event_key,created_at)
                    VALUES(?,?,?,?,?,?,?)
                    """,
                    (profile_id, account_name, domain, reason, client_ip, event_key, utc_now()),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def stats(self) -> dict[str, int]:
        with sqlite3.connect(self.path) as db:
            accounts = db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
            active = db.execute("SELECT COUNT(*) FROM accounts WHERE active=1").fetchone()[0]
            alerts = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            domains = db.execute("SELECT COUNT(*) FROM denylist").fetchone()[0]
            return {"accounts": accounts, "active_accounts": active, "alerts": alerts, "denylist_entries": domains}

    def recent_alerts(self, limit: int = 25) -> list[dict[str, Any]]:
        with sqlite3.connect(self.path) as db:
            db.row_factory = sqlite3.Row
            return [dict(r) for r in db.execute(
                "SELECT account_name,domain,reason,client_ip,created_at "
                "FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
            )]


class NextDNSClient:
    BASE = "https://api.nextdns.io"

    def __init__(self, api_key: str) -> None:
        self.session = requests.Session()
        self.session.headers.update({"X-Api-Key": api_key, "Accept": "application/json"})

    def profiles(self) -> list[dict[str, Any]]:
        r = self.session.get(f"{self.BASE}/profiles", timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        return r.json().get("data", [])

    def denylist(self, profile_id: str) -> list[str]:
        r = self.session.get(
            f"{self.BASE}/profiles/{profile_id}/denylist", timeout=HTTP_TIMEOUT
        )
        r.raise_for_status()
        values = r.json().get("data", [])
        domains: list[str] = []
        for item in values:
            value = item.get("id") or item.get("domain") or item.get("name")
            if value:
                domains.append(str(value).strip().lower())
        return domains

    def logs(self, profile_id: str, since_seconds: int = 60) -> list[dict[str, Any]]:
        params = {"limit": 100, "from": int((time.time() - since_seconds) * 1000)}
        r = self.session.get(
            f"{self.BASE}/profiles/{profile_id}/logs", params=params, timeout=HTTP_TIMEOUT
        )
        r.raise_for_status()
        return r.json().get("data", [])


def domain_matches(domain: str, denylist: set[str]) -> bool:
    domain = domain.lower().strip().rstrip(".")
    if domain in denylist:
        return True
    labels = domain.split(".")
    for i in range(1, len(labels)):
        if ".".join(labels[i:]) in denylist:
            return True
    return any(
        entry.startswith("*.") and domain.endswith(entry[1:])
        for entry in denylist
    )


def event_domain(log: dict[str, Any]) -> str:
    return str(
        log.get("domain")
        or log.get("query")
        or log.get("name")
        or ""
    ).lower().strip()


def event_key(profile_id: str, log: dict[str, Any]) -> str:
    raw = json.dumps(log, sort_keys=True, default=str)
    return hashlib.sha256(f"{profile_id}:{raw}".encode()).hexdigest()


def send_telegram(token: str, chat_id: str, message: str) -> bool:
    if not token or not chat_id:
        return False
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data={"chat_id": chat_id, "text": message},
            timeout=HTTP_TIMEOUT,
        )
        return r.ok
    except requests.RequestException:
        logging.exception("Telegram delivery failed")
        return False


@dataclass
class Sentinel:
    store: Store
    telegram_token: str = ""
    telegram_chat_id: str = ""

    def notify(self, account: dict[str, Any], domain: str, client_ip: str = "") -> None:
        message = (
            "🚨 NextDNS Sentinel alert\n\n"
            f"Account: {account['name']}\n"
            f"Domain: {domain}\n"
            "Reason: Matched custom denylist\n"
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
        while True:
            try:
                iteration += 1
                if iteration == 1 or iteration % 20 == 0:
                    denylist = set(client.denylist(profile_id))
                    self.store.replace_denylist(profile_id, list(denylist))
                    logging.info("Loaded %d denylist entries for %s", len(denylist), account["name"])
                for log in client.logs(profile_id):
                    domain = event_domain(log)
                    if not domain or not domain_matches(domain, denylist):
                        continue
                    key = event_key(profile_id, log)
                    client_ip = str(log.get("client", {}).get("ip", "") or "")
                    if self.store.add_alert(
                        profile_id, account["name"], domain,
                        "Matched custom denylist", client_ip, key
                    ):
                        logging.warning("Denylist match: %s -> %s", account["name"], domain)
                        self.notify(account, domain, client_ip)
                time.sleep(CHECK_INTERVAL)
            except requests.RequestException as exc:
                logging.error("NextDNS API error for %s: %s", account["name"], exc)
                time.sleep(max(CHECK_INTERVAL, 10))
            except Exception:
                logging.exception("Unexpected monitoring error for %s", account["name"])
                time.sleep(max(CHECK_INTERVAL, 10))

    def run(self) -> None:
        accounts = [a for a in self.store.accounts() if a["active"]]
        if not accounts:
            raise RuntimeError("No active accounts configured.")
        threads = [
            threading.Thread(target=self.monitor_account, args=(account,), daemon=True)
            for account in accounts
        ]
        for thread in threads:
            thread.start()
        logging.info("%s is monitoring %d account(s). Press Ctrl+C to stop.", APP_NAME, len(threads))
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            logging.info("Stopping %s.", APP_NAME)


DASHBOARD = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NextDNS Sentinel</title><style>
body{font-family:system-ui,sans-serif;background:#080b12;color:#e8edf7;margin:0;padding:32px}
main{max-width:1100px;margin:auto}h1{margin-bottom:6px}.muted{color:#8c98aa}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;margin:28px 0}
.card{background:#101621;border:1px solid #202a3a;border-radius:14px;padding:20px}.value{font-size:32px;font-weight:700}
table{width:100%;border-collapse:collapse;background:#101621;border-radius:14px;overflow:hidden}
th,td{text-align:left;padding:13px;border-bottom:1px solid #202a3a}code{color:#9ed0ff}
</style></head><body><main>
<h1>🛡️ NextDNS Sentinel</h1><p class="muted">Local monitoring dashboard</p>
<div class="grid" id="stats"></div><h2>Recent alerts</h2><table><thead><tr>
<th>Time</th><th>Account</th><th>Domain</th><th>Reason</th></tr></thead>
<tbody id="alerts"></tbody></table></main>
<script>
async function refresh(){const s=await fetch('/api/stats').then(r=>r.json());
document.querySelector('#stats').innerHTML=Object.entries(s).map(([k,v])=>'<div class="card"><div class="muted">'+k.replaceAll('_',' ')+'</div><div class="value">'+v+'</div></div>').join('');
const a=await fetch('/api/alerts').then(r=>r.json());document.querySelector('#alerts').innerHTML=a.map(x=>'<tr><td>'+x.created_at+'</td><td>'+x.account_name+'</td><td><code>'+x.domain+'</code></td><td>'+x.reason+'</td></tr>').join('')}
refresh();setInterval(refresh,5000);
</script></body></html>"""


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
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def bootstrap_accounts(store: Store, config: dict[str, Any]) -> None:
    for account in config.get("accounts", []):
        api_key = os.getenv(account.get("api_key_env", ""))
        if not api_key:
            logging.warning("Missing API key environment variable for %s", account.get("name", "account"))
            continue
        store.upsert_account({
            "profile_id": account["profile_id"],
            "name": account["name"],
            "profile_name": account.get("profile_name", ""),
            "api_key": api_key,
            "active": account.get("active", True),
            "added_at": account.get("added_at", utc_now()),
        })


def main() -> None:
    setup_logging()
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--monitor", action="store_true", help="Start live monitoring")
    parser.add_argument("--dashboard", action="store_true", help="Start the local dashboard")
    parser.add_argument("--host", default=os.getenv("NEXTDNS_SENTINEL_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("NEXTDNS_SENTINEL_PORT", "5000")))
    args = parser.parse_args()

    store = Store(DB_PATH)
    config = load_config()
    bootstrap_accounts(store, config)
    telegram_token = os.getenv(config.get("telegram_token_env", "TELEGRAM_BOT_TOKEN"), "")
    telegram_chat_id = os.getenv(config.get("telegram_chat_id_env", "TELEGRAM_CHAT_ID"), "")
    sentinel = Sentinel(store, telegram_token, telegram_chat_id)

    if args.dashboard:
        create_app(store).run(host=args.host, port=args.port, debug=False)
    elif args.monitor:
        sentinel.run()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
