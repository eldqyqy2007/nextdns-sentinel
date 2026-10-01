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
ALERT_RETENTION_DAYS = max(0, int(os.getenv("NEXTDNS_SENTINEL_ALERT_RETENTION_DAYS", "90")))
API_RETRIES = max(0, int(os.getenv("NEXTDNS_SENTINEL_API_RETRIES", "3")))
NOTIFICATION_RETRY_BASE = max(5, int(os.getenv("NEXTDNS_SENTINEL_NOTIFICATION_RETRY_BASE", "30")))
NOTIFICATION_RETRY_MAX = max(NOTIFICATION_RETRY_BASE, int(os.getenv("NEXTDNS_SENTINEL_NOTIFICATION_RETRY_MAX", "900")))
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
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA busy_timeout=5000")
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
                    event_timestamp TEXT NOT NULL DEFAULT '',
                    event_key TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    notified_at TEXT NOT NULL DEFAULT '',
                    notification_status TEXT NOT NULL DEFAULT 'pending',
                    notification_attempts INTEGER NOT NULL DEFAULT 0,
                    last_notification_attempt_at TEXT NOT NULL DEFAULT '',
                    next_retry_at TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_created_at
                ON alerts(created_at);

                CREATE INDEX IF NOT EXISTS idx_alerts_domain_created
                ON alerts(profile_id, domain, created_at);

                CREATE TABLE IF NOT EXISTS monitor_state (
                    profile_id TEXT PRIMARY KEY,
                    last_poll_ms INTEGER NOT NULL DEFAULT 0,
                    last_success_at TEXT NOT NULL DEFAULT '',
                    last_error TEXT NOT NULL DEFAULT '',
                    last_error_at TEXT NOT NULL DEFAULT ''
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
        if "notified_at" not in columns:
            db.execute("ALTER TABLE alerts ADD COLUMN notified_at TEXT NOT NULL DEFAULT ''")
        if "event_timestamp" not in columns:
            db.execute("ALTER TABLE alerts ADD COLUMN event_timestamp TEXT NOT NULL DEFAULT ''")
        if "notification_status" not in columns:
            db.execute("ALTER TABLE alerts ADD COLUMN notification_status TEXT NOT NULL DEFAULT 'pending'")
        monitor_columns = {row[1] for row in db.execute("PRAGMA table_info(monitor_state)")}
        if "last_error_at" not in monitor_columns:
            db.execute("ALTER TABLE monitor_state ADD COLUMN last_error_at TEXT NOT NULL DEFAULT ''")
        if "notification_attempts" not in columns:
            db.execute("ALTER TABLE alerts ADD COLUMN notification_attempts INTEGER NOT NULL DEFAULT 0")
        if "last_notification_attempt_at" not in columns:
            db.execute("ALTER TABLE alerts ADD COLUMN last_notification_attempt_at TEXT NOT NULL DEFAULT ''")
        if "next_retry_at" not in columns:
            db.execute("ALTER TABLE alerts ADD COLUMN next_retry_at TEXT NOT NULL DEFAULT ''")

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
        event_timestamp: str,
        event_key: str,
    ) -> bool:
        try:
            with sqlite3.connect(self.path) as db:
                db.execute(
                    """
                    INSERT INTO alerts(
                        profile_id,account_name,domain,matched_domain,reason,status,
                        client_ip,event_timestamp,event_key,created_at
                    )
                    VALUES(?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        profile_id,
                        account_name,
                        domain,
                        matched_domain,
                        reason,
                        status,
                        client_ip,
                        event_timestamp,
                        event_key,
                        utc_now(),
                    ),
                )
            return True
        except sqlite3.IntegrityError as exc:
            if "UNIQUE constraint failed: alerts.event_key" in str(exc):
                return False
            raise

    def was_recently_notified(
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
                  AND notified_at<>''
                ORDER BY id DESC LIMIT 1
                """,
                (profile_id, domain, cutoff),
            ).fetchone()
        return row is not None

    def mark_alert_notified(self, event_key: str) -> None:
        with sqlite3.connect(self.path) as db:
            db.execute(
                """
                UPDATE alerts
                SET notified_at=?, notification_status='sent'
                WHERE event_key=?
                """,
                (utc_now(), event_key),
            )

    def mark_alert_suppressed(self, event_key: str) -> None:
        with sqlite3.connect(self.path) as db:
            db.execute(
                "UPDATE alerts SET notification_status='suppressed' WHERE event_key=?",
                (event_key,),
            )
    def mark_notification_failed(self, event_key: str) -> None:
        now = datetime.now(timezone.utc)
        with sqlite3.connect(self.path) as db:
            row = db.execute(
                "SELECT notification_attempts FROM alerts WHERE event_key=?",
                (event_key,),
            ).fetchone()
            attempts = int(row[0]) + 1 if row else 1
            delay = min(NOTIFICATION_RETRY_BASE * (2 ** min(attempts - 1, 10)), NOTIFICATION_RETRY_MAX)
            next_retry_at = datetime.fromtimestamp(
                now.timestamp() + delay, timezone.utc
            ).isoformat()
            db.execute(
                """
                UPDATE alerts
                SET notification_attempts=?,
                    last_notification_attempt_at=?,
                    next_retry_at=?
                WHERE event_key=? AND notification_status='pending'
                """,
                (attempts, now.isoformat(), next_retry_at, event_key),
            )

    def cleanup_alerts(self, retention_days: int) -> int:
        if retention_days <= 0:
            return 0
        cutoff = datetime.fromtimestamp(
            time.time() - retention_days * 86400, timezone.utc
        ).isoformat()
        with sqlite3.connect(self.path) as db:
            cursor = db.execute(
                """
                DELETE FROM alerts
                WHERE created_at<? AND notified_at<>''
                """,
                (cutoff,),
            )
            return cursor.rowcount


    def unnotified_alerts(self, profile_id: str, limit: int = 10) -> list[dict[str, Any]]:
        with sqlite3.connect(self.path) as db:
            db.row_factory = sqlite3.Row
            return [
                dict(r)
                for r in db.execute(
                    """
                    SELECT event_key,account_name,domain,matched_domain,reason,status,
                           client_ip,event_timestamp
                    FROM alerts
                    WHERE profile_id=? AND notified_at=''
                      AND notification_status='pending'
                      AND (next_retry_at='' OR next_retry_at<=?)
                    ORDER BY id ASC LIMIT ?
                    """,
                    (profile_id, utc_now(), limit),
                )
            ]

    def set_poll_state(
        self, profile_id: str, last_poll_ms: int, error: str = ""
    ) -> None:
        with sqlite3.connect(self.path) as db:
            db.execute(
                """
                INSERT INTO monitor_state(profile_id,last_poll_ms,last_success_at,last_error,last_error_at)
                VALUES(?,?,?,?,?)
                ON CONFLICT(profile_id) DO UPDATE SET
                    last_poll_ms=excluded.last_poll_ms,
                    last_success_at=CASE
                        WHEN excluded.last_error='' THEN excluded.last_success_at
                        ELSE monitor_state.last_success_at
                    END,
                    last_error=excluded.last_error,
                    last_error_at=CASE
                        WHEN excluded.last_error='' THEN monitor_state.last_error_at
                        ELSE excluded.last_error_at
                    END
                """,
                (profile_id, last_poll_ms, utc_now() if not error else "", error, utc_now() if error else ""),
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
                SELECT last_success_at,last_error
                FROM monitor_state
                ORDER BY CASE WHEN last_success_at='' THEN 0 ELSE 1 END DESC,
                         last_success_at DESC
                LIMIT 1
                """
            ).fetchone()
            error_state = db.execute(
                """
                SELECT last_error
                FROM monitor_state
                WHERE last_error<>''
                ORDER BY last_error_at DESC
                LIMIT 1
                """
            ).fetchone()
            return {
                "accounts": accounts,
                "active_accounts": active,
                "alerts": alerts,
                "denylist_entries": domains,
                "last_success_at": state[0] if state else "",
                "last_error": error_state[0] if error_state else "",
                "poll_interval_seconds": CHECK_INTERVAL,
            }

    def monitor_health(self) -> list[dict[str, Any]]:
        with sqlite3.connect(self.path) as db:
            db.row_factory = sqlite3.Row
            return [
                dict(r)
                for r in db.execute(
                    """
                    SELECT a.profile_id,a.name,a.active,
                           s.last_poll_ms,s.last_success_at,s.last_error
                    FROM accounts a
                    LEFT JOIN monitor_state s ON s.profile_id=a.profile_id
                    ORDER BY a.name
                    """
                )
            ]


    def recent_alerts(self, limit: int = 25) -> list[dict[str, Any]]:
        with sqlite3.connect(self.path) as db:
            db.row_factory = sqlite3.Row
            return [
                dict(r)
                for r in db.execute(
                    """
                    SELECT account_name,domain,matched_domain,reason,status,client_ip,event_timestamp,created_at,notified_at
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
                    try:
                        retry_delay = float(retry_after) if retry_after else 2 ** attempt
                    except (TypeError, ValueError):
                        retry_delay = 2 ** attempt
                    delay = min(retry_delay, 60.0)
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

                try:
                    data = response.json()
                except ValueError as exc:
                    raise NextDNSError(
                        f"NextDNS API returned invalid JSON for {path}."
                    ) from exc

                api_errors = data.get("errors") if isinstance(data, dict) else None
                if api_errors:
                    detail = json.dumps(api_errors, ensure_ascii=False, default=str)[:500]
                    raise NextDNSError(
                        f"NextDNS API returned application errors for {path}: {detail}"
                    )

                if not isinstance(data, dict):
                    raise NextDNSError(
                        f"NextDNS API returned an unexpected response for {path}."
                    )
                return data
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
        domains: list[str] = []
        cursor: str | None = None

        seen_cursors: set[str] = set()
        while True:
            if cursor:
                if cursor in seen_cursors:
                    raise NextDNSError(
                        f"NextDNS denylist pagination repeated cursor for profile {profile_id}."
                    )
                seen_cursors.add(cursor)
            params: dict[str, Any] = {"limit": 100}
            if cursor:
                params["cursor"] = cursor

            response = self._get(f"/profiles/{profile_id}/denylist", params=params)
            for item in response.get("data", []):
                if not isinstance(item, dict) or not item.get("active", True):
                    continue
                value = item.get("id") or item.get("domain") or item.get("name")
                if value:
                    domains.append(normalize_domain(str(value)))

            cursor = (
                response.get("meta", {})
                .get("pagination", {})
                .get("cursor")
            )
            if not cursor:
                break

        return domains

    def logs(self, profile_id: str, from_ms: int) -> list[dict[str, Any]]:
        values: list[dict[str, Any]] = []
        cursor: str | None = None
        from_value = datetime.fromtimestamp(from_ms / 1000, timezone.utc).isoformat()
        to_ms = int(time.time() * 1000)
        to_value = datetime.fromtimestamp(to_ms / 1000, timezone.utc).isoformat()
        seen_cursors: set[str] = set()

        while True:
            if cursor:
                if cursor in seen_cursors:
                    raise NextDNSError(
                        f"NextDNS log pagination repeated cursor for profile {profile_id}."
                    )
                seen_cursors.add(cursor)
            params: dict[str, Any] = {
                "limit": 1000,
                "from": from_value,
                "to": to_value,
                "sort": "asc",
            }
            if cursor:
                params["cursor"] = cursor

            response = self._get(f"/profiles/{profile_id}/logs", params=params)
            page = response.get("data", [])
            values.extend(page)

            cursor = (
                response.get("meta", {})
                .get("pagination", {})
                .get("cursor")
            )
            if not cursor:
                break

        if len(values) >= 1000:
            logging.info(
                "Fetched %d log entries for profile %s using pagination.",
                len(values),
                profile_id,
            )
        return values


def normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def find_matching_domain(domain: str, denylist: set[str]) -> str:
    domain = normalize_domain(domain)
    if not domain:
        return ""

    if domain in denylist:
        return domain

    labels = domain.split(".")
    for i in range(1, len(labels)):
        parent = ".".join(labels[i:])
        if parent in denylist:
            return parent

    for entry in denylist:
        if entry.startswith("*.") and domain.endswith(entry[1:]):
            return entry
    return ""


def domain_matches(domain: str, denylist: set[str]) -> bool:
    return bool(find_matching_domain(domain, denylist))


def event_domain(log: dict[str, Any]) -> str:
    return normalize_domain(
        str(log.get("domain") or log.get("query") or log.get("name") or "")
    )


def matched_domain(log: dict[str, Any]) -> str:
    return normalize_domain(
        str(
            log.get("matched_name")
            or log.get("matchedDomain")
            or log.get("root")
            or ""
        )
    )


def event_timestamp(log: dict[str, Any]) -> str:
    value = log.get("timestamp") or log.get("time") or ""
    return str(value).strip()


def event_status(log: dict[str, Any]) -> str:
    return str(log.get("status") or "").strip()


def event_reason(log: dict[str, Any]) -> str:
    reasons = log.get("reasons") or log.get("reason") or ""
    if isinstance(reasons, list):
        names: list[str] = []
        for item in reasons:
            if isinstance(item, dict):
                value = item.get("name") or item.get("id")
            else:
                value = item
            if value:
                names.append(str(value))
        return ", ".join(names)
    if isinstance(reasons, dict):
        return str(reasons.get("name") or reasons.get("id") or "")
    return str(reasons).strip()


def event_client_ip(log: dict[str, Any]) -> str:
    client = log.get("client")
    if isinstance(client, dict):
        return str(client.get("ip") or "").strip()
    return str(
        log.get("clientIp")
        or log.get("client_ip")
        or ""
    ).strip()


def event_key(profile_id: str, log: dict[str, Any]) -> str:
    raw = json.dumps(log, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(f"{profile_id}:{raw}".encode()).hexdigest()


def send_telegram(
    token: str, chat_id: str, message: str, retries: int = API_RETRIES
) -> bool:
    if not token or not chat_id:
        return False

    for attempt in range(retries + 1):
        try:
            response = requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                data={"chat_id": chat_id, "text": message},
                timeout=HTTP_TIMEOUT,
            )
            if response.ok:
                return True

            if response.status_code == 429 or response.status_code >= 500:
                retry_after = response.headers.get("Retry-After", "")
                try:
                    retry_delay = float(retry_after) if retry_after else 2 ** attempt
                except (TypeError, ValueError):
                    retry_delay = 2 ** attempt
                delay = min(retry_delay, 60.0)
                if attempt < retries:
                    logging.warning(
                        "Telegram HTTP %s; retrying in %.1fs",
                        response.status_code,
                        delay,
                    )
                    time.sleep(delay)
                    continue

            logging.error("Telegram delivery failed: HTTP %s", response.status_code)
            return False
        except requests.RequestException as exc:
            if attempt >= retries:
                logging.exception("Telegram delivery failed")
                return False
            delay = min(2 ** attempt, 30)
            logging.warning(
                "Telegram network error; retrying in %ss: %s", delay, exc
            )
            time.sleep(delay)

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
        event_time: str = "",
    ) -> bool:
        message = (
            "NextDNS Sentinel alert

"
            f"Account: {account['name']}
"
            f"Domain: {domain}
"
            f"Matched: {matched or 'n/a'}
"
            f"Status: {status or 'n/a'}
"
            f"Reason: {reason or 'Custom denylist match'}
"
            f"Event Time: {event_time or 'n/a'}
"
            f"Detected At: {utc_now()}"
        )
        if client_ip:
            message += f"
Client IP: {client_ip}"
        if not self.telegram_token or not self.telegram_chat_id:
            return False
        return send_telegram(self.telegram_token, self.telegram_chat_id, message)

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
                    removed = self.store.cleanup_alerts(ALERT_RETENTION_DAYS)
                    if removed:
                        logging.info("Removed %d old delivered alerts.", removed)
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
                    matched = find_matching_domain(domain, denylist) or matched_domain(log)
                    status = event_status(log)
                    reason = event_reason(log) or "Custom denylist match"
                    client_ip = event_client_ip(log)
                    event_time = event_timestamp(log)

                    recently_notified = self.store.was_recently_notified(
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
                        event_time,
                        key,
                    ):
                        logging.warning(
                            "Denylist match: %s -> %s",
                            account["name"],
                            domain,
                        )
                        if not recently_notified:
                            delivered = self.notify(
                                account,
                                domain,
                                reason,
                                status,
                                matched,
                                client_ip,
                                event_time,
                            )
                            if delivered:
                                self.store.mark_alert_notified(key)
                            else:
                                self.store.mark_notification_failed(key)
                        else:
                            self.store.mark_alert_suppressed(key)
                            logging.info(
                                "Telegram notification suppressed by cooldown for %s",
                                domain,
                            )

                for alert in self.store.unnotified_alerts(profile_id):
                    delivered = self.notify(
                        account,
                        alert["domain"],
                        alert["reason"],
                        alert["status"],
                        alert["matched_domain"],
                        alert["client_ip"],
                        alert["event_timestamp"],
                    )
                    if delivered:
                        self.store.mark_alert_notified(alert["event_key"])
                    else:
                        self.store.mark_notification_failed(alert["event_key"])

                self.store.set_poll_state(profile_id, now_ms)
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
            except Exception as exc:
                message = str(exc)
                logging.exception(
                    "Unexpected monitoring error for %s", account["name"]
                )
                self.store.set_poll_state(
                    profile_id, self.store.get_poll_ms(profile_id), message
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
<div class="status" id="accounts-health">Loading account health...</div>
<div class="grid" id="stats"></div>
<h2>Recent alerts</h2>
<table>
<thead><tr>
<th>Event Time</th><th>Detected At</th><th>Account</th><th>Domain</th><th>Matched</th><th>Status</th><th>Reason</th>
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
    const statsResponse=await fetch('/api/stats');
    if(!statsResponse.ok) throw new Error('Stats API returned HTTP '+statsResponse.status);
    const s=await statsResponse.json();
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

    const healthResponse=await fetch('/api/health');
    if(!healthResponse.ok) throw new Error('Health API returned HTTP '+healthResponse.status);
    const accountHealth=await healthResponse.json();
    const healthBox=document.querySelector('#accounts-health');
    healthBox.replaceChildren();
    for(const account of accountHealth){
      const row=document.createElement('div');
      row.textContent=account.name+' · '+(
        account.last_error
          ? 'Error: '+account.last_error
          : 'Last success: '+(account.last_success_at||'not available')
      );
      if(account.last_error) row.className='error';
      healthBox.append(row);
    }

    const alertsResponse=await fetch('/api/alerts');
    if(!alertsResponse.ok) throw new Error('Alerts API returned HTTP '+alertsResponse.status);
    const alerts=await alertsResponse.json();
    const body=document.querySelector('#alerts');
    body.replaceChildren();
    for(const x of alerts){
      const tr=document.createElement('tr');
      for(const [key,code] of [
        ['event_timestamp',false],['created_at',false],['account_name',false],
        ['domain',true],['matched_domain',true],['status',false],['reason',false]
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

    @app.get("/api/health")
    def api_health() -> Any:
        return jsonify(store.monitor_health())

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
