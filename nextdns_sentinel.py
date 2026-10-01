#!/usr/bin/env python3
"""
NextDNS Sentinel
Local-first monitoring for NextDNS custom denylist matches.

Designed for defensive monitoring of NextDNS profiles you own or administer.
"""
from __future__ import annotations

import argparse
import csv
import io
import math
import re
import statistics
from collections import Counter
import hashlib
import json
from html import escape as html_escape
import logging
import os
import sqlite3
import threading
import time
import tempfile
import shutil
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests
from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, jsonify, render_template_string, request, send_file, session

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _loads(value: str, default: Any) -> Any:
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


class FeatureStore:
    def __init__(self, path):
        self.path = path
        self._ensure_schema()

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    def _ensure_schema(self):
        with self._connect() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS alert_metadata (
                alert_id INTEGER PRIMARY KEY,
                severity TEXT NOT NULL DEFAULT 'low',
                risk_score INTEGER NOT NULL DEFAULT 0,
                risk_factors TEXT NOT NULL DEFAULT '[]',
                correlation_id TEXT NOT NULL DEFAULT '',
                anomaly_score REAL NOT NULL DEFAULT 0,
                domain_risk TEXT NOT NULL DEFAULT 'low',
                enriched_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_alert_metadata_correlation
                ON alert_metadata(correlation_id);

            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_key TEXT NOT NULL UNIQUE,
                profile_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'low',
                risk_score INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'open',
                summary TEXT NOT NULL DEFAULT '',
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                alert_count INTEGER NOT NULL DEFAULT 0,
                device_id TEXT NOT NULL DEFAULT '',
                domain TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                resolved_at TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_incidents_status
                ON incidents(status, updated_at);

            CREATE TABLE IF NOT EXISTS incident_alerts (
                incident_id INTEGER NOT NULL,
                alert_id INTEGER NOT NULL,
                PRIMARY KEY(incident_id, alert_id)
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL DEFAULT '',
                target_id TEXT NOT NULL DEFAULT '',
                profile_id TEXT NOT NULL DEFAULT '',
                actor TEXT NOT NULL DEFAULT 'sentinel',
                details TEXT NOT NULL DEFAULT '{}',
                success INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_created
                ON audit_log(created_at);

            CREATE TABLE IF NOT EXISTS bulk_operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation TEXT NOT NULL,
                domain TEXT NOT NULL DEFAULT '',
                requested_at TEXT NOT NULL,
                completed_at TEXT NOT NULL DEFAULT '',
                successes INTEGER NOT NULL DEFAULT 0,
                failures INTEGER NOT NULL DEFAULT 0,
                skipped INTEGER NOT NULL DEFAULT 0,
                results TEXT NOT NULL DEFAULT '[]'
            );

            CREATE TABLE IF NOT EXISTS delivery_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER,
                channel TEXT NOT NULL,
                status TEXT NOT NULL,
                attempt INTEGER NOT NULL DEFAULT 1,
                error TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_delivery_alert
                ON delivery_events(alert_id, created_at);

            CREATE TABLE IF NOT EXISTS domain_intelligence (
                domain TEXT PRIMARY KEY,
                risk TEXT NOT NULL DEFAULT 'low',
                score INTEGER NOT NULL DEFAULT 0,
                factors TEXT NOT NULL DEFAULT '[]',
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                sightings INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS anomaly_baseline (
                profile_id TEXT NOT NULL,
                bucket_day TEXT NOT NULL,
                bucket_hour TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(profile_id, bucket_day, bucket_hour)
            );

            CREATE TABLE IF NOT EXISTS sentinel_health (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sentinel_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS alert_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                rule_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS alert_suppressions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                until_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_alert_suppressions_fp ON alert_suppressions(fingerprint, until_at);
            CREATE TABLE IF NOT EXISTS maintenance_windows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope TEXT NOT NULL DEFAULT 'global',
                profile_id TEXT NOT NULL DEFAULT '',
                reason TEXT NOT NULL DEFAULT '',
                starts_at TEXT NOT NULL,
                ends_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS escalation_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER,
                level INTEGER NOT NULL DEFAULT 1,
                channel TEXT NOT NULL DEFAULT 'telegram',
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS retention_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                retention_days INTEGER NOT NULL,
                deleted_alerts INTEGER NOT NULL DEFAULT 0,
                vacuumed INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS rate_limit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id TEXT NOT NULL DEFAULT '',
                endpoint TEXT NOT NULL DEFAULT '',
                retry_after REAL NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            """)
            self._migrate_anomaly_baseline_legacy(db)
            self._migrate_unique_constraints(db)

    @staticmethod
    def _migrate_anomaly_baseline_legacy(db: sqlite3.Connection) -> None:
        columns={row[1] for row in db.execute("PRAGMA table_info(anomaly_baseline)").fetchall()}
        if not columns or "bucket_day" in columns:
            return
        # Databases created by older Sentinel versions used only profile_id/bucket_hour.
        # Rebuild the table so the NOT NULL composite key required by current writes exists.
        db.execute("ALTER TABLE anomaly_baseline RENAME TO anomaly_baseline_legacy")
        db.execute("""CREATE TABLE anomaly_baseline (
            profile_id TEXT NOT NULL,
            bucket_day TEXT NOT NULL,
            bucket_hour TEXT NOT NULL,
            count INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(profile_id,bucket_day,bucket_hour)
        )""")
        rows=db.execute("SELECT profile_id,bucket_hour,count,updated_at FROM anomaly_baseline_legacy").fetchall()
        for profile_id,bucket_hour,count,updated_at in rows:
            try:
                day=datetime.fromisoformat(str(updated_at).replace("Z","+00:00")).astimezone(timezone.utc).strftime("%Y-%m-%d")
            except (TypeError,ValueError):
                day=datetime.now(timezone.utc).strftime("%Y-%m-%d")
            db.execute("""INSERT INTO anomaly_baseline(profile_id,bucket_day,bucket_hour,count,updated_at)
                          VALUES(?,?,?,?,?)
                          ON CONFLICT(profile_id,bucket_day,bucket_hour) DO UPDATE SET
                          count=anomaly_baseline.count+excluded.count,
                          updated_at=excluded.updated_at""",(profile_id,day,str(bucket_hour),int(count or 0),str(updated_at or now_iso())))
        db.execute("DROP TABLE anomaly_baseline_legacy")

    @staticmethod
    def _migrate_unique_constraints(db: sqlite3.Connection) -> None:
        # Older Sentinel databases may have been created before the composite
        # keys were declared. Deduplicate legacy rows before creating the
        # unique indexes required by the ON CONFLICT statements.
        migrations = [
            ("alert_metadata", "DELETE FROM alert_metadata WHERE rowid NOT IN (SELECT MAX(rowid) FROM alert_metadata GROUP BY alert_id)",
             "CREATE UNIQUE INDEX IF NOT EXISTS idx_alert_metadata_alert_unique ON alert_metadata(alert_id)"),
            ("domain_intelligence", "DELETE FROM domain_intelligence WHERE rowid NOT IN (SELECT MAX(rowid) FROM domain_intelligence GROUP BY domain)",
             "CREATE UNIQUE INDEX IF NOT EXISTS idx_domain_intelligence_domain_unique ON domain_intelligence(domain)"),
            ("anomaly_baseline", "DELETE FROM anomaly_baseline WHERE rowid NOT IN (SELECT MAX(rowid) FROM anomaly_baseline GROUP BY profile_id,bucket_day,bucket_hour)",
             "CREATE UNIQUE INDEX IF NOT EXISTS idx_anomaly_baseline_profile_day_hour_unique ON anomaly_baseline(profile_id,bucket_day,bucket_hour)"),
            ("sentinel_settings", "DELETE FROM sentinel_settings WHERE rowid NOT IN (SELECT MAX(rowid) FROM sentinel_settings GROUP BY key)",
             "CREATE UNIQUE INDEX IF NOT EXISTS idx_sentinel_settings_key_unique ON sentinel_settings(key)"),
        ]
        for table, dedupe_sql, index_sql in migrations:
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
                db.execute(dedupe_sql)
                db.execute(index_sql)

    def _domain_intel(self, domain: str) -> dict[str, Any]:
        domain = str(domain or '').strip().lower().rstrip('.')
        if not domain:
            return {"risk": "low", "score": 0, "factors": []}
        factors = []
        score = 0
        labels = domain.split('.')
        tld = labels[-1] if labels else ''
        suspicious_tlds = {
            'zip','mov','click','top','gq','tk','ml','ga','cf','work','download',
            'country','stream','cam','rest','fit','buzz','monster','support'
        }
        if tld in suspicious_tlds:
            score += 20
            factors.append("higher-risk TLD heuristic")
        if len(domain) > 80:
            score += 15
            factors.append("unusually long domain")
        if len(labels) >= 5:
            score += 10
            factors.append("deep subdomain nesting")
        if re.search(r'xn--', domain):
            score += 25
            factors.append("IDN/punycode label")
        if re.search(r'\d{6,}', domain):
            score += 15
            factors.append("long numeric sequence")
        if domain.count('-') >= 4:
            score += 10
            factors.append("many hyphens")
        if re.search(r'(login|verify|secure|account|wallet|signin|password)', domain):
            score += 10
            factors.append("credential-themed label")
        score = min(score, 100)
        risk = 'critical' if score >= 80 else 'high' if score >= 55 else 'medium' if score >= 30 else 'low'
        return {"risk": risk, "score": score, "factors": factors}

    def _baseline_anomaly(self, profile_id: str, when: str) -> float:
        try:
            dt = datetime.fromisoformat(str(when).replace('Z', '+00:00'))
        except ValueError:
            dt = datetime.now(timezone.utc)
        bucket_day = dt.astimezone(timezone.utc).strftime('%Y-%m-%d')
        bucket = dt.astimezone(timezone.utc).strftime('%H')
        with self._connect() as db:
            rows = db.execute(
                "SELECT count FROM anomaly_baseline WHERE profile_id=? AND bucket_hour=? ORDER BY bucket_day DESC LIMIT 30",
                (profile_id, bucket),
            ).fetchall()
        if len(rows) < 3:
            return 0.0
        values = [int(r['count']) for r in rows]
        mean = statistics.mean(values)
        if mean <= 0:
            return 0.0
        current = values[-1]
        deviation = (current - mean) / max(mean, 1)
        return round(max(0.0, min(10.0, deviation * 5.0)), 2)

    def _severity(self, alert_type: str, status: str, domain_risk: str, anomaly: float) -> tuple[str, int, list[str]]:
        score = 15
        factors = []
        if alert_type in {'config_change', 'device_inactive'}:
            score += 20
            factors.append(alert_type.replace('_', ' '))
        if alert_type == 'denylist_match':
            score += 20
            factors.append('denylist match')
        if status in {'blocked', 'error'}:
            score += 15
            factors.append(status)
        if domain_risk == 'medium':
            score += 10
            factors.append('domain heuristic')
        elif domain_risk == 'high':
            score += 25
            factors.append('high domain heuristic')
        elif domain_risk == 'critical':
            score += 40
            factors.append('critical domain heuristic')
        if anomaly >= 4:
            score += 20
            factors.append('behavioral anomaly')
        elif anomaly >= 2:
            score += 10
            factors.append('elevated activity')
        score = min(100, score)
        severity = 'critical' if score >= 80 else 'high' if score >= 60 else 'medium' if score >= 35 else 'low'
        return severity, score, factors

    def enrich_alert(self, alert_id: int, profile_id: str, alert_type: str, status: str,
                     domain: str, device_id: str, event_time: str) -> dict[str, Any]:
        intel = self._domain_intel(domain)
        self.update_baseline(profile_id, event_time)
        anomaly = self._baseline_anomaly(profile_id, event_time)
        severity, score, factors = self._severity(alert_type, status, intel['risk'], anomaly)
        with self._connect() as db:
            row = db.execute(
                "SELECT id,profile_id,domain,device_id,event_timestamp,reason FROM alerts WHERE id=?",
                (alert_id,),
            ).fetchone()
            if not row:
                return {}
            correlation_id = ''
            if domain or device_id:
                since = datetime.now(timezone.utc) - timedelta(minutes=15)
                clauses = ["profile_id=?", "created_at>=?"]
                params: list[Any] = [profile_id, since.isoformat()]
                if device_id:
                    clauses.append("device_id=?"); params.append(device_id)
                elif domain:
                    clauses.append("domain=?"); params.append(domain)
                existing = db.execute(
                    "SELECT id FROM alerts WHERE " + " AND ".join(clauses) + " ORDER BY id ASC LIMIT 1",
                    params,
                ).fetchone()
                if existing:
                    correlation_id = f"{profile_id}:{existing['id']}"
                else:
                    correlation_id = f"{profile_id}:{alert_id}"
            db.execute(
                """INSERT INTO alert_metadata
                   (alert_id,severity,risk_score,risk_factors,correlation_id,anomaly_score,domain_risk,enriched_at)
                   VALUES(?,?,?,?,?,?,?,?)
                   ON CONFLICT(alert_id) DO UPDATE SET
                   severity=excluded.severity,risk_score=excluded.risk_score,
                   risk_factors=excluded.risk_factors,correlation_id=excluded.correlation_id,
                   anomaly_score=excluded.anomaly_score,domain_risk=excluded.domain_risk,
                   enriched_at=excluded.enriched_at""",
                (alert_id,severity,score,json.dumps(factors),correlation_id,anomaly,intel['risk'],now_iso()),
            )
            if domain:
                current = db.execute("SELECT sightings FROM domain_intelligence WHERE domain=?", (domain,)).fetchone()
                sightings = int(current['sightings']) + 1 if current else 1
                db.execute(
                    """INSERT INTO domain_intelligence(domain,risk,score,factors,first_seen_at,last_seen_at,sightings)
                       VALUES(?,?,?,?,?,?,?)
                       ON CONFLICT(domain) DO UPDATE SET risk=excluded.risk,score=excluded.score,
                       factors=excluded.factors,last_seen_at=excluded.last_seen_at,sightings=excluded.sightings""",
                    (domain,intel['risk'],intel['score'],json.dumps(intel['factors']),now_iso(),now_iso(),sightings),
                )
            return {
                "alert_id": alert_id, "severity": severity, "risk_score": score,
                "risk_factors": factors, "correlation_id": correlation_id,
                "anomaly_score": anomaly, "domain_risk": intel['risk'],
            }

    def create_or_update_incident(self, alert_id: int, context: dict[str, Any]) -> dict[str, Any] | None:
        correlation_id = str(context.get('correlation_id') or '')
        if not correlation_id:
            return None
        profile_id = str(context.get('profile_id') or '')
        now = now_iso()
        with self._connect() as db:
            row = db.execute("SELECT id FROM incidents WHERE incident_key=?", (correlation_id,)).fetchone()
            if row:
                incident_id = int(row['id'])
                db.execute(
                    """UPDATE incidents SET severity=?,risk_score=max(risk_score,?),last_seen_at=?,
                       alert_count=alert_count+1,updated_at=? WHERE id=?""",
                    (context['severity'],int(context['risk_score']),now,now,incident_id),
                )
            else:
                title = str(context.get('title') or 'Security event correlation')
                db.execute(
                    """INSERT INTO incidents(incident_key,profile_id,title,severity,risk_score,status,summary,
                       first_seen_at,last_seen_at,alert_count,device_id,domain,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (correlation_id,profile_id,title,context['severity'],int(context['risk_score']),'open',
                     str(context.get('reason') or 'Correlated security activity'),
                     now,now,1,str(context.get('device_id') or ''),str(context.get('domain') or ''),now,now),
                )
                incident_id = int(db.execute("SELECT last_insert_rowid()").fetchone()[0])
            db.execute("INSERT OR IGNORE INTO incident_alerts(incident_id,alert_id) VALUES(?,?)",(incident_id,alert_id))
            return self.incident(incident_id)

    def process_alert(self, alert_id: int, context: dict[str, Any]) -> dict[str, Any]:
        enriched = self.enrich_alert(alert_id, context.get('profile_id',''), context.get('alert_type',''),
                                      context.get('status',''), context.get('domain',''),
                                      context.get('device_id',''), context.get('event_timestamp',''))
        if enriched:
            incident = self.create_or_update_incident(alert_id, {**context, **enriched})
            if incident:
                enriched['incident_id'] = incident['id']
        return enriched

    def alert_context(self, alert_id: int) -> dict[str, Any]:
        with self._connect() as db:
            row = db.execute(
                """SELECT a.*,m.severity,m.risk_score,m.risk_factors,m.correlation_id,m.anomaly_score,m.domain_risk,
                          i.id AS incident_id
                   FROM alerts a LEFT JOIN alert_metadata m ON m.alert_id=a.id
                   LEFT JOIN incident_alerts ia ON ia.alert_id=a.id
                   LEFT JOIN incidents i ON i.id=ia.incident_id
                   WHERE a.id=?""",(alert_id,)
            ).fetchone()
            return dict(row) if row else {}

    def alert_by_event_key(self, event_key: str) -> dict[str, Any]:
        with self._connect() as db:
            row = db.execute("SELECT id FROM alerts WHERE event_key=?", (event_key,)).fetchone()
        return self.alert_context(int(row['id'])) if row else {}

    def incidents(self, status: str = '', limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as db:
            if status:
                rows = db.execute("SELECT * FROM incidents WHERE status=? ORDER BY updated_at DESC LIMIT ?", (status,limit)).fetchall()
            else:
                rows = db.execute("SELECT * FROM incidents ORDER BY updated_at DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def incident(self, incident_id: int) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if not row:
                return None
            result = dict(row)
            result['alerts'] = [dict(r) for r in db.execute(
                """SELECT a.*,m.severity,m.risk_score,m.risk_factors,m.correlation_id,m.anomaly_score,m.domain_risk
                   FROM incident_alerts ia JOIN alerts a ON a.id=ia.alert_id
                   LEFT JOIN alert_metadata m ON m.alert_id=a.id
                   WHERE ia.incident_id=? ORDER BY a.id ASC""",(incident_id,)
            ).fetchall()]
            return result

    def set_incident_status(self, incident_id: int, status: str) -> bool:
        if status not in {'open','investigating','resolved','ignored'}:
            return False
        with self._connect() as db:
            cur = db.execute(
                "UPDATE incidents SET status=?,resolved_at=?,updated_at=? WHERE id=?",
                (status, now_iso() if status == 'resolved' else '', now_iso(), incident_id),
            )
            return cur.rowcount > 0

    def heartbeat(self, state: str = 'running', details: Any = None) -> None:
        with self._connect() as db:
            db.execute(
                "INSERT INTO sentinel_health(key,value,updated_at) VALUES('heartbeat',?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
                (json.dumps({"state":state,"details":details or {}},ensure_ascii=False,default=str),now_iso()),
            )

    def audit(self, action: str, target_type: str = '', target_id: str = '',
              profile_id: str = '', details: Any = None, success: bool = True,
              actor: str = 'sentinel') -> int:
        with self._connect() as db:
            cur = db.execute(
                "INSERT INTO audit_log(action,target_type,target_id,profile_id,actor,details,success,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (action,target_type,target_id,profile_id,actor,json.dumps(details or {},ensure_ascii=False,default=str),int(success),now_iso()),
            )
            return int(cur.lastrowid)

    def audit_entries(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._connect() as db:
            return [dict(r) for r in db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]

    def record_bulk(self, operation: str, domain: str, results: list[dict[str, Any]]) -> int:
        successes = sum(r.get('status') == 'success' for r in results)
        failures = sum(r.get('status') == 'failed' for r in results)
        skipped = sum(r.get('status') == 'skipped' for r in results)
        with self._connect() as db:
            cur = db.execute(
                "INSERT INTO bulk_operations(operation,domain,requested_at,completed_at,successes,failures,skipped,results) VALUES(?,?,?,?,?,?,?,?)",
                (operation,domain,now_iso(),now_iso(),successes,failures,skipped,json.dumps(results,ensure_ascii=False)),
            )
            return int(cur.lastrowid)

    def bulk_history(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = [dict(r) for r in db.execute("SELECT * FROM bulk_operations ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]
            for row in rows:
                row['results'] = _loads(row['results'], [])
            return rows

    def delivery(self, alert_id: int, channel: str, status: str, attempt: int = 1, error: str = '') -> None:
        with self._connect() as db:
            db.execute(
                "INSERT INTO delivery_events(alert_id,channel,status,attempt,error,created_at) VALUES(?,?,?,?,?,?)",
                (alert_id,channel,status,attempt,error,now_iso()),
            )

    def delivery_history(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._connect() as db:
            return [dict(r) for r in db.execute(
                """SELECT d.*,a.account_name,a.domain,a.alert_type
                   FROM delivery_events d LEFT JOIN alerts a ON a.id=d.alert_id
                   ORDER BY d.id DESC LIMIT ?""",(limit,)
            ).fetchall()]

    def device_detail(self, profile_id: str, device_id: str) -> dict[str, Any]:
        with self._connect() as db:
            state = db.execute("SELECT * FROM device_state WHERE profile_id=? AND device_id=?", (profile_id,device_id)).fetchone()
            alerts = db.execute(
                """SELECT a.*,m.severity,m.risk_score,m.domain_risk,m.anomaly_score
                   FROM alerts a LEFT JOIN alert_metadata m ON m.alert_id=a.id
                   WHERE a.profile_id=? AND a.device_id=? ORDER BY a.id DESC LIMIT 100""",(profile_id,device_id)
            ).fetchall()
            return {"device":dict(state) if state else {}, "alerts":[dict(r) for r in alerts]}

    def search(self, query: str, limit: int = 100) -> list[dict[str, Any]]:
        q=f"%{query.lower()}%"
        with self._connect() as db:
            alerts=db.execute(
                """SELECT 'alert' AS type,id,profile_id,domain,reason,created_at AS timestamp
                   FROM alerts WHERE lower(domain) LIKE ? OR lower(reason) LIKE ? OR lower(account_name) LIKE ?
                   ORDER BY id DESC LIMIT ?""",(q,q,q,limit)
            ).fetchall()
            incidents=db.execute(
                """SELECT 'incident' AS type,id,profile_id,title AS domain,summary AS reason,created_at AS timestamp
                   FROM incidents WHERE lower(title) LIKE ? OR lower(summary) LIKE ?
                   ORDER BY id DESC LIMIT ?""",(q,q,limit)
            ).fetchall()
            audits=db.execute(
                """SELECT 'audit' AS type,id,profile_id,target_type AS domain,action AS reason,created_at AS timestamp
                   FROM audit_log WHERE lower(action) LIKE ? OR lower(details) LIKE ?
                   ORDER BY id DESC LIMIT ?""",(q,q,limit)
            ).fetchall()
            return [dict(r) for r in sorted([*alerts,*incidents,*audits], key=lambda x:x['timestamp'], reverse=True)[:limit]]

    def analytics(self) -> dict[str, Any]:
        with self._connect() as db:
            severity=[dict(r) for r in db.execute("SELECT severity,COUNT(*) count FROM alert_metadata GROUP BY severity").fetchall()]
            risk=[dict(r) for r in db.execute("SELECT domain_risk,COUNT(*) count FROM alert_metadata GROUP BY domain_risk").fetchall()]
            open_incidents=db.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('open','investigating')").fetchone()[0]
            return {"severity":severity,"domain_risk":risk,"open_incidents":open_incidents}

    def health(self) -> dict[str, Any]:
        with self._connect() as db:
            checks = {}
            try:
                db.execute("SELECT 1")
                checks['sqlite'] = True
            except sqlite3.Error:
                checks['sqlite'] = False
            checks['alerts'] = True
            checks['tables'] = all(
                db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
                for name in ('alert_metadata','incidents','audit_log','delivery_events','sentinel_health')
            )
            heartbeat=db.execute("SELECT updated_at,value FROM sentinel_health WHERE key='heartbeat'").fetchone()
            heartbeat_age=None
            heartbeat_state='unknown'
            if heartbeat:
                try:
                    heartbeat_age=(datetime.now(timezone.utc)-datetime.fromisoformat(str(heartbeat['updated_at']).replace('Z','+00:00'))).total_seconds()
                except ValueError:
                    heartbeat_age=None
                payload=_loads(heartbeat['value'],{})
                if isinstance(payload,dict): heartbeat_state=str(payload.get('state') or 'unknown')
            # A deliberately stopped monitor is a valid runtime state; it is not
            # a stale-heartbeat failure. A running monitor must keep heartbeating.
            checks['heartbeat'] = heartbeat_state == 'stopped' or (heartbeat_age is not None and 0 <= heartbeat_age < 120)
            return {"checks":checks,"healthy":all(checks.values()),"heartbeat_age_seconds":heartbeat_age,"heartbeat_state":heartbeat_state,"checked_at":now_iso()}

    def export_json(self) -> dict[str, Any]:
        return {
            "generated_at": now_iso(),
            "alerts": self.alerts(),
            "incidents": self.incidents(),
            "audit": self.audit_entries(),
            "bulk_operations": self.bulk_history(),
            "delivery": self.delivery_history(),
            "domains": self.domain_intelligence(),
        }

    def alerts(self, limit: int = 10000) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows=[dict(r) for r in db.execute(
                """SELECT a.*,m.severity,m.risk_score,m.risk_factors,m.correlation_id,m.anomaly_score,m.domain_risk
                   FROM alerts a LEFT JOIN alert_metadata m ON m.alert_id=a.id ORDER BY a.id DESC LIMIT ?""",(limit,)
            ).fetchall()]
            for row in rows:
                row['risk_factors']=_loads(row.get('risk_factors'),[])
            return rows

    def domain_intelligence(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows=[dict(r) for r in db.execute("SELECT * FROM domain_intelligence ORDER BY score DESC,last_seen_at DESC LIMIT ?",(limit,)).fetchall()]
            for row in rows:
                row['factors']=_loads(row.get('factors'),[])
            return rows

    def export_csv(self) -> str:
        rows=self.alerts(10000)
        if not rows:
            return "id,profile_id,domain,reason,severity,risk_score,notification_status,created_at\\n"
        fields=['id','profile_id','account_name','domain','matched_domain','alert_type','status','reason',
                'device_id','device_name','device_model','client_ip','event_timestamp',
                'severity','risk_score','domain_risk','anomaly_score','notification_status','seen_at','created_at']
        output=io.StringIO()
        writer=csv.DictWriter(output,fieldnames=fields,extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)
        return output.getvalue()

    def update_baseline(self, profile_id: str, event_time: str) -> None:
        try:
            dt=datetime.fromisoformat(str(event_time).replace('Z','+00:00'))
        except ValueError:
            dt=datetime.now(timezone.utc)
        bucket_day=dt.astimezone(timezone.utc).strftime('%Y-%m-%d')
        bucket=dt.astimezone(timezone.utc).strftime('%H')
        with self._connect() as db:
            row=db.execute(
                "SELECT count FROM anomaly_baseline WHERE profile_id=? AND bucket_day=? AND bucket_hour=?",
                (profile_id,bucket_day,bucket),
            ).fetchone()
            count=int(row['count'])+1 if row else 1
            db.execute(
                "INSERT INTO anomaly_baseline(profile_id,bucket_day,bucket_hour,count,updated_at) VALUES(?,?,?,?,?) "
                "ON CONFLICT(profile_id,bucket_day,bucket_hour) DO UPDATE SET count=excluded.count,updated_at=excluded.updated_at",
                (profile_id,bucket_day,bucket,count,now_iso()),
            )

APP_NAME = "NextDNS Sentinel"
DB_PATH = Path(os.getenv("NEXTDNS_SENTINEL_DB", "data/sentinel.db"))
CONFIG_PATH = Path(os.getenv("NEXTDNS_SENTINEL_CONFIG", "config.json"))
LOG_LEVEL = os.getenv("NEXTDNS_SENTINEL_LOG_LEVEL", "INFO").upper()
HTTP_TIMEOUT = float(os.getenv("NEXTDNS_SENTINEL_HTTP_TIMEOUT", "10"))
CHECK_INTERVAL = max(1, int(os.getenv("NEXTDNS_SENTINEL_INTERVAL", "5")))
INITIAL_LOOKBACK = max(30, int(os.getenv("NEXTDNS_SENTINEL_INITIAL_LOOKBACK", "60")))
POLL_OVERLAP_MS = max(0, int(os.getenv("NEXTDNS_SENTINEL_POLL_OVERLAP_MS", "5000")))
ALERT_COOLDOWN = max(0, int(os.getenv("NEXTDNS_SENTINEL_ALERT_COOLDOWN", "300")))
ALERT_RETENTION_DAYS = max(0, int(os.getenv("NEXTDNS_SENTINEL_ALERT_RETENTION_DAYS", "90")))
API_RETRIES = max(0, int(os.getenv("NEXTDNS_SENTINEL_API_RETRIES", "3")))
NOTIFICATION_RETRY_BASE = max(5, int(os.getenv("NEXTDNS_SENTINEL_NOTIFICATION_RETRY_BASE", "30")))
NOTIFICATION_RETRY_MAX = max(NOTIFICATION_RETRY_BASE, int(os.getenv("NEXTDNS_SENTINEL_NOTIFICATION_RETRY_MAX", "900")))
MAX_NOTIFICATION_ATTEMPTS = max(1, int(os.getenv("NEXTDNS_SENTINEL_MAX_NOTIFICATION_ATTEMPTS", "10")))
DEVICE_INACTIVITY_SECONDS = max(60, int(os.getenv("NEXTDNS_SENTINEL_DEVICE_INACTIVITY_SECONDS", "180")))
SECRET_KEY_FILE = Path(
    os.getenv("NEXTDNS_SENTINEL_SECRET_FILE", "data/.sentinel_secret")
)
ALERT_LOG_PATH = Path(
    os.getenv("NEXTDNS_SENTINEL_ALERT_LOG", "data/recent_alerts.jsonl")
)


def load_or_create_secret_key() -> str:
    env_key = os.getenv("NEXTDNS_SENTINEL_SECRET_KEY", "").strip()
    if env_key:
        return env_key

    SECRET_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        if SECRET_KEY_FILE.exists():
            key = SECRET_KEY_FILE.read_text(encoding="utf-8").strip()
            if key:
                return key

        key = Fernet.generate_key().decode("ascii")
        fd = os.open(SECRET_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, key.encode("ascii"))
        finally:
            os.close(fd)
        return key
    except FileExistsError:
        key = SECRET_KEY_FILE.read_text(encoding="utf-8").strip()
        if key:
            return key
        raise RuntimeError("NEXTDNS_SENTINEL_SECRET_FILE exists but is empty.")


SECRET_KEY = load_or_create_secret_key()


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
        try:
            self.cipher = Fernet(SECRET_KEY.encode())
        except (ValueError, TypeError) as exc:
            raise RuntimeError(
                "The configured NextDNS Sentinel secret key is not a valid Fernet key."
            ) from exc

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
                    alert_type TEXT NOT NULL DEFAULT 'denylist_match',
                    device_id TEXT NOT NULL DEFAULT '',
                    device_name TEXT NOT NULL DEFAULT '',
                    device_model TEXT NOT NULL DEFAULT '',
                    protocol TEXT NOT NULL DEFAULT '',
                    encrypted INTEGER NOT NULL DEFAULT 0,
                    source TEXT NOT NULL DEFAULT 'nextdns_logs',
                    seen_at TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    notified_at TEXT NOT NULL DEFAULT '',
                    notification_status TEXT NOT NULL DEFAULT 'pending',
                    notification_attempts INTEGER NOT NULL DEFAULT 0,
                    last_notification_attempt_at TEXT NOT NULL DEFAULT '',
                    next_retry_at TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS notification_state (
                    alert_id INTEGER PRIMARY KEY,
                    state TEXT NOT NULL DEFAULT 'created',
                    created_at TEXT NOT NULL,
                    sent_at TEXT NOT NULL DEFAULT '',
                    seen_at TEXT NOT NULL DEFAULT ''
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
                    last_error_at TEXT NOT NULL DEFAULT '',
                    consecutive_failures INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                
                CREATE TABLE IF NOT EXISTS telegram_bots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL DEFAULT 'Telegram Bot',
                    token TEXT NOT NULL,
                    chat_id TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    bot_username TEXT NOT NULL DEFAULT '',
                    bot_name TEXT NOT NULL DEFAULT '',
                    chat_title TEXT NOT NULL DEFAULT '',
                    last_notification_at TEXT NOT NULL DEFAULT '',
                    last_error TEXT NOT NULL DEFAULT '',
                    added_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            self._migrate_alert_columns(db)
            columns = {row[1] for row in db.execute("PRAGMA table_info(monitor_state)")}
            if "consecutive_failures" not in columns:
                db.execute("ALTER TABLE monitor_state ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0")
            db.execute("""
                CREATE TABLE IF NOT EXISTS config_snapshots (
                    profile_id TEXT PRIMARY KEY,
                    snapshot TEXT NOT NULL,
                    captured_at TEXT NOT NULL
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS config_changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    profile_id TEXT NOT NULL,
                    change_type TEXT NOT NULL,
                    before_json TEXT NOT NULL,
                    after_json TEXT NOT NULL,
                    changed_at TEXT NOT NULL,
                    undone_at TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL DEFAULT 'unknown'
                )
            """)
            db.execute("DELETE FROM config_snapshots WHERE rowid NOT IN (SELECT MAX(rowid) FROM config_snapshots GROUP BY profile_id)")
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_config_snapshots_profile_unique ON config_snapshots(profile_id)")
            config_change_columns={row[1] for row in db.execute("PRAGMA table_info(config_changes)")}
            if "source" not in config_change_columns:
                db.execute("ALTER TABLE config_changes ADD COLUMN source TEXT NOT NULL DEFAULT 'unknown'")



    def _migrate_alert_columns(self, db: sqlite3.Connection) -> None:
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
        for column, definition in {
            "alert_type": "TEXT NOT NULL DEFAULT 'denylist_match'",
            "device_id": "TEXT NOT NULL DEFAULT ''",
            "device_name": "TEXT NOT NULL DEFAULT ''",
            "device_model": "TEXT NOT NULL DEFAULT ''",
            "protocol": "TEXT NOT NULL DEFAULT ''",
            "encrypted": "INTEGER NOT NULL DEFAULT 0",
            "source": "TEXT NOT NULL DEFAULT 'nextdns_logs'",
            "seen_at": "TEXT NOT NULL DEFAULT ''",
        }.items():
            if column not in columns:
                db.execute(f"ALTER TABLE alerts ADD COLUMN {column} {definition}")
        db.execute("""
            INSERT OR IGNORE INTO notification_state(alert_id,state,created_at,sent_at,seen_at)
            SELECT id,
                   CASE
                     WHEN seen_at<>'' THEN 'seen'
                     WHEN notified_at<>'' OR notification_status IN ('sent','suppressed') THEN 'sent'
                     ELSE 'created'
                   END,
                   created_at,
                   notified_at,
                   seen_at
            FROM alerts
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS device_state (
                profile_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                device_name TEXT NOT NULL DEFAULT '',
                device_model TEXT NOT NULL DEFAULT '',
                client_ip TEXT NOT NULL DEFAULT '',
                last_seen_at TEXT NOT NULL DEFAULT '',
                last_status TEXT NOT NULL DEFAULT '',
                last_domain TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL,
                inactive_alerted_at TEXT NOT NULL DEFAULT '',
                PRIMARY KEY(profile_id, device_id)
            )
        """)
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='telegram_bots'").fetchone():
            existing=db.execute("SELECT COUNT(*) FROM telegram_bots").fetchone()[0]
            legacy_token=self.get_secret("telegram_token")
            legacy_chat=self.get_secret("telegram_chat_id")
            if not existing and legacy_token and legacy_chat:
                now=utc_now()
                db.execute("INSERT INTO telegram_bots(name,token,chat_id,enabled,bot_username,bot_name,chat_title,last_notification_at,last_error,added_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                           ("Telegram Bot",self.cipher.encrypt(legacy_token.encode()).decode(),self.cipher.encrypt(legacy_chat.encode()).decode(),
                            int(self.get_setting("telegram_enabled","1")=="1"),self.get_setting("telegram_bot_username",""),
                            self.get_setting("telegram_bot_name",""),self.get_setting("telegram_chat_title",""),"",
                            self.get_setting("telegram_last_error",""),now,now))
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='denylist'").fetchone():
            db.execute("DELETE FROM denylist WHERE rowid NOT IN (SELECT MAX(rowid) FROM denylist GROUP BY profile_id,domain)")
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_denylist_profile_domain_unique ON denylist(profile_id,domain)")

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

    def telegram_destinations(self) -> list[dict[str, Any]]:
        return [bot for bot in self.telegram_bots() if bot.get("enabled") and bot.get("token") and bot.get("chat_id")]

    def telegram_bots(self) -> list[dict[str, Any]]:
        with sqlite3.connect(self.path) as db:
            db.row_factory=sqlite3.Row
            rows=[dict(r) for r in db.execute("SELECT * FROM telegram_bots ORDER BY id").fetchall()]
        result=[]
        for row in rows:
            try:
                row["token"]=self.cipher.decrypt(row["token"].encode()).decode()
                row["chat_id"]=self.cipher.decrypt(row["chat_id"].encode()).decode()
            except InvalidToken:
                row["token"]=""; row["chat_id"]=""; row["last_error"]="Stored Telegram credentials could not be decrypted."
            row["enabled"]=bool(row["enabled"])
            result.append(row)
        return result

    def save_telegram_bot(self, bot_id: int | None, name: str, token: str, chat_id: str,
                          enabled: bool = True, identity: dict[str, Any] | None = None) -> int:
        identity=identity or {}
        bot=identity.get("bot") if isinstance(identity.get("bot"),dict) else {}
        chat=identity.get("chat") if isinstance(identity.get("chat"),dict) else {}
        now=utc_now()
        encrypted_token=self.cipher.encrypt(token.encode()).decode()
        encrypted_chat=self.cipher.encrypt(chat_id.encode()).decode()
        with sqlite3.connect(self.path) as db:
            if bot_id:
                db.execute("UPDATE telegram_bots SET name=?,token=?,chat_id=?,enabled=?,bot_username=?,bot_name=?,chat_title=?,updated_at=? WHERE id=?",
                           (name or "Telegram Bot",encrypted_token,encrypted_chat,int(enabled),
                            str(bot.get("username") or ""),str(bot.get("first_name") or ""),
                            str(chat.get("title") or chat.get("first_name") or chat.get("username") or ""),now,bot_id))
                return int(bot_id)
            cur=db.execute("INSERT INTO telegram_bots(name,token,chat_id,enabled,bot_username,bot_name,chat_title,added_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                           (name or "Telegram Bot",encrypted_token,encrypted_chat,int(enabled),
                            str(bot.get("username") or ""),str(bot.get("first_name") or ""),
                            str(chat.get("title") or chat.get("first_name") or chat.get("username") or ""),now,now))
            return int(cur.lastrowid)

    def set_telegram_bot_enabled(self, bot_id: int, enabled: bool) -> bool:
        with sqlite3.connect(self.path) as db:
            cur=db.execute("UPDATE telegram_bots SET enabled=?,updated_at=? WHERE id=?",(int(enabled),utc_now(),bot_id))
            return cur.rowcount>0

    def delete_telegram_bot(self, bot_id: int) -> bool:
        with sqlite3.connect(self.path) as db:
            cur=db.execute("DELETE FROM telegram_bots WHERE id=?",(bot_id,))
            return cur.rowcount>0

    def mark_telegram_bot_result(self, bot_id: int, ok: bool, error: str = "") -> None:
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE telegram_bots SET last_notification_at=?,last_error=?,updated_at=? WHERE id=?",
                       (utc_now() if ok else "", "" if ok else error, utc_now(), bot_id))

    def set_setting(self, key: str, value: str) -> None:
        with sqlite3.connect(self.path) as db:
            db.execute(
                "INSERT INTO settings(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def get_setting(self, key: str, default: str = "") -> str:
        with sqlite3.connect(self.path) as db:
            row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return str(row[0]) if row else default

    def setting(self, key: str, default: str = "") -> str:
        return self.get_setting(key, default)

    def save_alert_logs_enabled(self) -> bool:
        return self.get_setting("save_alert_logs", "true").lower() == "true"

    def set_save_alert_logs_enabled(self, enabled: bool) -> None:
        self.set_setting("save_alert_logs", "true" if enabled else "false")

    def export_alerts_to_file(self) -> int:
        ALERT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        alerts = self.recent_alerts(limit=1000000)
        with ALERT_LOG_PATH.open("w", encoding="utf-8") as handle:
            for alert in reversed(alerts):
                handle.write(json.dumps(alert, ensure_ascii=False, default=str) + "\n")
        return len(alerts)

    def append_alert_to_file(self, alert: dict[str, Any]) -> None:
        ALERT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with ALERT_LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(alert, ensure_ascii=False, default=str) + "\n")

    def set_secret(self, key: str, value: str) -> None:
        encrypted = self.cipher.encrypt(value.encode()).decode()
        with sqlite3.connect(self.path) as db:
            db.execute(
                "INSERT INTO settings(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, encrypted),
            )

    def get_secret(self, key: str) -> str:
        with sqlite3.connect(self.path) as db:
            row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        if not row:
            return ""
        try:
            return self.cipher.decrypt(row[0].encode()).decode()
        except InvalidToken as exc:
            raise RuntimeError(
                "Unable to decrypt stored settings. Verify the NextDNS Sentinel secret key."
            ) from exc

    def delete_secret(self, key: str) -> None:
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM settings WHERE key=?", (key,))

    def set_account_active(self, profile_id: str, active: bool) -> None:
        with sqlite3.connect(self.path) as db:
            db.execute(
                "UPDATE accounts SET active=? WHERE profile_id=?",
                (int(active), profile_id),
            )

    def delete_account(self, profile_id: str) -> None:
        with sqlite3.connect(self.path) as db:
            alert_ids=[row[0] for row in db.execute("SELECT id FROM alerts WHERE profile_id=?", (profile_id,)).fetchall()]
            if alert_ids:
                placeholders=",".join("?" for _ in alert_ids)
                db.execute(f"DELETE FROM alert_metadata WHERE alert_id IN ({placeholders})", alert_ids)
                db.execute(f"DELETE FROM incident_alerts WHERE alert_id IN ({placeholders})", alert_ids)
                db.execute(f"DELETE FROM delivery_events WHERE alert_id IN ({placeholders})", alert_ids)
                db.execute(f"DELETE FROM escalation_events WHERE alert_id IN ({placeholders})", alert_ids)
            db.execute("DELETE FROM incidents WHERE profile_id=?", (profile_id,))
            db.execute("DELETE FROM alerts WHERE profile_id=?", (profile_id,))
            db.execute("DELETE FROM audit_log WHERE profile_id=?", (profile_id,))
            db.execute("DELETE FROM anomaly_baseline WHERE profile_id=?", (profile_id,))
            db.execute("DELETE FROM device_state WHERE profile_id=?", (profile_id,))
            db.execute("DELETE FROM config_changes WHERE profile_id=?", (profile_id,))
            db.execute("DELETE FROM config_snapshots WHERE profile_id=?", (profile_id,))
            db.execute("DELETE FROM denylist WHERE profile_id=?", (profile_id,))
            db.execute("DELETE FROM monitor_state WHERE profile_id=?", (profile_id,))
            db.execute("DELETE FROM accounts WHERE profile_id=?", (profile_id,))

    def account_exists(self, profile_id: str) -> bool:
        with sqlite3.connect(self.path) as db:
            return db.execute(
                "SELECT 1 FROM accounts WHERE profile_id=?", (profile_id,)
            ).fetchone() is not None

    def denylist_entries(self, profile_id: str) -> list[str]:
        with sqlite3.connect(self.path) as db:
            return [
                row[0]
                for row in db.execute(
                    "SELECT domain FROM denylist WHERE profile_id=? ORDER BY domain",
                    (profile_id,),
                )
            ]

    def config_snapshot(self, profile_id: str) -> dict[str,Any] | None:
        with sqlite3.connect(self.path) as db:
            row=db.execute("SELECT snapshot FROM config_snapshots WHERE profile_id=?",(profile_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def save_config_snapshot(self, profile_id: str, snapshot: dict[str,Any]) -> None:
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO config_snapshots(profile_id,snapshot,captured_at) VALUES(?,?,?) ON CONFLICT(profile_id) DO UPDATE SET snapshot=excluded.snapshot,captured_at=excluded.captured_at",(profile_id,json.dumps(snapshot,sort_keys=True,separators=(',',':')),utc_now()))

    def add_config_change(self, profile_id: str, before: dict[str,Any], after: dict[str,Any], change_type: str, source: str = "unknown") -> int:
        with sqlite3.connect(self.path) as db:
            cur=db.execute("INSERT INTO config_changes(profile_id,change_type,before_json,after_json,changed_at,source) VALUES(?,?,?,?,?,?)",(profile_id,change_type,json.dumps(before,sort_keys=True),json.dumps(after,sort_keys=True),utc_now(),source))
            return int(cur.lastrowid)

    def config_changes(self, limit:int=50) -> list[dict[str,Any]]:
        with sqlite3.connect(self.path) as db:
            db.row_factory=sqlite3.Row
            return [dict(r) for r in db.execute("SELECT id,profile_id,change_type,before_json,after_json,changed_at,undone_at,source FROM config_changes ORDER BY id DESC LIMIT ?",(limit,))]

    def mark_change_undone(self, change_id:int) -> None:
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE config_changes SET undone_at=? WHERE id=?",(utc_now(),change_id))

    def mark_alert_seen(self, alert_id: int) -> bool:
        with sqlite3.connect(self.path) as db:
            now=utc_now()
            cur=db.execute("UPDATE alerts SET seen_at=? WHERE id=? AND seen_at=''",(now,alert_id))
            if cur.rowcount:
                db.execute("UPDATE notification_state SET state='seen',seen_at=? WHERE alert_id=?",(now,alert_id))
            return cur.rowcount>0

    def update_device_state(self, profile_id: str, device_id: str, device_name: str,
                            device_model: str, client_ip: str, last_seen_at: str,
                            last_status: str, last_domain: str) -> None:
        device_id=device_id or "__UNIDENTIFIED__"
        with sqlite3.connect(self.path) as db:
            db.execute("""
                INSERT INTO device_state(profile_id,device_id,device_name,device_model,client_ip,last_seen_at,last_status,last_domain,updated_at,inactive_alerted_at)
                VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(profile_id,device_id) DO UPDATE SET
                  device_name=excluded.device_name,device_model=excluded.device_model,
                  client_ip=excluded.client_ip,last_seen_at=CASE WHEN excluded.last_seen_at<>'' THEN excluded.last_seen_at ELSE device_state.last_seen_at END,
                  last_status=excluded.last_status,last_domain=excluded.last_domain,updated_at=excluded.updated_at,
                  inactive_alerted_at=CASE WHEN excluded.last_seen_at<>'' THEN '' ELSE device_state.inactive_alerted_at END
            """,(profile_id,device_id,device_name,device_model,client_ip,last_seen_at,last_status,last_domain,utc_now(),""))

    def mark_device_inactive_alerted(self, profile_id: str, device_id: str) -> bool:
        with sqlite3.connect(self.path) as db:
            cur=db.execute("UPDATE device_state SET inactive_alerted_at=? WHERE profile_id=? AND device_id=? AND inactive_alerted_at=''",(utc_now(),profile_id,device_id))
            return cur.rowcount>0

    def device_states(self) -> list[dict[str, Any]]:
        with sqlite3.connect(self.path) as db:
            db.row_factory=sqlite3.Row
            rows=[dict(r) for r in db.execute("""
                SELECT d.*,
                       a.name AS account_name,
                       (SELECT COUNT(*) FROM alerts al WHERE al.profile_id=d.profile_id AND al.device_id=d.device_id) AS alert_count,
                       (SELECT COUNT(*) FROM denylist dl WHERE dl.profile_id=d.profile_id) AS denylist_count,
                       (SELECT COUNT(*) FROM alerts al WHERE al.profile_id=d.profile_id AND al.device_id=d.device_id AND al.alert_type='denylist_match') AS blocked_count
                FROM device_state d
                LEFT JOIN accounts a ON a.profile_id=d.profile_id
                ORDER BY a.name,d.device_name,d.device_id
            """)]
            return rows

    def update_device_properties(self, profile_id: str, device_id: str, data: dict[str, Any]) -> bool:
        allowed={"device_name","device_model","client_ip","last_seen_at","last_status","last_domain","inactive_alerted_at"}
        fields=[key for key in data if key in allowed]
        if not fields:return False
        assignments=",".join(f"{key}=?" for key in fields)
        values=[str(data[key] or "") for key in fields]+[utc_now(),profile_id,device_id]
        with sqlite3.connect(self.path) as db:
            cur=db.execute(f"UPDATE device_state SET {assignments},updated_at=? WHERE profile_id=? AND device_id=?",values)
            return cur.rowcount>0

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
        alert_type: str = "denylist_match",
        device_id: str = "",
        device_name: str = "",
        device_model: str = "",
        protocol: str = "",
        encrypted: bool = False,
        source: str = "nextdns_logs",
    ) -> bool:
        try:
            with sqlite3.connect(self.path) as db:
                db.execute(
                    """
                    INSERT INTO alerts(
                        profile_id,account_name,domain,matched_domain,reason,status,
                        client_ip,event_timestamp,event_key,alert_type,device_id,device_name,
                        device_model,protocol,encrypted,source,created_at
                    )
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
                        alert_type, device_id, device_name, device_model, protocol,
                        int(encrypted), source, utc_now(),
                    ),
                )
                alert_row=db.execute("SELECT id,created_at FROM alerts WHERE event_key=?", (event_key,)).fetchone()
                if alert_row:
                    db.execute(
                        "INSERT OR IGNORE INTO notification_state(alert_id,state,created_at) VALUES(?,?,?)",
                        (alert_row[0],"created",alert_row[1]),
                    )
            if self.save_alert_logs_enabled():
                self.append_alert_to_file(
                    {
                        "profile_id": profile_id,
                        "account_name": account_name,
                        "domain": domain,
                        "matched_domain": matched_domain,
                        "reason": reason,
                        "status": status,
                        "client_ip": client_ip,
                        "event_timestamp": event_timestamp,
                        "event_key": event_key,
                        "created_at": utc_now(),
                    }
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
                WHERE profile_id=? AND domain=? AND notified_at>=?
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
            db.execute("""
                UPDATE notification_state
                SET state=CASE WHEN seen_at<>'' THEN 'seen' ELSE 'sent' END,
                    sent_at=?
                WHERE alert_id=(SELECT id FROM alerts WHERE event_key=?)
            """,(utc_now(),event_key))

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
            notification_status = (
                "failed" if attempts >= MAX_NOTIFICATION_ATTEMPTS else "pending"
            )
            db.execute(
                """
                UPDATE alerts
                SET notification_attempts=?,
                    last_notification_attempt_at=?,
                    next_retry_at=?,
                    notification_status=?
                WHERE event_key=? AND notification_status='pending'
                """,
                (
                    attempts,
                    now.isoformat(),
                    next_retry_at if notification_status == "pending" else "",
                    notification_status,
                    event_key,
                ),
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
                WHERE created_at<?
                  AND notification_status IN ('sent','suppressed','failed')
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
                    SELECT id,event_key,account_name,domain,matched_domain,reason,status,
                           client_ip,event_timestamp,device_id,device_name,device_model,protocol,encrypted
                    FROM alerts a
                    JOIN notification_state ns ON ns.alert_id=a.id
                    WHERE a.profile_id=? AND a.notified_at=''
                      AND a.notification_status='pending'
                      AND ns.state='created'
                      AND (a.next_retry_at='' OR a.next_retry_at<=?)
                    ORDER BY a.id ASC LIMIT ?
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
                INSERT INTO monitor_state(profile_id,last_poll_ms,last_success_at,last_error,last_error_at,consecutive_failures)
                VALUES(?,?,?,?,?,?)
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
                    END,
                    consecutive_failures=CASE
                        WHEN excluded.last_error='' THEN 0
                        ELSE monitor_state.consecutive_failures+1
                    END
                """,
                (profile_id, last_poll_ms, utc_now() if not error else "", error, utc_now() if error else "", 1 if error else 0),
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
                SELECT last_success_at,last_error,last_error_at
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
                "last_error_at": (
                    db.execute(
                        """
                        SELECT last_error_at
                        FROM monitor_state
                        WHERE last_error<>''
                        ORDER BY last_error_at DESC
                        LIMIT 1
                        """
                    ).fetchone()[0]
                    if error_state else ""
                ),
                "poll_interval_seconds": CHECK_INTERVAL,
            }

    def alert_analytics(self, hours: int = 24) -> dict[str, Any]:
        hours=max(1,min(720,int(hours)))
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=hours)
        start_iso = start.isoformat()
        with sqlite3.connect(self.path) as db:
            rows = db.execute(
                """
                SELECT COALESCE(NULLIF(event_timestamp,''),created_at),domain,status
                FROM alerts
                WHERE (
                    (event_timestamp >= ? AND event_timestamp <> '')
                    OR (event_timestamp = '' AND created_at >= ?)
                )
                ORDER BY created_at ASC
                """,
                (start_iso, start_iso),
            ).fetchall()
        buckets: dict[str, int] = {}
        for i in range(hours):
            bucket = (start.replace(minute=0, second=0, microsecond=0) + timedelta(hours=i)).isoformat()
            buckets[bucket] = 0
        status_counts: dict[str, int] = {}
        domains: dict[str, int] = {}
        for event_timestamp, domain, status in rows:
            try:
                event_dt = datetime.fromisoformat(str(event_timestamp).replace("Z", "+00:00"))
                hour = event_dt.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0).isoformat()
                if hour in buckets:
                    buckets[hour] += 1
            except (TypeError, ValueError):
                pass
            status_key = str(status or "unknown")
            status_counts[status_key] = status_counts.get(status_key, 0) + 1
            domain_key = str(domain or "unknown")
            domains[domain_key] = domains.get(domain_key, 0) + 1
        top_domains = sorted(domains.items(), key=lambda item: (-item[1], item[0]))[:12]
        profile_rows: dict[str, dict[str, Any]] = {}
        with sqlite3.connect(self.path) as db:
            db.row_factory = sqlite3.Row
            detail_rows = db.execute("""SELECT a.profile_id,a.account_name,a.domain,a.status,a.alert_type,a.reason,a.device_name,a.device_id,a.event_timestamp,a.created_at,COALESCE(m.severity,'') severity,COALESCE(m.risk_score,0) risk_score,COALESCE(m.domain_risk,'') domain_risk FROM alerts a LEFT JOIN alert_metadata m ON m.alert_id=a.id WHERE ((a.event_timestamp>=? AND a.event_timestamp<>'') OR (a.event_timestamp='' AND a.created_at>=?)) ORDER BY COALESCE(NULLIF(a.event_timestamp,''),a.created_at) DESC""",(start_iso,start_iso)).fetchall()
        for row in detail_rows:
            pid=str(row["profile_id"] or "unknown")
            item=profile_rows.setdefault(pid,{"profile_id":pid,"account_name":str(row["account_name"] or pid),"total_alerts":0,"blocked_count":0,"status_counts":{},"domains":{},"recent_events":[]})
            item["total_alerts"]+=1
            if str(row["alert_type"] or "")=="denylist_match": item["blocked_count"]+=1
            sk=str(row["status"] or "unknown");item["status_counts"][sk]=item["status_counts"].get(sk,0)+1
            dk=str(row["domain"] or "unknown");item["domains"][dk]=item["domains"].get(dk,0)+1
            if len(item["recent_events"])<25:item["recent_events"].append(dict(row))
        for item in profile_rows.values():
            item["top_domains"]=[{"domain":k,"count":v} for k,v in sorted(item["domains"].items(),key=lambda x:(-x[1],x[0]))[:10]]
            item["statuses"]=[{"status":k,"count":v} for k,v in sorted(item["status_counts"].items(),key=lambda x:(-x[1],x[0]))]
            item.pop("domains",None);item.pop("status_counts",None)
        return {"timeline":[{"time":key,"count":value} for key,value in buckets.items()],"statuses":status_counts,"top_domains":[{"domain":key,"count":value} for key,value in top_domains],"profiles":sorted(profile_rows.values(),key=lambda x:(-x["total_alerts"],x["account_name"].lower())),"total_24h":len(rows)}

    def monitor_health(self) -> list[dict[str, Any]]:
        with sqlite3.connect(self.path) as db:
            db.row_factory = sqlite3.Row
            return [
                dict(r)
                for r in db.execute(
                    """
                    SELECT a.profile_id,a.name,a.active,
                           s.last_poll_ms,s.last_success_at,s.last_error,s.last_error_at,
                           COALESCE(s.consecutive_failures,0) AS consecutive_failures,
                           CASE
                             WHEN a.active=0 THEN 'disabled'
                             WHEN COALESCE(s.consecutive_failures,0)>=3 THEN 'degraded'
                             WHEN s.last_success_at<>'' THEN 'healthy'
                             ELSE 'starting'
                           END AS status
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
                    SELECT id,profile_id,account_name,domain,matched_domain,reason,status,client_ip,event_timestamp,
                           alert_type,device_id,device_name,device_model,protocol,encrypted,source,seen_at,
                           created_at,notified_at,notification_status,notification_attempts,last_notification_attempt_at,next_retry_at
                    FROM alerts ORDER BY id DESC LIMIT ?
                    """,
                    (limit,),
                )
            ]


    def alert_policy(self, profile_id: str, domain: str, device_id: str, alert_type: str) -> dict[str, Any]:
        fingerprint=hashlib.sha256(f"{profile_id}|{domain}|{device_id}|{alert_type}".encode()).hexdigest()
        maintenance=self.maintenance_active(profile_id)
        suppression=self.suppression_active(fingerprint)
        decision={"fingerprint":fingerprint,"suppressed":bool(maintenance or suppression),"maintenance":maintenance,"suppression":suppression,"escalate":False}
        for rule in self.rules(True):
            match=rule.get("rule") or {}; matched=True
            for key,value in match.items():
                if key in {"action","severity","cooldown_seconds","name"}: continue
                actual={"profile_id":profile_id,"domain":domain,"device_id":device_id,"alert_type":alert_type}.get(key)
                if actual is None or str(actual).lower()!=str(value).lower(): matched=False; break
            if matched:
                action=str(match.get("action","")).lower()
                if action in {"suppress","ignore"}: decision["suppressed"]=True
                if action=="escalate": decision["escalate"]=True
                cooldown=match.get("cooldown_seconds")
                if cooldown:
                    self.add_suppression(fingerprint,int(cooldown),"Rule: "+rule["name"]); decision["suppressed"]=True
        return decision
    def export_settings(self) -> dict[str, Any]:
        # Export only portable, non-secret settings. Authentication hashes and
        # credential material must never be copied by this feature.
        excluded_keys = {"api_auth_hash", "api_auth_token", "telegram_token", "telegram_chat_id"}
        with self._connect() as db:
            rows=db.execute("SELECT key,value,updated_at FROM sentinel_settings ORDER BY key").fetchall()
            rules=db.execute("SELECT id,name,enabled,rule_json,created_at,updated_at FROM alert_rules ORDER BY id").fetchall()
        settings = [dict(r) for r in rows if r["key"] not in excluded_keys and "token" not in r["key"].lower() and "api_key" not in r["key"].lower()]
        return {"version":1,"exported_at":now_iso(),"settings":settings,"rules":[{**dict(r),"rule":_loads(r["rule_json"],{})} for r in rules]}

    def import_settings(self, payload: dict[str, Any]) -> dict[str, int]:
        if not isinstance(payload, dict) or payload.get("version", 1) != 1:
            raise ValueError("Unsupported settings document version.")
        imported_settings=0; imported_rules=0
        settings = payload.get("settings", [])
        rules = payload.get("rules", [])
        if not isinstance(settings, list) or not isinstance(rules, list):
            raise ValueError("Invalid settings document structure.")
        with self._connect() as db:
            for item in settings:
                if not isinstance(item, dict): continue
                key=str(item.get("key","")).strip()
                if not key or key in {"api_auth_hash","api_auth_token","telegram_token","telegram_chat_id"} or "token" in key.lower() or "api_key" in key.lower(): continue
                db.execute("INSERT INTO sentinel_settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",(key,str(item.get("value","")),now_iso())); imported_settings+=1
            for item in rules:
                if not isinstance(item, dict): continue
                name=str(item.get("name","")).strip()
                rule=item.get("rule") or {}
                if not name or not isinstance(rule, dict): continue
                rule_id=item.get("id")
                if isinstance(rule_id, int) and rule_id > 0:
                    existing=db.execute("SELECT id FROM alert_rules WHERE id=?",(rule_id,)).fetchone()
                else:
                    existing=None
                if existing:
                    db.execute("UPDATE alert_rules SET name=?,enabled=?,rule_json=?,updated_at=? WHERE id=?",(name,int(bool(item.get("enabled",True))),json.dumps(rule),now_iso(),rule_id))
                else:
                    db.execute("INSERT INTO alert_rules(name,enabled,rule_json,created_at,updated_at) VALUES(?,?,?,?,?)",(name,int(bool(item.get("enabled",True))),json.dumps(rule),now_iso(),now_iso()))
                imported_rules+=1
        return {"settings":imported_settings,"rules":imported_rules}

    def incident_metrics(self) -> dict[str, Any]:
        with self._connect() as db:
            total=db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
            open_count=db.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('open','investigating')").fetchone()[0]
            resolved=db.execute("SELECT COUNT(*) FROM incidents WHERE status='resolved'").fetchone()[0]
            avg_row=db.execute("SELECT AVG((julianday(resolved_at)-julianday(first_seen_at))*86400) FROM incidents WHERE status='resolved' AND resolved_at<>''").fetchone()
            alert_count=db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        return {"total_incidents":total,"open_incidents":open_count,"resolved_incidents":resolved,"mean_time_to_resolve_seconds":round(float(avg_row[0] or 0),1),"total_alerts":alert_count}

    def config_diff(self, profile_id: str) -> dict[str, Any]:
        with self._connect() as db:
            row=db.execute("SELECT before_json,after_json,change_type,created_at,undone_at FROM config_changes WHERE profile_id=? ORDER BY id DESC LIMIT 1",(profile_id,)).fetchone()
        if not row: return {"profile_id":profile_id,"changed":False,"diff":[]}
        before=_loads(row["before_json"],{}); after=_loads(row["after_json"],{}); diff=[]
        for key in sorted(set(before)|set(after)):
            if before.get(key)!=after.get(key): diff.append({"field":key,"before":before.get(key),"after":after.get(key)})
        return {"profile_id":profile_id,"changed":bool(diff),"diff":diff,"change_type":row["change_type"],"created_at":row["created_at"],"undone_at":row["undone_at"]}

    def risk_history(self, profile_id: str = "", days: int = 30) -> list[dict[str, Any]]:
        cutoff=(datetime.now(timezone.utc)-timedelta(days=max(1,min(365,int(days))))).isoformat()
        with self._connect() as db:
            if profile_id:
                rows=db.execute("SELECT substr(a.created_at,1,10) day,AVG(m.risk_score) avg_risk,MAX(m.risk_score) max_risk,COUNT(*) alerts FROM alerts a JOIN alert_metadata m ON m.alert_id=a.id WHERE a.profile_id=? AND a.created_at>=? GROUP BY day ORDER BY day",(profile_id,cutoff)).fetchall()
            else:
                rows=db.execute("SELECT substr(a.created_at,1,10) day,AVG(m.risk_score) avg_risk,MAX(m.risk_score) max_risk,COUNT(*) alerts FROM alerts a JOIN alert_metadata m ON m.alert_id=a.id WHERE a.created_at>=? GROUP BY day ORDER BY day",(cutoff,)).fetchall()
        return [dict(r) for r in rows]

    def baseline_view(self, profile_id: str = "") -> list[dict[str, Any]]:
        with self._connect() as db:
            if profile_id: rows=db.execute("SELECT bucket_hour,AVG(count) baseline,MAX(count) peak FROM anomaly_baseline WHERE profile_id=? GROUP BY bucket_hour ORDER BY bucket_hour",(profile_id,)).fetchall()
            else: rows=db.execute("SELECT bucket_hour,AVG(count) baseline,MAX(count) peak FROM anomaly_baseline GROUP BY bucket_hour ORDER BY bucket_hour").fetchall()
        return [dict(r) for r in rows]
    def live_snapshot(self) -> dict[str, Any]:
        return {"generated_at":now_iso(),"health":self.health(),"incidents":self.incidents(limit=10),"metrics":self.incident_metrics()}

    def rules(self, enabled_only=False):
        q="SELECT * FROM alert_rules"
        if enabled_only: q+=" WHERE enabled=1"
        q+=" ORDER BY id DESC"
        with self._connect() as db:
            rows=[dict(r) for r in db.execute(q).fetchall()]
        for r in rows: r["rule"]=_loads(r.pop("rule_json"),{})
        return rows

    def save_rule(self, rule_id, name, rule, enabled=True):
        with self._connect() as db:
            if rule_id:
                db.execute("UPDATE alert_rules SET name=?,enabled=?,rule_json=?,updated_at=? WHERE id=?",(name,int(enabled),json.dumps(rule),now_iso(),rule_id))
                return int(rule_id)
            cur=db.execute("INSERT INTO alert_rules(name,enabled,rule_json,created_at,updated_at) VALUES(?,?,?,?,?)",(name,int(enabled),json.dumps(rule),now_iso(),now_iso()))
            return int(cur.lastrowid)

    def delete_rule(self, rule_id):
        with self._connect() as db: return db.execute("DELETE FROM alert_rules WHERE id=?",(rule_id,)).rowcount>0

    def maintenance_active(self, profile_id=""):
        now=now_iso()
        with self._connect() as db:
            row=db.execute("SELECT * FROM maintenance_windows WHERE starts_at<=? AND ends_at>=? AND (scope='global' OR profile_id=?) ORDER BY ends_at DESC LIMIT 1",(now,now,profile_id)).fetchone()
        return dict(row) if row else None

    def suppression_active(self, fingerprint):
        now=now_iso()
        with self._connect() as db:
            row=db.execute("SELECT * FROM alert_suppressions WHERE fingerprint=? AND until_at>=? ORDER BY until_at DESC LIMIT 1",(fingerprint,now)).fetchone()
        return dict(row) if row else None

    def add_suppression(self,fingerprint,seconds,reason=""):
        until=(datetime.now(timezone.utc)+timedelta(seconds=max(1,int(seconds)))).isoformat()
        with self._connect() as db:
            cur=db.execute("INSERT INTO alert_suppressions(fingerprint,reason,until_at,created_at) VALUES(?,?,?,?)",(fingerprint,reason,until,now_iso()))
        return int(cur.lastrowid)

    def add_maintenance(self,scope,profile_id,seconds,reason=""):
        start=now_iso(); end=(datetime.now(timezone.utc)+timedelta(seconds=max(1,int(seconds)))).isoformat()
        with self._connect() as db:
            cur=db.execute("INSERT INTO maintenance_windows(scope,profile_id,reason,starts_at,ends_at,created_at) VALUES(?,?,?,?,?,?)",(scope,profile_id,reason,start,end,now_iso()))
        return int(cur.lastrowid)

    def cleanup(self, days):
        days=max(1,int(days)); cutoff=(datetime.now(timezone.utc)-timedelta(days=days)).isoformat()
        with self._connect() as db:
            deleted=0
            for table in ("delivery_events","alerts","audit_log"):
                deleted += db.execute(f"DELETE FROM {table} WHERE created_at<?", (cutoff,)).rowcount
            deleted += db.execute("DELETE FROM alert_metadata WHERE alert_id NOT IN (SELECT id FROM alerts)").rowcount
            deleted += db.execute("DELETE FROM incident_alerts WHERE alert_id NOT IN (SELECT id FROM alerts)").rowcount
            db.commit()
            vacuumed = 0
            try:
                db.execute("VACUUM")
                vacuumed = 1
            except sqlite3.DatabaseError:
                logging.debug("SQLite VACUUM skipped during retention cleanup", exc_info=True)
            db.execute("INSERT INTO retention_runs(retention_days,deleted_alerts,vacuumed,created_at) VALUES(?,?,?,?)",(days,deleted,vacuumed,now_iso()))
            db.commit()
        return deleted

    def rate_limit_history(self, limit=100):
        with self._connect() as db: return [dict(r) for r in db.execute("SELECT * FROM rate_limit_events ORDER BY id DESC LIMIT ?",(limit,)).fetchall()]

    def diagnostics(self):
        checks={}
        try:
            with self._connect() as db:
                db.execute("SELECT 1")
            checks["database"]=True
        except Exception:
            checks["database"]=False
        checks["encryption"]=bool(SECRET_KEY)
        required=("alerts","incidents","audit_log","sentinel_health","alert_rules")
        checks["schema"]=all(self._table_exists(t) for t in required)
        return checks

    def _table_exists(self, name):
        try:
            with self._connect() as db:
                return bool(db.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(name,)
                ).fetchone())
        except Exception:
            return False

def record_rate_limit_event(endpoint: str, retry_after: float = 0.0, profile_id: str = "") -> None:
    try:
        with sqlite3.connect(DB_PATH) as db:
            db.execute("INSERT INTO rate_limit_events(profile_id,endpoint,retry_after,created_at) VALUES(?,?,?,?)",(profile_id,endpoint,float(retry_after or 0),utc_now()))
    except Exception:
        logging.debug("Unable to persist rate-limit telemetry", exc_info=True)

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
                    record_rate_limit_event(path, float(retry_after or 0) if str(retry_after).replace(".","",1).isdigit() else 0.0)
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
                    detail = response.text.strip()[:500]
                    if response.status_code == 401:
                        message = "NextDNS API authentication failed (HTTP 401). Check the API key."
                    elif response.status_code == 403:
                        message = "NextDNS API access denied (HTTP 403). Check that the API key can access this profile."
                    elif response.status_code == 404:
                        message = f"NextDNS resource not found (HTTP 404) for {path}. Check the Profile ID and API key access."
                    elif response.status_code == 429:
                        message = "NextDNS API rate limit exceeded (HTTP 429). Please retry shortly."
                    else:
                        message = f"NextDNS API returned HTTP {response.status_code} for {path}."
                    raise NextDNSError(f"{message} Response: {detail}")

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



    def _patch(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.BASE}{path}"
        for attempt in range(API_RETRIES + 1):
            try:
                response = self.session.patch(url, json=payload, timeout=HTTP_TIMEOUT)
                if response.status_code == 429:
                    retry_after = response.headers.get("Retry-After", "")
                    try:
                        retry_delay = float(retry_after) if retry_after else 2 ** attempt
                    except (TypeError, ValueError):
                        retry_delay = 2 ** attempt
                    delay = min(retry_delay, 60.0)
                    if attempt < API_RETRIES:
                        logging.warning("NextDNS rate limit (429) for %s; retrying in %.1fs", path, delay)
                        time.sleep(delay)
                        continue
                    raise NextDNSError("NextDNS API rate limit exceeded (HTTP 429).")
                if response.status_code >= 500:
                    delay = min(2 ** attempt, 30)
                    if attempt < API_RETRIES:
                        logging.warning("NextDNS server error (%s) for %s; retrying in %ss", response.status_code, path, delay)
                        time.sleep(delay)
                        continue
                if not response.ok:
                    detail = response.text.strip()[:500]
                    if response.status_code == 401:
                        message = "NextDNS API authentication failed (HTTP 401). Check the API key."
                    elif response.status_code == 403:
                        message = "NextDNS API access denied (HTTP 403). Check that the API key can modify this profile."
                    elif response.status_code == 404:
                        message = f"NextDNS resource not found (HTTP 404) for {path}."
                    else:
                        message = f"NextDNS API returned HTTP {response.status_code} for {path}."
                    raise NextDNSError(f"{message} Response: {detail}")
                if response.status_code == 204 or not response.content:
                    return {}
                try:
                    data = response.json()
                except ValueError as exc:
                    raise NextDNSError(f"NextDNS API returned invalid JSON for {path}.") from exc
                api_errors = data.get("errors") if isinstance(data, dict) else None
                if api_errors:
                    detail = json.dumps(api_errors, ensure_ascii=False, default=str)[:500]
                    raise NextDNSError(f"NextDNS API returned application errors for {path}: {detail}")
                if not isinstance(data, dict):
                    raise NextDNSError(f"NextDNS API returned an unexpected response for {path}.")
                return data
            except requests.RequestException as exc:
                if attempt >= API_RETRIES:
                    raise NextDNSError(f"NextDNS request failed for {path}: {exc}") from exc
                delay = min(2 ** attempt, 30)
                logging.warning("Network error for %s; retrying in %ss: %s", path, delay, exc)
                time.sleep(delay)
        raise NextDNSError(f"NextDNS request failed for {path}.")

    def _request_mutation(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        url=f"{self.BASE}{path}"
        for attempt in range(API_RETRIES+1):
            try:
                response=self.session.request(method,url,json=payload,timeout=HTTP_TIMEOUT)
                if response.status_code==429 and attempt<API_RETRIES:
                    time.sleep(min(float(response.headers.get("Retry-After","2")),60)); continue
                if response.status_code>=500 and attempt<API_RETRIES:
                    time.sleep(min(2**attempt,30)); continue
                if not response.ok:
                    raise NextDNSError(f"NextDNS API returned HTTP {response.status_code} for {path}. Response: {response.text.strip()[:500]}")
                if response.status_code==204 or not response.content: return {}
                data=response.json()
                if data.get("errors"):
                    raise NextDNSError("NextDNS API returned application errors for %s: %s"%(path,json.dumps(data["errors"],ensure_ascii=False)[:500]))
                return data if isinstance(data,dict) else {}
            except (requests.RequestException,ValueError) as exc:
                if attempt>=API_RETRIES: raise NextDNSError(f"NextDNS mutation failed for {path}: {exc}") from exc
                time.sleep(min(2**attempt,30))
        raise NextDNSError(f"NextDNS mutation failed for {path}.")

    def add_denylist(self, profile_id: str, domain: str) -> None:
        domain=normalize_domain(domain)
        if not domain: raise NextDNSError("A domain is required.")
        self._request_mutation("POST",f"/profiles/{profile_id}/denylist",{"id":domain,"active":True})

    def remove_denylist(self, profile_id: str, domain: str) -> None:
        domain=normalize_domain(domain)
        if not domain: raise NextDNSError("A domain is required.")
        self._request_mutation("DELETE",f"/profiles/{profile_id}/denylist/{domain}")

    def profiles(self) -> list[dict[str, Any]]:
        """Return profiles visible to the API key using the account profiles endpoint."""
        values: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            # /profiles currently rejects the documented pagination parameters
            # in practice. Fetch the account profile collection without limit.
            params: dict[str, Any] = {}
            if cursor:
                params["cursor"] = cursor
            response = self._get("/profiles", params=params)
            page = response.get("data", [])
            if not isinstance(page, list):
                raise NextDNSError("NextDNS returned an unexpected profiles response.")
            for item in page:
                if isinstance(item, dict) and item.get("id"):
                    values.append(item)
            next_cursor = response.get("meta", {}).get("pagination", {}).get("cursor")
            if not next_cursor or next_cursor == cursor:
                break
            cursor = next_cursor
        return values


    def profile(self, profile_id: str) -> dict[str,Any]:
        response=self._get(f"/profiles/{profile_id}")
        profile=response.get("data",response)
        if not isinstance(profile,dict): raise NextDNSError("Unexpected profile response.")
        return profile

    def update_profile_name(self, profile_id: str, name: str) -> None:
        if not name:
            raise NextDNSError("NextDNS profile name is required.")
        self._patch(f"/profiles/{profile_id}", {"name": name})

    def denylist(self, profile_id: str) -> list[str]:
        # The current NextDNS API exposes the profile's denylist in the
        # profile representation. Do not send unsupported query parameters
        # such as "limit" to the /denylist child endpoint.
        response = self._get(f"/profiles/{profile_id}")
        profile = response.get("data", response)
        if not isinstance(profile, dict):
            raise NextDNSError(
                f"NextDNS returned an unexpected profile response for {profile_id}."
            )

        entries = profile.get("denylist", [])
        if not isinstance(entries, list):
            raise NextDNSError(
                f"NextDNS returned an unexpected denylist format for profile {profile_id}."
            )

        domains: list[str] = []
        for item in entries:
            if not isinstance(item, dict) or not item.get("active", True):
                continue
            value = item.get("id") or item.get("domain") or item.get("name")
            if value:
                domains.append(normalize_domain(str(value)))
        return domains

    def logs(self, profile_id: str, from_ms: int) -> tuple[list[dict[str, Any]], int]:
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

            next_cursor = (
                response.get("meta", {})
                .get("pagination", {})
                .get("cursor")
            )
            if not next_cursor:
                break
            if next_cursor == cursor:
                logging.warning(
                    "NextDNS returned the same log pagination cursor for profile %s; "
                    "stopping pagination to avoid an infinite loop.",
                    profile_id,
                )
                break
            cursor = next_cursor

        if len(values) >= 1000:
            logging.info(
                "Fetched %d log entries for profile %s using pagination.",
                len(values),
                profile_id,
            )
        return values, to_ms


def config_snapshot(profile: dict[str,Any]) -> dict[str,Any]:
    value=json.loads(json.dumps(profile,sort_keys=True,default=str))
    if isinstance(value,dict):
        value.pop("id",None)
        value.pop("meta",None)
    return value

def config_change_summary(before: dict[str,Any], after: dict[str,Any]) -> str:
    changed=[]
    keys=sorted(set(before)|set(after))
    for key in keys:
        if before.get(key)!=after.get(key): changed.append(key)
    return ", ".join(changed) if changed else "configuration"

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
        wildcard = f"*.{parent}"
        if wildcard in denylist:
            return wildcard
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
    if value in ("", None):
        return utc_now()
    raw = str(value).strip()
    try:
        numeric = float(raw)
        if numeric > 10_000_000_000:
            numeric /= 1000.0
        return datetime.fromtimestamp(numeric, timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        pass
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    except ValueError:
        return raw


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


def event_device(log: dict[str, Any]) -> tuple[str,str,str]:
    d=log.get("device")
    if isinstance(d,dict):
        return str(d.get("id") or ""),str(d.get("name") or ""),str(d.get("model") or "")
    return "","",""

def event_protocol(log: dict[str, Any]) -> str:
    return str(log.get("protocol") or "")

def event_encrypted(log: dict[str, Any]) -> bool:
    v=log.get("encrypted")
    return bool(v) if isinstance(v,bool) else str(v).lower()=="true"

def event_key(profile_id: str, log: dict[str, Any]) -> str:
    raw = json.dumps(log, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(f"{profile_id}:{raw}".encode()).hexdigest()


def validate_telegram_credentials(token: str, chat_id: str) -> dict[str, Any]:
    if not token or not chat_id:
        raise RuntimeError("Telegram bot token and chat ID are required.")
    try:
        response = requests.get(
            f"https://api.telegram.org/bot{token}/getMe",
            timeout=HTTP_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"Unable to reach Telegram: {exc}") from exc
    if not response.ok:
        raise RuntimeError(
            f"Telegram token validation failed (HTTP {response.status_code})."
        )
    try:
        data = response.json()
    except ValueError as exc:
        raise RuntimeError("Telegram returned invalid JSON.") from exc
    if not data.get("ok"):
        raise RuntimeError("Telegram token validation failed.")
    bot = data.get("result") if isinstance(data.get("result"), dict) else {}
    try:
        response = requests.get(
            f"https://api.telegram.org/bot{token}/getChat",
            params={"chat_id": chat_id},
            timeout=HTTP_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"Unable to validate Telegram chat: {exc}") from exc
    if not response.ok:
        raise RuntimeError(
            f"Telegram chat validation failed (HTTP {response.status_code})."
        )
    try:
        data = response.json()
    except ValueError as exc:
        raise RuntimeError("Telegram returned invalid JSON.") from exc
    if not data.get("ok"):
        raise RuntimeError("Telegram chat ID could not be validated.")
    chat = data.get("result") if isinstance(data.get("result"), dict) else {}
    return {"bot": bot, "chat": chat}


def send_telegram_result(
    token: str, chat_id: str, message: str, retries: int = API_RETRIES,
    parse_mode: str = "HTML",
) -> tuple[bool, str]:
    if not token or not chat_id:
        return False, "Telegram is not configured."

    last_reason = "Telegram delivery failed."
    for attempt in range(retries + 1):
        try:
            response = requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                data={
                    "chat_id": chat_id,
                    "text": message,
                    "parse_mode": parse_mode,
                    "disable_web_page_preview": "true",
                },
                timeout=HTTP_TIMEOUT,
            )
            if response.ok:
                return True, "Message delivered."

            try:
                payload = response.json()
                api_reason = str(payload.get("description") or "").strip()
            except ValueError:
                api_reason = ""
            last_reason = api_reason or f"Telegram HTTP {response.status_code}."
            if response.status_code == 429 or response.status_code >= 500:
                retry_after = response.headers.get("Retry-After", "")
                try:
                    retry_delay = float(retry_after) if retry_after else 2 ** attempt
                except (TypeError, ValueError):
                    retry_delay = 2 ** attempt
                delay = min(retry_delay, 60.0)
                if attempt < retries:
                    logging.warning("Telegram HTTP %s; retrying in %.1fs: %s", response.status_code, delay, last_reason)
                    time.sleep(delay)
                    continue
            logging.error("Telegram delivery failed: %s", last_reason)
            return False, last_reason
        except requests.RequestException as exc:
            last_reason = f"Telegram network error: {exc}"
            if attempt >= retries:
                logging.exception("Telegram delivery failed: %s", exc)
                return False, last_reason
            delay = min(2 ** attempt, 30)
            logging.warning("Telegram network error; retrying in %ss: %s", delay, exc)
            time.sleep(delay)

    return False, last_reason


def send_telegram(
    token: str, chat_id: str, message: str, retries: int = API_RETRIES
) -> bool:
    return send_telegram_result(token, chat_id, message, retries)[0]


@dataclass
class Sentinel:
    store: Store
    features: FeatureStore | None = None
    telegram_token: str = ""
    telegram_chat_id: str = ""
    stop_event: threading.Event | None = None
    threads: list[threading.Thread] | None = None
    profile_events: dict[str, threading.Event] | None = None
    profile_threads: dict[str, threading.Thread] | None = None
    notification_thread: threading.Thread | None = None

    def notify(
        self,
        account: dict[str, Any],
        domain: str,
        reason: str,
        status: str,
        matched: str,
        client_ip: str = "",
        event_time: str = "",
        device_id: str = "",
        device_name: str = "",
        device_model: str = "",
        protocol: str = "",
        encrypted: bool = False,
        alert_id: int | None = None,
    ) -> bool:
        context = self.features.alert_context(alert_id) if self.features and alert_id else {}
        alert_type = str(context.get("alert_type") or status or "security_event").lower()
        severity = str(context.get("severity") or "").strip()
        risk_score = context.get("risk_score")
        domain_risk = str(context.get("domain_risk") or "").strip()
        incident_id = context.get("incident_id")
        type_titles = {
            "denylist_match": "🚫 Blocked Site Access",
            "denylist_added": "➕ Denylist Change",
            "denylist_removed": "➖ Denylist Change",
            "config_changed": "🔧 Config Change",
            "configuration_action": "🔧 Configuration Action",
            "configuration_undo": "↩️ Configuration Undo",
            "device_inactive": "📱 Device Inactive",
            "device_new": "📱 New Device",
            "security_event": "🛡️ Security Event",
        }
        title = type_titles.get(alert_type, "🛡️ Security Event")
        profile = html_escape(str(account.get("name") or account.get("profile_id") or "Profile"))
        lines=[f"<b>{title} — {profile}</b>"]
        if severity:
            risk_text=f" · Risk {int(risk_score)}/100" if isinstance(risk_score,(int,float)) else ""
            lines.append(f"<b>Risk:</b> {html_escape(severity.upper())}{risk_text}")
        elif isinstance(risk_score,(int,float)):
            lines.append(f"<b>Risk:</b> {int(risk_score)}/100")
        if domain_risk:
            lines.append(f"<b>Domain Risk:</b> {html_escape(domain_risk.upper())}")
        if domain:
            lines.append(f"<b>Domain:</b> <code>{html_escape(domain)}</code>")
        if matched and matched != domain:
            lines.append(f"<b>Matched:</b> <code>{html_escape(matched)}</code>")
        if device_name or device_id:
            lines.append(f"<b>Device:</b> {html_escape(device_name or device_id)}")
        if device_model:
            lines.append(f"<b>Model:</b> {html_escape(device_model)}")
        if client_ip:
            lines.append(f"<b>Client IP:</b> <code>{html_escape(client_ip)}</code>")
        if protocol:
            lines.append(f"<b>Protocol:</b> {html_escape(protocol)}")
        if encrypted:
            lines.append("<b>Encrypted:</b> Yes")
        if reason:
            lines.append(f"<b>Reason:</b> {html_escape(reason)}")
        if alert_type in {"config_changed","configuration_action","configuration_undo"} and self.features:
            changes=self.store.config_changes(50)
            latest=next((item for item in changes if item.get("profile_id")==account.get("profile_id")),None)
            if latest and latest.get("change_type"):
                lines.append(f"<b>Change:</b> {html_escape(str(latest['change_type']))}")
        if incident_id:
            lines.append(f"<b>Incident:</b> #{html_escape(str(incident_id))}")
        if event_time:
            try:
                dt=datetime.fromisoformat(str(event_time).replace("Z","+00:00"))
                if dt.tzinfo is None: dt=dt.replace(tzinfo=timezone.utc)
                stamp=dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            except ValueError:
                stamp=event_time
            lines.append(f"<b>Time:</b> {html_escape(stamp)}")
        message="\n".join(lines)
        destinations=self.store.telegram_destinations()
        if destinations:
            delivered=False
            for bot in destinations:
                ok,reason=send_telegram_result(bot["token"],bot["chat_id"],message,parse_mode="HTML")
                self.store.mark_telegram_bot_result(int(bot["id"]),ok,"" if ok else reason)
                delivered=delivered or ok
            return delivered
        if not self.telegram_token or not self.telegram_chat_id:
            return False
        return send_telegram(self.telegram_token, self.telegram_chat_id, message)
    
    def notify_report(self, title: str, lines: list[str], alert_id: int | None = None) -> bool:
        context = self.features.alert_context(alert_id) if self.features and alert_id else {}
        title_text = str(title or "Sentinel Event").strip() or "Sentinel Event"
        title_lower = title_text.lower()
        if "config" in title_lower or "configuration" in title_lower:
            event_header = "🔧 Configuration Event"
        elif "denylist" in title_lower or "blocked" in title_lower:
            event_header = "🚫 Denylist Event"
        elif "device" in title_lower:
            event_header = "📱 Device Event"
        elif "incident" in title_lower:
            event_header = "🛡️ Incident Event"
        elif "monitor" in title_lower:
            event_header = "⚙️ Monitoring Event"
        else:
            event_header = "🛡️ Sentinel Event"

        body_lines = [f"<b>{event_header}</b>", f"<b>{html_escape(title_text)}</b>"]
        severity = str(context.get("severity") or "").strip()
        risk = context.get("risk_score")
        if severity:
            risk_text = f" · Risk {int(risk)}/100" if isinstance(risk, (int, float)) else ""
            body_lines.append(f"<b>Risk:</b> {html_escape(severity.upper())}{risk_text}")
        elif isinstance(risk, (int, float)):
            body_lines.append(f"<b>Risk:</b> {int(risk)}/100")
        for line in lines or []:
            value = str(line or "").strip()
            if value:
                body_lines.append(html_escape(value))
        message = "\n\n".join(body_lines)
        destinations = self.store.telegram_destinations()
        delivered = False
        if destinations:
            for bot in destinations:
                ok, reason = send_telegram_result(bot["token"], bot["chat_id"], message, parse_mode="HTML")
                self.store.mark_telegram_bot_result(int(bot["id"]), ok, "" if ok else reason)
                delivered = delivered or ok
        elif self.telegram_token and self.telegram_chat_id:
            delivered = send_telegram_result(self.telegram_token, self.telegram_chat_id, message, parse_mode="HTML")[0]
        if self.features and alert_id:
            self.features.delivery(alert_id, "telegram", "sent" if delivered else "failed")
        return delivered

    def enrich_alert(self, event_key: str, account: dict[str, Any], domain: str, reason: str,
                     status: str, matched: str, client_ip: str, event_time: str,
                     device_id: str, device_name: str, device_model: str,
                     protocol: str, encrypted: bool) -> int | None:
        if not self.features:
            return None
        context = self.features.alert_by_event_key(event_key)
        alert_id = int(context["id"]) if context.get("id") else None
        if not alert_id:
            return None
        self.features.process_alert(alert_id, {
            "profile_id": account["profile_id"], "account_name": account["name"],
            "domain": domain, "reason": reason, "status": status,
            "alert_type": context.get("alert_type") or "security_event",
            "device_id": device_id, "device_name": device_name,
            "device_model": device_model, "event_timestamp": event_time,
            "matched_domain": matched, "client_ip": client_ip,
            "protocol": protocol, "encrypted": encrypted,
            "title": domain or reason or "Security event",
        })
        return alert_id

    def dispatch_pending_notifications(self) -> None:
        # Retries are independent from DNS polling so a recovered Telegram bot
        # receives queued alerts immediately.
        while self.stop_event is not None and not self.stop_event.is_set():
            if not self.store.telegram_destinations() and (not self.telegram_token or not self.telegram_chat_id):
                self.stop_event.wait(1)
                continue
            try:
                for account in self.store.accounts():
                    if not account.get("active"):
                        continue
                    for alert in self.store.unnotified_alerts(account["profile_id"], 25):
                        alert_id=int(alert.get("id") or 0) or None
                        delivered=self.notify(
                            account, alert["domain"], alert["reason"], alert["status"],
                            alert["matched_domain"], alert["client_ip"], alert["event_timestamp"],
                            alert.get("device_id",""), alert.get("device_name",""),
                            alert.get("device_model",""), alert.get("protocol",""),
                            bool(alert.get("encrypted")), alert_id,
                        )
                        if delivered:
                            self.store.mark_alert_notified(alert["event_key"])
                            if self.features and alert_id:
                                self.features.delivery(alert_id,"telegram","sent")
                        else:
                            self.store.mark_notification_failed(alert["event_key"])
                            if self.features and alert_id:
                                self.features.delivery(alert_id,"telegram","failed")
            except Exception:
                logging.exception("Pending notification dispatcher failed")
            self.stop_event.wait(1)

    def check_device_inactivity(self, account: dict[str, Any]) -> None:
        profile_id = account["profile_id"]
        for device in self.store.device_states():
            if device["profile_id"] != profile_id or not device["last_seen_at"] or device.get("inactive_alerted_at"):
                continue
            try:
                last_dt = datetime.fromisoformat(str(device["last_seen_at"]).replace("Z","+00:00"))
                age = (datetime.now(timezone.utc) - last_dt).total_seconds()
                if age < DEVICE_INACTIVITY_SECONDS:
                    continue
                if not self.store.mark_device_inactive_alerted(profile_id,device["device_id"]):
                    continue
                key=hashlib.sha256(("inactive:"+profile_id+":"+device["device_id"]+":"+device["last_seen_at"]).encode()).hexdigest()
                reason="No recent DNS activity detected; DNS may be inactive on this device."
                self.store.add_alert(profile_id,account["name"],"","",reason,"device_inactive",
                                     device.get("client_ip",""),device["last_seen_at"],key,
                                     "device_inactive",device.get("device_id",""),
                                     device.get("device_name",""),device.get("device_model",""),"")
                alert_id=self.enrich_alert(key,account,"",reason,"device_inactive","",
                                           device.get("client_ip",""),device["last_seen_at"],
                                           device.get("device_id",""),device.get("device_name",""),
                                           device.get("device_model",""),"",False)
                delivered=self.notify(account,"",reason,"device_inactive","",
                                     device.get("client_ip",""),device["last_seen_at"],
                                     device.get("device_id",""),device.get("device_name",""),
                                     device.get("device_model",""),"",False,alert_id)
                if delivered:
                    self.store.mark_alert_notified(key)
                else:
                    self.store.mark_notification_failed(key)
            except (TypeError,ValueError):
                continue

    def monitor_account(self, account: dict[str, Any], stop_event: threading.Event | None = None) -> None:
        client = NextDNSClient(account["api_key"])
        profile_id = account["profile_id"]
        logging.info("Monitoring %s (%s)", account["name"], profile_id)
        denylist: set[str] = set()
        iteration = 0
        event = stop_event or self.stop_event

        while event is None or not event.is_set():
            try:
                if self.features:
                    self.features.heartbeat("running", {"profile_id": profile_id})
                iteration += 1
                if iteration == 1 or iteration % 20 == 0:
                    try:
                        live_profile=client.profile(profile_id)
                        live_snapshot=config_snapshot(live_profile)
                        previous=self.store.config_snapshot(profile_id)
                        if previous is not None and previous != live_snapshot:
                            change_type=config_change_summary(previous,live_snapshot)
                            change_id=self.store.add_config_change(profile_id,previous,live_snapshot,change_type,"nextdns_profile")
                            key=hashlib.sha256(f"config:{profile_id}:{change_id}".encode()).hexdigest()
                            self.store.add_alert(profile_id,account["name"],"", "", "Configuration changed: "+change_type, "config_changed", "", utc_now(), key, "config_change", source="nextdns_profile")
                            alert_id=self.enrich_alert(key,account,"","Configuration changed: "+change_type,"config_changed","","",utc_now(),"","","","",False)
                            delivered=self.notify(account,"","Configuration changed: "+change_type,"config_changed","",event_time=utc_now(),alert_id=alert_id)
                            if delivered:
                                self.store.mark_alert_notified(key)
                                if self.features and alert_id: self.features.delivery(alert_id,"telegram","sent")
                            else:
                                self.store.mark_notification_failed(key)
                                if self.features and alert_id: self.features.delivery(alert_id,"telegram","failed")
                        self.store.save_config_snapshot(profile_id,live_snapshot)
                    except Exception as exc:
                        logging.warning("Profile configuration snapshot failed for %s: %s",account["name"],exc)
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

                logs, checkpoint_ms = client.logs(profile_id, from_ms)
                for log in logs:
                    domain = event_domain(log)
                    status = event_status(log)
                    event_time = event_timestamp(log)
                    client_ip = event_client_ip(log)
                    device_id,device_name,device_model=event_device(log)
                    protocol=event_protocol(log)
                    encrypted=event_encrypted(log)
                    # Device state is updated from every DNS log, not only denylist matches.
                    if domain:
                        try:
                            self.store.update_device_state(
                                profile_id, device_id, device_name, device_model,
                                client_ip, event_time, status, domain,
                            )
                        except sqlite3.Error as exc:
                            # Device telemetry must never prevent denylist detection/alerting.
                            logging.warning(
                                "Device state update failed for %s/%s: %s",
                                account["name"], device_id or "__UNIDENTIFIED__", exc,
                            )
                    if not domain or not domain_matches(domain, denylist):
                        continue

                    key = event_key(profile_id, log)
                    matched = find_matching_domain(domain, denylist) or matched_domain(log)
                    reason = event_reason(log) or "Custom denylist match"

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
                        "denylist_match",device_id,device_name,device_model,protocol,encrypted,"nextdns_logs",
                    ):
                        logging.warning(
                            "Denylist match: %s -> %s",
                            account["name"],
                            domain,
                        )
                        alert_id=self.enrich_alert(key,account,domain,reason,status,matched,client_ip,event_time,device_id,device_name,device_model,protocol,encrypted)
                        policy=self.features.alert_policy(profile_id,domain,device_id,"denylist_match") if self.features else {"suppressed":False,"escalate":False}
                        if not recently_notified and not policy.get("suppressed"):
                            delivered = self.notify(
                                account, domain, reason, status, matched, client_ip, event_time,
                                device_id, device_name, device_model, protocol, encrypted, alert_id,
                            )
                            if delivered:
                                self.store.mark_alert_notified(key)
                                if self.features and alert_id: self.features.delivery(alert_id,"telegram","sent")
                            else:
                                self.store.mark_notification_failed(key)
                                if self.features and alert_id: self.features.delivery(alert_id,"telegram","failed")
                            if policy.get("escalate") and delivered:
                                self.features.audit("notification_escalation","alert",str(alert_id or ""),profile_id,{"level":2})
                                self.notify_report("Alert escalation",["Profile: "+account["name"],"Domain: "+domain,"Rule requested escalation."],alert_id)
                        else:
                            self.store.mark_alert_suppressed(key)
                            if self.features and alert_id: self.features.delivery(alert_id,"telegram","suppressed")
                            logging.info(
                                "Telegram notification suppressed by cooldown for %s",
                                domain,
                            )

                self.check_device_inactivity(account)

                # Pending notification retries are handled by the dedicated dispatcher.
                self.store.set_poll_state(profile_id, checkpoint_ms)
                if event:
                    event.wait(CHECK_INTERVAL)
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
                if event:
                    event.wait(max(CHECK_INTERVAL, 10))
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

    def _sync_thread_list(self) -> None:
        self.threads = list((self.profile_threads or {}).values())

    def start_profile(self, profile_id: str) -> bool:
        account = next((a for a in self.store.accounts() if a["profile_id"] == profile_id and a["active"]), None)
        if not account:
            return False
        if self.profile_events is None:
            self.profile_events = {}
        if self.profile_threads is None:
            self.profile_threads = {}
        existing = self.profile_threads.get(profile_id)
        if existing and existing.is_alive():
            return False
        if self.stop_event is None:
            self.stop_event = threading.Event()
        if self.stop_event.is_set():
            self.stop_event.clear()
        event = threading.Event()
        self.profile_events[profile_id] = event
        thread = threading.Thread(
            target=self.monitor_account,
            args=(account, event),
            name=f"sentinel-{profile_id}",
            daemon=True,
        )
        self.profile_threads[profile_id] = thread
        self._sync_thread_list()
        thread.start()
        logging.info("%s started monitoring profile %s.", APP_NAME, profile_id)
        return True

    def stop_profile(self, profile_id: str) -> bool:
        event = (self.profile_events or {}).get(profile_id)
        thread = (self.profile_threads or {}).get(profile_id)
        if not event and not thread:
            return False
        if event:
            event.set()
        if thread:
            thread.join(timeout=CHECK_INTERVAL + 5)
        if self.profile_events:
            self.profile_events.pop(profile_id, None)
        if self.profile_threads:
            self.profile_threads.pop(profile_id, None)
        self._sync_thread_list()
        logging.info("%s stopped monitoring profile %s.", APP_NAME, profile_id)
        return True

    def start(self) -> int:
        accounts = [a for a in self.store.accounts() if a["active"]]
        if not accounts:
            raise RuntimeError(
                "No active accounts configured. Add a NextDNS profile from the dashboard."
            )
        if self.stop_event is None:
            self.stop_event = threading.Event()
        if self.stop_event.is_set():
            self.stop_event.clear()
        if self.profile_events is None:
            self.profile_events = {}
        if self.profile_threads is None:
            self.profile_threads = {}
        if self.features:
            self.features.heartbeat("starting", {"profiles": len(accounts)})
        started = 0
        for account in accounts:
            if self.start_profile(account["profile_id"]):
                started += 1
        self._sync_thread_list()
        if self.notification_thread is None or not self.notification_thread.is_alive():
            self.notification_thread = threading.Thread(
                target=self.dispatch_pending_notifications,
                name="sentinel-notifications",
                daemon=True,
            )
            self.notification_thread.start()
        logging.info("%s is monitoring %d active account(s).", APP_NAME, len(self.threads or []))
        return started

    def is_running(self) -> bool:
        return bool(self.threads and any(thread.is_alive() for thread in self.threads))

    def stop(self) -> None:
        if self.stop_event:
            self.stop_event.set()
        for event in (self.profile_events or {}).values():
            event.set()
        for thread in (self.profile_threads or {}).values():
            thread.join(timeout=CHECK_INTERVAL + 5)
        self.profile_threads = {}
        self.profile_events = {}
        self.threads = []
        notification_thread = self.notification_thread
        self.notification_thread = None
        if notification_thread and notification_thread.is_alive():
            notification_thread.join(timeout=2)
        self.stop_event = None
        if self.features:
            self.features.heartbeat("stopped")
        logging.info("Stopped %s.", APP_NAME)

    def run(self) -> None:
        self.start()
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            logging.info("Stopping %s.", APP_NAME)
            self.stop()


AUTH_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NextDNS Sentinel · Authentication</title>
<style>body{font-family:system-ui;background:#080b12;color:#e8edf7;display:grid;place-items:center;min-height:100vh;margin:0}.box{width:min(420px,calc(100% - 32px));background:#101621;border:1px solid #263248;border-radius:16px;padding:24px;box-shadow:0 20px 50px #0008}input,button{width:100%;box-sizing:border-box;padding:11px;border-radius:9px;margin-top:10px}input{background:#0b1019;color:#e8edf7;border:1px solid #303b4e}button{background:#35c76f;border:0;font-weight:800;cursor:pointer}.muted{color:#8c98aa;font-size:13px}.error{color:#ffb4b4;margin-top:10px}</style></head>
<body><div class="box"><h2>NextDNS Sentinel</h2><div class="muted">API authentication is enabled. Sign in to open the dashboard.</div>
<input id="token" type="password" autocomplete="current-password" placeholder="Sentinel API token">
<button onclick="login()">Sign in</button><div id="error" class="error"></div></div>
<script>async function login(){const e=document.getElementById('error');e.textContent='';try{const r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:document.getElementById('token').value})});const d=await r.json();if(!r.ok)throw new Error(d.error||'Authentication failed');location.reload()}catch(x){e.textContent=x.message}}</script></body></html>"""

DASHBOARD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NextDNS Sentinel</title>
<style>:root{color-scheme:dark}*{box-sizing:border-box}body{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:radial-gradient(circle at 15% 0%,#14243a 0,#080b12 36%);color:#e8edf7;margin:0;padding:24px;line-height:1.45}main{max-width:1250px;margin:auto}h1{margin:0;font-size:32px;letter-spacing:-.6px}h2{margin:0 0 12px;font-size:18px}h3{margin:0 0 10px}.muted{color:#8c98aa}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:18px 0}.card,.panel{background:linear-gradient(145deg,rgba(16,22,33,.97),rgba(11,16,25,.97));border:1px solid #263248;border-radius:16px;padding:17px;margin-bottom:14px;box-shadow:0 12px 35px rgba(0,0,0,.16)}.value{font-size:29px;font-weight:750;margin-top:3px}.card .muted{text-transform:capitalize;font-size:12px;letter-spacing:.4px}.status{margin:10px 0;padding:11px 13px;border-radius:10px;background:#101621;border:1px solid #263248}.ok{color:#9af0bb}.error{color:#ffb4b4}.neutral-text{color:#b8c4d8}button{border:1px solid transparent;border-radius:9px;padding:9px 13px;font-weight:700;cursor:pointer;margin:3px;transition:transform .15s,filter .15s}button:hover{filter:brightness(1.08);transform:translateY(-1px)}.start{background:#35c76f;color:#07140b}.stop{background:#ef6b73;color:#21080a}.neutral{background:#29364a;color:#e8edf7}input,select{width:100%;box-sizing:border-box;background:#0b1019;color:#e8edf7;border:1px solid #303b4e;border-radius:9px;padding:10px;margin:5px 0 10px}label{display:block;font-size:13px;color:#aeb8c8}form{max-width:560px}table{width:100%;border-collapse:collapse;background:#101621;border-radius:14px;overflow:hidden}th,td{text-align:left;padding:10px;border-bottom:1px solid #202a3a;font-size:13px}th{color:#9eabc0;font-size:12px;text-transform:uppercase;letter-spacing:.5px}tbody tr:hover{background:#141d2a}code{color:#9ed0ff}.hidden{display:none}.account{padding:12px 0;border-bottom:1px solid #202a3a}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;margin:10px 0}.meta div{background:#0b1019;border:1px solid #202a3a;border-radius:8px;padding:9px}.meta strong{display:block;font-size:12px;color:#8c98aa;margin-bottom:3px}.hero{display:flex;justify-content:space-between;gap:18px;align-items:center;padding:22px 24px;margin-bottom:14px}.hero-copy{min-width:0}.eyebrow{font-size:11px;text-transform:uppercase;letter-spacing:1.6px;color:#7f91aa;font-weight:800}.hero-badge{border:1px solid #2d405c;background:#0c1420;border-radius:12px;padding:10px 13px;white-space:nowrap}.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px;background:#65758d}.dot.ok{background:#35c76f}.analytics{display:grid;grid-template-columns:minmax(0,2fr) minmax(260px,1fr);gap:14px}.chart{height:230px;display:flex;align-items:flex-end;gap:6px;padding:18px 8px 28px;border-top:1px solid #202a3a}.bar-wrap{height:100%;flex:1;display:flex;align-items:flex-end;justify-content:center;position:relative;min-width:4px}.bar{width:100%;max-width:22px;min-height:3px;border-radius:6px 6px 2px 2px;background:linear-gradient(180deg,#55d98a,#2e9e68);transition:height .3s}.bar-label{position:absolute;bottom:-24px;font-size:10px;color:#75839a;white-space:nowrap}.bar-value{position:absolute;top:-18px;font-size:10px;color:#aebbd0}.panel{transition:transform .18s ease,border-color .18s ease}.panel:hover{border-color:#34435d}.table-wrap table{min-width:760px}.table-wrap th{position:sticky;top:0;background:#101621;z-index:2}.sidebar .nav-btn{opacity:.86}.sidebar .nav-btn.active{opacity:1;box-shadow:inset 3px 0 #55d98a;background:#172235}.status.error{box-shadow:0 0 0 1px rgba(239,107,115,.12)}.toast{position:fixed;right:20px;bottom:20px;z-index:1000;max-width:min(520px,calc(100vw - 40px));padding:12px 15px;border:1px solid #34435d;border-radius:12px;background:#101621;box-shadow:0 14px 40px rgba(0,0,0,.35);opacity:0;pointer-events:none;transform:translateY(8px);transition:.2s}.toast.show{opacity:1;transform:translateY(0)}.toast.ok{border-color:#2f8b58}.toast.error{border-color:#a54d55}.mini-list{display:grid;gap:8px}.mini-item{display:flex;justify-content:space-between;gap:10px;padding:9px 10px;background:#0b1019;border:1px solid #202a3a;border-radius:9px}.recent-alerts-panel{border-color:#334766;background:linear-gradient(145deg,rgba(18,27,41,.98),rgba(10,15,24,.98));box-shadow:0 14px 38px rgba(0,0,0,.22)}.recent-alerts-head{align-items:flex-start}.recent-alerts-head h2{display:flex;align-items:center;gap:8px}.recent-alerts-dot{width:9px;height:9px;border-radius:50%;background:#efc95f;box-shadow:0 0 12px rgba(239,201,95,.55)}.recent-alerts-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:10px}.recent-alert-account{background:#0b1019;border:1px solid #263248;border-radius:12px;padding:12px;min-width:0}.recent-alert-account.unseen{border-color:#3a506f}.recent-alert-account-head{display:flex;justify-content:space-between;align-items:flex-start;gap:10px;margin-bottom:9px}.recent-alert-account-title{min-width:0}.recent-alert-account-title strong{display:block;font-size:15px}.recent-alert-account-title .muted{font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.recent-alert-summary{display:flex;gap:5px;flex-wrap:wrap;margin-top:7px}.recent-alert-summary .pill{font-size:10px}.recent-alert-list{display:grid;gap:7px;max-height:360px;overflow:auto;padding-right:2px}.recent-alert-item{display:grid;grid-template-columns:30px minmax(0,1fr) auto;gap:9px;align-items:start;padding:9px;background:#101621;border:1px solid #202a3a;border-radius:10px}.recent-alert-item.unseen{border-left:3px solid #efc95f;background:#121b29}.recent-alert-icon{width:28px;height:28px;display:grid;place-items:center;border-radius:8px;background:#172235;font-size:15px}.recent-alert-main{min-width:0}.recent-alert-type{font-weight:800;font-size:12px}.recent-alert-detail{font-size:12px;margin-top:3px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.recent-alert-meta{display:flex;gap:7px;flex-wrap:wrap;margin-top:5px;font-size:10px;color:#8c98aa}.recent-alert-time{font-size:10px;color:#8c98aa;white-space:nowrap}.recent-alert-actions{display:flex;align-items:center;gap:3px}.recent-alert-actions button{padding:6px 8px;font-size:10px;margin:0}.recent-alert-seen{color:#9af0bb}.recent-alert-new{color:#efc95f}.recent-alert-empty{padding:16px;text-align:center;background:#0b1019;border:1px dashed #263248;border-radius:10px}@media(max-width:700px){.recent-alerts-grid{grid-template-columns:1fr}.recent-alert-item{grid-template-columns:28px minmax(0,1fr)}}.progress{height:5px;background:#202a3a;border-radius:99px;overflow:hidden;margin-top:5px}.progress>span{display:block;height:100%;background:#55d98a}.section-head{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:10px}.pill{font-size:11px;padding:4px 8px;border-radius:99px;background:#172235;color:#aebbd0}@media(max-width:800px){body{padding:12px}.analytics{grid-template-columns:1fr}.hero{align-items:flex-start;flex-direction:column}.hero-badge{width:100%}}.device-badge{font-size:11px;padding:5px 9px;border:1px solid #2d405c;border-radius:99px;background:#101a28;color:#b8c4d8}.health-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:10px}.health-card{padding:12px;background:#0b1019;border:1px solid #202a3a;border-radius:10px}.health-card .name{font-weight:750}.health-card .line{display:flex;justify-content:space-between;gap:8px;font-size:12px;margin-top:5px}.timeline{display:grid;gap:8px}.timeline-item{display:grid;grid-template-columns:8px 1fr auto;gap:10px;align-items:center;padding:9px 10px;background:#0b1019;border:1px solid #202a3a;border-radius:9px}.timeline-dot{width:8px;height:8px;border-radius:50%;background:#55d98a}.timeline-dot.warn{background:#efc95f}.timeline-dot.error{background:#ef6b73}.table-wrap{overflow-x:auto;border-radius:14px}.device-state{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px}.device-item{padding:10px;background:#0b1019;border:1px solid #202a3a;border-radius:10px}.device-item .name{font-weight:750}.device-item .line{font-size:12px;display:flex;justify-content:space-between;margin-top:5px}body.device-android{padding:12px}body.device-android main{max-width:100%}body.device-android h1{font-size:26px}body.device-android .card{padding:14px}body.device-android button{min-height:42px}body.device-android input,body.device-android select{min-height:44px}body.device-windows{padding:28px}@media(max-width:560px){.grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.value{font-size:23px}.card{padding:13px}.chart{gap:2px;height:200px}.bar{max-width:12px}.bar-label{font-size:8px;transform:rotate(-35deg);transform-origin:top left}.section-head{align-items:flex-start;flex-direction:column}.hero-badge{white-space:normal}.timeline-item{grid-template-columns:8px minmax(0,1fr);}.timeline-item>strong{grid-column:2}}.app-shell{display:flex;min-height:calc(100vh - 48px);max-width:1500px;margin:auto}.sidebar{width:245px;flex:0 0 245px;background:rgba(9,14,22,.96);border:1px solid #263248;border-radius:18px;padding:14px;position:sticky;top:24px;height:calc(100vh - 48px);overflow:auto;z-index:50}.sidebar-brand{display:flex;align-items:center;gap:10px;padding:10px 8px 16px;border-bottom:1px solid #202a3a;margin-bottom:12px}.sidebar-brand img{width:30px;height:30px}.nav-label{font-size:10px;text-transform:uppercase;letter-spacing:1.3px;color:#66758c;font-weight:800;padding:10px}.nav-btn{width:100%;display:flex;align-items:center;gap:10px;text-align:left;background:transparent;color:#aebbd0;border:1px solid transparent;padding:10px 11px;margin:2px 0}.nav-btn:hover{background:#111b29;border-color:#24334a;transform:none}.nav-btn.active{background:#162238;border-color:#2d405c;color:#e8edf7}.nav-btn img{width:18px;height:18px}.app-content{min-width:0;flex:1;padding-left:16px}.page-view{display:none}.page-view.active{display:block}.sidebar-toggle{display:none}@media(max-width:900px){.app-shell{display:block}.sidebar{position:fixed;left:12px;top:12px;bottom:12px;height:auto;width:270px;transform:translateX(-120%);transition:transform .2s;box-shadow:0 20px 60px rgba(0,0,0,.5)}.sidebar.open{transform:translateX(0)}.sidebar-toggle{display:flex;position:fixed;left:18px;top:18px;width:44px;height:44px;z-index:60;align-items:center;justify-content:center;background:#162238;color:#e8edf7;border:1px solid #30415a;border-radius:11px}.sidebar-toggle svg{width:22px;height:22px}.app-content{padding-left:0}.hero{padding-top:72px}} .toast{position:fixed;right:20px;bottom:20px;z-index:1000;max-width:min(520px,calc(100vw - 40px));padding:12px 15px;border:1px solid #344766;border-radius:12px;background:rgba(10,16,27,.96);box-shadow:0 18px 50px rgba(0,0,0,.35);font-size:13px;display:none}.toast.show{display:block}.toast.error{color:#ffd0d0;border-color:#6a3640}.toast.ok{color:#c8ffdc;border-color:#2f6b4b}.action-cell{white-space:nowrap}.scalable-list{max-height:430px;overflow:auto;padding-right:3px}.scalable-list::-webkit-scrollbar{width:7px}.scalable-list::-webkit-scrollbar-thumb{background:#30415a;border-radius:8px}#alerts,#accounts,#denylist,#device-activity,#event-timeline,#config-changes,#telegram-bot-card{max-height:430px;overflow:auto;padding-right:3px}.table-wrap{max-height:520px;overflow:auto}.table-wrap table{min-width:760px}.section-head h2{letter-spacing:-.2px}.panel{backdrop-filter:blur(8px)}.start{background:linear-gradient(135deg,#35d487,#25ad73);box-shadow:0 6px 18px rgba(37,173,115,.16)}.neutral{background:linear-gradient(135deg,#263852,#1d2a3f)}.stop{background:linear-gradient(135deg,#ef6b73,#c94f5b)}</style>
</head>
<body>
<div id="action-toast" class="toast"></div><button type="button" class="sidebar-toggle" id="sidebar-toggle" aria-label="Open navigation" onclick="toggleSidebar()"><svg viewBox="0 0 24 24" fill="none"><path d="M4 6h16M4 12h16M4 18h16" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg></button><div class="app-shell"><aside class="sidebar" id="sidebar"><div class="sidebar-brand"><img src="/assets/icons/dashboard.svg" alt=""><div><strong>Sentinel</strong><div class="muted" style="font-size:11px">Security Console</div></div></div><div class="nav-label">Monitor</div><button type="button" class="nav-btn active" data-page="overview" data-nav-page="overview" onclick="showPage('overview')"><img src="/assets/icons/overview.svg" alt="">Overview</button><button type="button" class="nav-btn" data-page="analytics" data-nav-page="analytics" onclick="showPage('analytics')"><img src="/assets/icons/features.svg" alt="">Analytics</button><button type="button" class="nav-btn" data-page="devices" data-nav-page="devices" onclick="showPage('devices')"><img src="/assets/icons/project.svg" alt="">Devices</button><div class="nav-label">Security</div><button type="button" class="nav-btn" data-page="security" data-nav-page="security" onclick="showPage('security')"><img src="/assets/icons/security.svg" alt="">Security</button><button type="button" class="nav-btn" data-page="profiles" data-nav-page="profiles" onclick="showPage('profiles')"><img src="/assets/icons/config.svg" alt="">Profiles & Config</button><div class="nav-label">Operations</div><button type="button" class="nav-btn" data-page="notifications" data-nav-page="notifications" onclick="showPage('notifications')"><img src="/assets/icons/security.svg" alt="">Notifications</button><button type="button" class="nav-btn" data-page="operations" data-nav-page="operations" onclick="showPage('operations')"><img src="/assets/icons/process.svg" alt="">Control Center</button><button type="button" class="nav-btn" data-page="data" data-nav-page="data" onclick="showPage('data')"><img src="/assets/icons/storage.svg" alt="">Data & Recovery</button></aside><div class="app-content"><main>
<div class="panel hero">
<div class="hero-copy"><div class="eyebrow">Security Operations Console</div><h1>NextDNS Sentinel</h1><div class="muted">Local monitoring, alerting and profile control</div></div>
<div class="hero-badge"><span id="hero-dot" class="dot"></span><span id="hero-status">Checking monitor</span><div id="device-info" class="device-badge" style="margin-top:7px">Detecting device…</div></div>
</div>

<div class="panel recent-alerts-panel" id="recent-alerts-panel">
<div class="section-head recent-alerts-head"><div><h2><span class="recent-alerts-dot"></span>Recent Alerts</h2><div class="muted">Latest security activity, grouped by monitored account. Blocked-site access, profile changes, denylist actions and device events are shown separately.</div></div><div class="row"><span id="recent-alerts-count" class="pill">0 alerts</span><button type="button" class="neutral" onclick="markAllRecentAlertsSeen()">Mark all seen</button></div></div>
<div id="recent-alerts" class="recent-alerts-grid"><div class="muted">Loading recent alerts...</div></div>
</div>

<div class="panel">
<div class="row"><strong>Monitor:</strong><span id="runtime" class="muted">Checking...</span></div>
<button type="button" class="start" onclick="controlMonitor('start')">Start Monitoring</button>
<button type="button" class="stop" onclick="controlMonitor('stop')">Stop Monitoring</button>
<div class="status" id="health">Loading health...</div>
</div>

<div class="panel">
<div class="section-head"><div><h2>Profile Health</h2><div class="muted">Live monitoring status for every configured profile</div></div><span id="health-count" class="pill">0 profiles</span></div>
<div id="profile-health" class="health-grid"><div class="muted">Loading...</div></div>
</div>

<div class="panel"><div class="section-head"><div><h2>Device Activity</h2><div class="muted">Last observed DNS activity; inactivity does not prove DNS was disabled.</div></div><span id="device-count" class="pill">0 devices</span></div><div id="device-activity" class="device-state"><div class="muted">Loading...</div></div></div><div id="device-detail-panel" class="panel hidden"><div class="section-head"><div><h2>Device Details</h2><div id="device-detail-subtitle" class="muted"></div></div><button type="button" class="neutral" onclick="closeDeviceDetail()">Close</button></div><div id="device-detail-content" class="mini-list"></div></div>
<div id="device-editor" class="panel hidden"><h3>Edit Device</h3><form id="device-edit-form">
<input type="hidden" name="profile_id"><input type="hidden" name="device_id">
<label>Device Name<input name="device_name"></label><label>Device Model<input name="device_model"></label>
<label>Client IP<input name="client_ip"></label><label>Last Seen At<input name="last_seen_at"></label>
<label>Status<input name="last_status"></label><label>Last Domain<input name="last_domain"></label>
<label>Inactive Alerted At<input name="inactive_alerted_at"></label>
<button class="start" type="submit">Save Device</button><button class="neutral" type="button" onclick="closeDeviceEditor()">Cancel</button>
</form><div class="status" id="device-edit-message"></div></div>
<div class="panel">
<div class="section-head"><div><h2>Event Timeline</h2><div class="muted">Latest monitor and alert activity</div></div><span id="timeline-count" class="pill">0 events</span></div>
<div id="event-timeline" class="timeline"><div class="muted">Loading...</div></div>
</div>

<div class="panel">
<h2>NextDNS Profiles</h2>
<form id="account-form">
<label>NextDNS Account API key<input name="api_key" type="password" required placeholder="NextDNS account API key"></label>
<button class="neutral" type="button" onclick="discoverProfiles()">Load Profiles</button>
</form>
<div class="status" id="account-message"></div>
<div id="profile-picker" class="hidden"></div>
<div id="accounts">Loading monitored profiles...</div>
<div id="profile-editor" class="panel hidden">
<h3>Edit Monitored Profile</h3>
<form id="profile-edit-form">
<label>Local Display Name<input name="name" required></label>
<label>NextDNS Profile Name<input name="profile_name" required></label>
<label>NextDNS Account API key<input name="api_key" type="password" placeholder="Leave blank to keep the current API key"></label>
<div id="profile-meta" class="meta"></div>
<div class="status muted">Profile ID is read-only. NextDNS profile changes use the API only.</div>
<button class="start" type="submit">Save Changes</button>
<button class="stop" type="button" onclick="clearProfileDenylistFromEditor()">Clear Entire Denylist</button>
<button class="neutral" type="button" onclick="closeProfileEditor()">Cancel</button>
</form>
<div class="status" id="profile-edit-message"></div>
</div>
</div>

<div class="panel">
<div class="section-head"><div><h2>Configuration Changes</h2><div class="muted">Changes detected by comparing the live NextDNS profile with the last known snapshot.</div></div></div>
<div id="config-changes"><div class="muted">Loading...</div></div>
</div>
<div class="panel">
<div class="section-head"><div><h2>Advanced Profile API Control</h2><div class="muted">Edit one selected profile only. The readable view explains every field returned by the NextDNS API. The formatted JSON is the exact payload sent when you apply changes.</div></div></div>
<div class="meta">
<div><strong>Profile</strong><span>Choose one monitored profile. Changes never apply to other profiles.</span></div>
<div><strong>Security</strong><span>Threat and security filtering controls exposed by NextDNS.</span></div>
<div><strong>Privacy</strong><span>Blocklists, tracker/privacy and related privacy options.</span></div>
<div><strong>Parental Control</strong><span>Categories, services, SafeSearch and bypass controls.</span></div>
<div><strong>Settings</strong><span>Logging, retention, performance, block page and other settings.</span></div>
</div>
<div class="row"><select id="config-profile"></select><select id="config-section"><option value="profile">Profile overview</option><option value="security">Security</option><option value="privacy">Privacy</option><option value="parentalControl">Parental Control</option><option value="settings">Settings</option><option value="denylist">Denylist</option><option value="allowlist">Allowlist</option></select></div>
<div id="config-readable" class="mini-list"><div class="muted">Load a section to see a human-readable summary.</div></div>
<div id="config-form" class="scalable-list"><div class="muted">Load live configuration to edit supported fields.</div></div>
<div class="row"><button type="button" class="neutral" onclick="loadConfigSection()">Load Live Configuration</button><button type="button" class="neutral" onclick="clearConfigForm()">Clear</button><button type="button" class="start" onclick="saveConfigSection()">Apply Changes</button></div>
<div class="status" id="config-status">Select a profile and load its live configuration.</div>
</div>
<div class="panel">
<h2>Telegram Alerts</h2>
<form id="telegram-form">
<label>Bot name<input name="name" placeholder="Primary Bot"></label>
<label>Bot token<input name="token" type="password" placeholder="123456:ABC..."></label>
<label>Chat ID<input name="chat_id" placeholder="Telegram chat ID"></label>
<button class="start" type="submit">Add / Save Bot</button>
</form>
<div class="status" id="telegram-status">Checking...</div>
<div class="mini-list" id="telegram-bot-card"><div class="muted">Loading Telegram bots...</div></div>
<div id="telegram-editor" class="editor hidden">
<strong>Edit Telegram Bot</strong>
<form id="telegram-edit-form">
<label>Bot name<input name="name" placeholder="Telegram Bot"></label>
<label>Bot token<input name="token" type="password" placeholder="Leave blank to keep the current token"></label>
<label>Chat ID<input name="chat_id" placeholder="Telegram chat ID"></label>
<button class="start" type="submit">Save Bot Changes</button>
<button class="neutral" type="button" onclick="closeTelegramEditor()">Cancel</button>
</form>
<div class="status" id="telegram-edit-message"></div>
</div>
</div>

<div class="grid" id="stats"></div>

<div class="analytics">
<div class="panel">
<div class="section-head"><div><h2>Alert Activity</h2><div class="muted">Last 24 hours · hourly alert volume</div></div><span id="analytics-total" class="pill">0 alerts</span></div>
<div id="alert-chart" class="chart"></div>
</div>
<div class="panel">
<div class="section-head"><div><h2>Top Domains</h2><div class="muted">Most frequent recent alerts</div></div></div>
<div id="top-domains" class="mini-list"><div class="muted">Loading...</div></div><div class="panel" style="margin-top:12px"><div class="section-head"><div><h2>Per-Profile Analytics</h2><div class="muted">Detailed activity for each monitored profile: blocked access, domains, status and recent events.</div></div><span id="analytics-profile-count" class="pill">0 profiles</span></div><div id="analytics-profiles" class="scalable-list"><div class="muted">Loading profile analytics...</div></div></div>
</div>
</div>

<div class="analytics">
<div class="panel">
<div class="section-head"><div><h2>Risk & Incident Overview</h2><div class="muted">Severity, domain intelligence and correlated incidents</div></div></div>
<div id="risk-overview" class="meta"><div><strong>Open Incidents</strong><span id="open-incidents">0</span></div><div><strong>Critical</strong><span id="critical-alerts">0</span></div><div><strong>High</strong><span id="high-alerts">0</span></div><div><strong>Domain Risk</strong><span id="domain-risk">—</span></div></div>
</div>
<div class="panel">
<div class="section-head"><div><h2>Sentinel Health</h2><div class="muted">Storage and runtime self-check</div></div><span id="sentinel-health-pill" class="pill">Checking</span></div>
<div id="sentinel-health" class="mini-list"><div class="muted">Loading...</div></div>
</div>
</div>

<div class="panel">
<div class="section-head"><div><h2>Security Incidents</h2><div class="muted">Correlated alerts with investigation lifecycle</div></div><span id="incident-count" class="pill">0</span></div>
<div id="incidents" class="mini-list"><div class="muted">Loading...</div></div>
</div>

<div class="panel">
<div class="section-head"><div><h2>Domain Intelligence</h2><div class="muted">Local heuristic enrichment only; not a reputation verdict</div></div></div>
<div id="domain-intelligence" class="mini-list"><div class="muted">Loading...</div></div>
</div>

<div class="panel">
<div class="section-head"><div><h2>Search Everything</h2><div class="muted">Search alerts, incidents and audit activity</div></div></div>
<div class="row"><input id="global-search" placeholder="Search domain, reason, profile, action…"><button type="button" class="neutral" onclick="runGlobalSearch()">Search</button></div>
<div id="search-results" class="mini-list"><div class="muted">Enter a query to search.</div></div>
</div>

<div class="panel">
<div class="section-head"><div><h2>Audit & Delivery Center</h2><div class="muted">Dashboard actions and Telegram delivery history</div></div></div>
<div class="row"><button type="button" class="neutral" onclick="loadAudit()">Audit Log</button><button type="button" class="neutral" onclick="loadDelivery()">Telegram Delivery</button><button type="button" class="neutral" onclick="loadBulkHistory()">Bulk Operations</button><button type="button" class="neutral" onclick="exportJson()">Export JSON</button><button type="button" class="neutral" onclick="exportCsv()">Export CSV</button></div>
<div id="operations-center" class="mini-list"><div class="muted">Choose a history view.</div></div>
</div>

<div class="panel">
<div class="section-head"><div><h2>Denylist Management</h2><div class="muted">Choose exactly which monitored profile receives the change. Bulk actions are available separately when you intentionally want all active profiles.</div></div></div>
<div class="row"><select id="deny-profile"></select><input id="deny-domain" placeholder="example.com"><button type="button" class="start" onclick="profileDeny('add')">Add to selected profile</button><button type="button" class="stop" onclick="profileDeny('remove')">Remove from selected profile</button></div>
<div class="row"><button type="button" class="neutral" onclick="bulkDeny('add')">Add to all active profiles</button><button type="button" class="neutral" onclick="bulkDeny('remove')">Remove from all active profiles</button></div>
<div class="status" id="bulk-result">Select a profile and enter a domain.</div>
</div>
<div class="panel">
<div class="section-head"><div><h2>Profile Denylist</h2><div class="muted">Live entries fetched from the selected NextDNS profile.</div></div><button type="button" class="neutral" onclick="showSelectedDenylist()">Refresh List</button></div>
<div id="denylist">Select a profile to view its entries.</div>
</div>

<div class="panel">
<div class="section-head"><div><h2>Export & Backup</h2><div class="muted">Export investigation data or create a full SQLite backup</div></div></div>
<div class="row"><button type="button" class="neutral" onclick="exportJson()">Export JSON</button><button type="button" class="neutral" onclick="exportCsv()">Export CSV</button><button type="button" class="neutral" onclick="downloadBackup()">Download SQLite Backup</button></div>
<form id="restore-form" style="margin-top:8px"><label>Restore SQLite backup</label><input id="restore-file" type="file" accept=".db,.sqlite,.sqlite3"><button class="stop" type="submit">Restore Backup</button></form>
<div class="status" id="restore-status">Restoring replaces the current local database. Keep a backup first.</div>
</div>

<div class="panel">
<div class="section-head"><div><h2>Sentinel Control Center</h2><div class="muted">Operational controls, alert policy, diagnostics and safe maintenance</div></div><span id="live-pill" class="pill">Live</span></div>
<div class="row">
<select id="analytics-range" onchange="loadRangeAnalytics()"><option value="1">1 hour</option><option value="6">6 hours</option><option value="24" selected>24 hours</option><option value="168">7 days</option><option value="720">30 days</option></select>
<button type="button" class="neutral" onclick="loadControlCenter()">Refresh Control Center</button>
<button type="button" class="neutral" onclick="exportSettings()">Export Settings</button>
<label class="neutral" style="display:inline-flex;align-items:center;gap:6px;cursor:pointer">Import Settings<input id="settings-import" type="file" accept=".json,application/json" hidden onchange="importSettings(this)"></label>
</div>
<div id="control-summary" class="mini-list"><div class="muted">Loading...</div></div>
<div class="grid">
<div class="panel"><h3>Alert Rules</h3><div class="row"><input id="rule-name" placeholder="Rule name"><input id="rule-json" placeholder='{"action":"suppress","domain":"example.com"}'><button type="button" class="start" onclick="saveRule()">Save Rule</button></div><div id="rules-list" class="mini-list"></div></div>
<div class="panel"><h3>Maintenance / Suppression</h3><div class="row"><input id="maintenance-seconds" type="number" min="60" value="3600"><input id="maintenance-reason" placeholder="Reason"><button type="button" class="neutral" onclick="enableMaintenance()">Enable Maintenance</button></div><div class="row"><input id="suppression-fingerprint" placeholder="Fingerprint"><input id="suppression-seconds" type="number" min="30" value="600"><button type="button" class="neutral" onclick="addSuppression()">Suppress</button></div></div>
</div>
<div class="mini-list">
<div class="mini-item"><span><strong>Safe Mode</strong><br><span class="muted">Temporarily blocks configuration-changing API actions.</span></span><button type="button" class="neutral" onclick="toggleSafeMode()">Toggle</button></div>
<div class="mini-item"><span><strong>Diagnostics</strong><br><span class="muted">Checks database, encryption and required tables.</span></span><button type="button" class="neutral" onclick="loadDiagnostics()">Run</button></div>
<div class="mini-item"><span><strong>Incident Metrics</strong><br><span class="muted">Shows incident counts and mean time to resolve.</span></span><button type="button" class="neutral" onclick="loadIncidentMetrics()">View</button></div>
<div class="mini-item"><span><strong>Database Cleanup</strong><br><span class="muted">Deletes old operational records and attempts SQLite VACUUM.</span></span><span class="row"><input id="retention-days" type="number" min="1" value="30" style="max-width:90px"><button type="button" class="neutral" onclick="runRetention()">Run</button></span></div>
<div class="mini-item"><span><strong>Latest Config Diff</strong><br><span class="muted">Shows the latest detected configuration difference.</span></span><button type="button" class="neutral" onclick="showConfigDiff()">View</button></div>
<div class="mini-item"><span><strong>Risk / Baseline</strong><br><span class="muted">Shows historical risk and learned hourly activity baseline.</span></span><button type="button" class="neutral" onclick="loadRiskBaseline()">View</button></div>
<div class="mini-item"><span><strong>Rate Limits</strong><br><span class="muted">Shows recent NextDNS API rate-limit telemetry.</span></span><button type="button" class="neutral" onclick="loadRateLimits()">View</button></div>
<div class="mini-item"><span><strong>API Authentication</strong><br><span class="muted">Protects Sentinel's local API with a bearer token.</span></span><span class="row"><input id="api-auth-token" type="password" placeholder="16+ chars" style="max-width:180px"><button type="button" class="neutral" onclick="configureApiAuth()">Enable / Login</button><button type="button" class="neutral" onclick="logoutApiAuth()">Logout</button></span></div>
</div>
<div id="control-details" class="mini-list"></div>
</div>

<div class="panel">
<h2>Alert Log Storage</h2>
<label class="row"><input id="save-alert-logs" type="checkbox" style="width:auto;margin:0 8px 0 0"> Save Recent Alerts to file automatically</label>
<p class="muted">Alerts are also kept in SQLite. When enabled, each new alert is appended immediately to <code>data/recent_alerts.jsonl</code>.</p>
<button class="neutral" type="button" onclick="exportAlertLogs()">Save Existing Alerts to File</button>
<div class="status" id="alert-log-status">Checking...</div>
</div>

<div class="panel">
<div class="section-head"><div><h2>Security Alerts & Actions</h2><div class="muted">Blocked-site access, profile changes, denylist actions, device activity and system alerts</div></div><span id="alerts-count" class="pill">0 shown</span></div>
<div class="row"><input id="alert-search" type="search" placeholder="Search domain, account, reason, status…" autocomplete="off"><select id="alert-type-filter" style="max-width:260px"><option value="">All alert types</option><option value="security_alert">Security alerts</option><option value="profile_change">Profile changes</option><option value="denylist_action">Denylist actions</option><option value="device_activity">Device activity</option><option value="system_action">System actions</option><option value="config_change">Profile config change</option><option value="configuration_action">Configuration action</option><option value="denylist_match">Blocked-site access</option><option value="denylist_added">Denylist added</option><option value="denylist_removed">Denylist removed</option><option value="device_inactive">Device event</option><option value="configuration_undo">Configuration undo</option></select></div>
<div class="table-wrap"><table>
<thead><tr><th>Time</th><th>Type</th><th>Account</th><th>Device</th><th>Domain</th><th>Severity</th><th>Risk</th><th>Status</th><th>Reason</th><th>Notification</th><th>Seen</th></tr></thead>
<tbody id="alerts"></tbody>
</table></div>
</div>
</main>
</div>
</div>
<script>
function pad2(value){return String(value).padStart(2,'0');}
function formatDateTime(value){
 if(!value)return '—';
 const d=new Date(value);
 if(Number.isNaN(d.getTime()))return String(value);
 return d.getUTCFullYear()+'-'+pad2(d.getUTCMonth()+1)+'-'+pad2(d.getUTCDate())+' '+pad2(d.getUTCHours())+':'+pad2(d.getUTCMinutes())+':'+pad2(d.getUTCSeconds())+' UTC';
}
function formatTime(value){
 if(!value)return '—';
 const d=new Date(value);
 if(Number.isNaN(d.getTime()))return String(value);
 const hours=d.getUTCHours();
 const hour12=hours%12||12;
 const suffix=hours>=12?'PM':'AM';
 return pad2(hour12)+':'+pad2(d.getUTCMinutes())+' '+suffix;
}
function formatTimestampCell(td,value){td.textContent=formatDateTime(value);td.title=value||'';}

function renderIntelligence(data){
 const sev={};for(const x of data?.intelligence?.severity||[])sev[x.severity]=x.count;
 setText('open-incidents',data?.intelligence?.open_incidents||0,'');
 setText('critical-alerts',sev.critical||0,'');
 setText('high-alerts',sev.high||0,'');
 const risks=(data?.intelligence?.domain_risk||[]).map(x=>x.domain_risk+': '+x.count).join(' · ');
 setText('domain-risk',risks||'None','');
}
function editDevice(device){
 const form=document.getElementById('device-edit-form');if(!form)return;
 for(const field of ['profile_id','device_id','device_name','device_model','client_ip','last_seen_at','last_status','last_domain','inactive_alerted_at'])if(form.elements[field])form.elements[field].value=device[field]||'';
 document.getElementById('device-editor').classList.remove('hidden');setText('device-edit-message','Editing local device state.','muted');document.getElementById('device-editor').scrollIntoView({behavior:'smooth',block:'nearest'});
}
function closeDeviceEditor(){document.getElementById('device-editor').classList.add('hidden');document.getElementById('device-edit-form').reset();setText('device-edit-message','','');}
document.getElementById('device-edit-form')?.addEventListener('submit',async e=>{
 e.preventDefault();const d=Object.fromEntries(new FormData(e.target).entries());const profileId=d.profile_id,deviceId=d.device_id;delete d.profile_id;delete d.device_id;
 try{await api('/api/devices/'+encodeURIComponent(profileId)+'/'+encodeURIComponent(deviceId),{method:'PATCH',body:JSON.stringify(d)});closeDeviceEditor();await refresh();setText('device-edit-message','Device updated successfully.','ok');}
 catch(err){setText('device-edit-message','Save failed: '+err.message,'error');}
});
async function loadDeviceDetail(profileId,deviceId){
 try{
  const d=await api('/api/devices/'+encodeURIComponent(profileId)+'/'+encodeURIComponent(deviceId));
  const panel=document.getElementById('device-detail-panel');const box=document.getElementById('device-detail-content');if(!panel||!box)return;
  panel.classList.remove('hidden');box.replaceChildren();
  const device=d.device||{};
  setText('device-detail-subtitle',(device.account_name||profileId)+' · '+(device.device_name||deviceId)+' · '+(d.alerts?.length||0)+' alerts','muted');
  const fields=[['Device ID',device.device_id],['Model',device.device_model],['Client IP',device.client_ip],['Status',device.last_status],['Last Domain',device.last_domain],['Last Seen',formatDateTime(device.last_seen_at)]];
  for(const [label,value] of fields){const row=document.createElement('div');row.className='mini-item';row.innerHTML='<strong></strong><span></span>';row.firstChild.textContent=label;row.lastChild.textContent=value||'—';box.append(row);}
  const heading=document.createElement('div');heading.className='muted';heading.style.marginTop='8px';heading.textContent='Recent device alerts';box.append(heading);
  for(const a of d.alerts||[]){const row=document.createElement('div');row.className='mini-item';row.innerHTML='<span></span><strong></strong>';row.firstChild.textContent=(a.alert_type||'event')+' · '+(a.domain||a.reason||'No domain');row.lastChild.textContent=formatDateTime(a.event_timestamp||a.created_at);row.title=a.reason||'';box.append(row);}
  panel.scrollIntoView({behavior:'smooth',block:'nearest'});
 }catch(e){setText('device-detail-content','Details failed: '+e.message,'error');}
}
function closeDeviceDetail(){document.getElementById('device-detail-panel')?.classList.add('hidden');}
async function loadIncidentDetail(id){
 try{
  const d=await api('/api/incidents/'+id);const box=document.getElementById('operations-center');box.replaceChildren();
  const head=document.createElement('div');head.className='mini-item';head.innerHTML='<strong></strong><span></span>';
  head.firstChild.textContent='#'+d.id+' · '+d.title+' · '+d.status.toUpperCase();head.lastChild.textContent=d.risk_score+'/100 · '+d.severity.toUpperCase();box.append(head);
  for(const a of d.alerts||[]){const row=document.createElement('div');row.className='mini-item';row.innerHTML='<span></span><strong></strong>';row.firstChild.textContent=formatDateTime(a.event_timestamp||a.created_at)+' · '+(a.domain||a.alert_type);row.lastChild.textContent=(a.severity||'medium').toUpperCase()+' · '+(a.risk_score??'—')+'/100';row.title=a.reason||'';box.append(row);}
  box.scrollIntoView({behavior:'smooth',block:'nearest'});
 }catch(e){setText('operations-center',e.message,'error');}
}
async function loadIncidents(){
 const items=await api('/api/incidents?limit=20');const box=document.getElementById('incidents');box.replaceChildren();
 setText('incident-count',items.length+' incidents','');
 if(!items.length){box.textContent='No correlated incidents yet.';return;}
 for(const x of items){
  const row=document.createElement('div');row.className='mini-item';row.style.cursor='pointer';row.onclick=()=>loadIncidentDetail(x.id);
  const left=document.createElement('div');left.innerHTML='<strong></strong><div class="muted"></div>';
  left.firstChild.textContent='#'+x.id+' · '+x.title+' · '+x.severity.toUpperCase();
  left.lastChild.textContent=x.summary+' · '+x.alert_count+' alert(s) · '+formatDateTime(x.updated_at);
  const select=document.createElement('select');for(const s of ['open','investigating','resolved','ignored']){const o=document.createElement('option');o.value=s;o.textContent=s;o.selected=s===x.status;select.append(o);}
  select.onchange=async()=>{await api('/api/incidents/'+x.id+'/status',{method:'POST',body:JSON.stringify({status:select.value})});loadIncidents();};
  row.append(left,select);box.append(row);
 }
}
async function loadDomains(){
 const items=await api('/api/domains?limit=12');const box=document.getElementById('domain-intelligence');box.replaceChildren();
 if(!items.length){box.textContent='No domain intelligence available.';return;}
 for(const x of items){const row=document.createElement('div');row.className='mini-item';row.innerHTML='<span></span><strong></strong>';row.firstChild.textContent=x.domain+' · '+x.risk.toUpperCase();row.lastChild.textContent=x.score+'/100 · '+x.sightings;box.append(row);}
}
async function loadSentinelHealth(){
 const d=await api('/api/sentinel/health');const box=document.getElementById('sentinel-health');box.replaceChildren();
 const keys=Object.entries(d.checks||{});for(const [k,v] of keys){const row=document.createElement('div');row.className='mini-item';row.innerHTML='<span></span><strong></strong>';row.firstChild.textContent=k;row.lastChild.textContent=v?'OK':'FAIL';row.lastChild.className=v?'ok':'error';box.append(row);}
 setText('sentinel-health-pill',d.healthy?'Healthy':'Attention',d.healthy?'ok':'error');
}
async function runGlobalSearch(){
 const q=document.getElementById('global-search').value.trim();if(!q)return;
 const items=await api('/api/search?q='+encodeURIComponent(q));const box=document.getElementById('search-results');box.replaceChildren();
 if(!items.length){box.textContent='No results.';return;}
 for(const x of items){const row=document.createElement('div');row.className='mini-item';row.innerHTML='<span></span><strong></strong>';row.firstChild.textContent=x.type.toUpperCase()+' #'+x.id+' · '+(x.domain||x.profile_id);row.lastChild.textContent=formatDateTime(x.timestamp);row.title=x.reason||'';box.append(row);}
}
async function loadAudit(){
 const items=await api('/api/audit?limit=30');renderOperationList(items.map(x=>({main:x.action+' · '+x.target_type+' '+x.target_id,sub:x.actor+' · '+formatDateTime(x.created_at)})));
}
async function loadDelivery(){
 const items=await api('/api/delivery?limit=30');renderOperationList(items.map(x=>({main:x.channel.toUpperCase()+' · '+x.status+' · alert '+(x.alert_id||'—'),sub:x.account_name+' · '+formatDateTime(x.created_at)+(x.error?' · '+x.error:'')})));
}
async function loadBulkHistory(){
 const items=await api('/api/bulk-history?limit=30');renderOperationList(items.map(x=>({main:x.operation.toUpperCase()+' · '+x.domain,sub:'#'+x.id+' · '+x.successes+' success · '+x.failures+' failed · '+x.skipped+' skipped'})));
}
function renderOperationList(items){
 const box=document.getElementById('operations-center');box.replaceChildren();if(!items.length){box.textContent='No history.';return;}
 for(const x of items){const row=document.createElement('div');row.className='mini-item';row.innerHTML='<span></span><strong></strong>';row.firstChild.textContent=x.main;row.lastChild.textContent=x.sub;box.append(row);}
}
function exportJson(){window.open('/api/export/json','_blank');}
function exportCsv(){window.open('/api/export/csv','_blank');}
function downloadBackup(){window.open('/api/backup','_blank');}
bindDashboardListener('restore-form','submit',async e=>{
 if(!confirm('Restore the selected SQLite backup? Sentinel will create a rollback copy first.')){e.preventDefault();return;}
 e.preventDefault();const file=document.getElementById('restore-file').files[0];if(!file){setText('restore-status','Select a backup file first.','error');return;}
 if(!confirm('Restore this SQLite backup? Current local data will be replaced.'))return;
 const form=new FormData();form.append('backup',file);
 try{await api('/api/restore',{method:'POST',body:form,headers:{}});setText('restore-status','Backup restored successfully.','ok');refresh();}catch(err){setText('restore-status',err.message,'error');}
});


function renderAnalytics(data){
 const profileBox=document.getElementById('analytics-profiles');const profiles=data.profiles||[];setText('analytics-profile-count',profiles.length+' profiles','');if(profileBox){profileBox.replaceChildren();if(!profiles.length){profileBox.textContent='No profile activity recorded in this range.';}else{for(const p of profiles){const card=document.createElement('details');card.className='account';const summary=document.createElement('summary');summary.style.cursor='pointer';summary.textContent=(p.account_name||p.profile_id)+' · '+p.total_alerts+' alerts · '+p.blocked_count+' blocked';card.append(summary);const body=document.createElement('div');body.className='mini-list';const stats=document.createElement('div');stats.className='meta';[['Total Alerts',p.total_alerts],['Blocked Sites',p.blocked_count],['Profile ID',p.profile_id]].forEach(([k,v])=>{const item=document.createElement('div');item.innerHTML='<strong></strong><span></span>';item.firstChild.textContent=k;item.lastChild.textContent=String(v);stats.append(item);});body.append(stats);const dh=document.createElement('div');dh.className='muted';dh.textContent='Top domains';body.append(dh);for(const d of p.top_domains||[]){const row=document.createElement('div');row.className='mini-item';row.innerHTML='<span></span><strong></strong>';row.firstChild.textContent=d.domain;row.lastChild.textContent=d.count;body.append(row);}const eh=document.createElement('div');eh.className='muted';eh.style.marginTop='8px';eh.textContent='Recent events';body.append(eh);for(const e of p.recent_events||[]){const row=document.createElement('div');row.className='mini-item';row.innerHTML='<span></span><strong></strong>';row.firstChild.textContent=(e.alert_type||'event')+' · '+(e.domain||e.reason||'No domain');row.lastChild.textContent=formatDateTime(e.event_timestamp||e.created_at);row.title=(e.reason||'')+' · '+(e.status||'');body.append(row);}card.append(body);profileBox.append(card);}}}
 const chart=document.getElementById('alert-chart');chart.replaceChildren();
 const points=data.timeline||[];const max=Math.max(1,...points.map(x=>x.count));
 for(const point of points){
  const wrap=document.createElement('div');wrap.className='bar-wrap';wrap.title=formatDateTime(point.time)+': '+point.count+' alert(s)';
  const value=document.createElement('span');value.className='bar-value';value.textContent=point.count?point.count:'';value.style.display=point.count?'block':'none';
  const bar=document.createElement('div');bar.className='bar';bar.style.height=(point.count?Math.max(4,(point.count/max)*100):2)+'%';
  const label=document.createElement('span');label.className='bar-label';label.textContent=formatTime(point.time);
  wrap.append(value,bar,label);chart.append(wrap);
 }
 setText('analytics-total',(data.total_24h||0)+' alerts','');
 const list=document.getElementById('top-domains');list.replaceChildren();
 const domains=data.top_domains||[];
 if(!domains.length){list.textContent='No alerts recorded in the last 24 hours.';return;}
 const maxDomain=Math.max(1,...domains.map(x=>x.count));
 for(const item of domains){
  const row=document.createElement('div');row.className='mini-item';
  const left=document.createElement('div');left.style.minWidth='0';
  const name=document.createElement('div');name.textContent=item.domain;name.style.overflow='hidden';name.style.textOverflow='ellipsis';name.style.whiteSpace='nowrap';
  const progress=document.createElement('div');progress.className='progress';const fill=document.createElement('span');fill.style.width=(item.count/maxDomain*100)+'%';progress.append(fill);left.append(name,progress);
  const count=document.createElement('strong');count.textContent=item.count;row.append(left,count);list.append(row);
 }
}

function detectDevice(){
 const ua=navigator.userAgent||'';
 const platform=navigator.userAgentData?.platform||navigator.platform||'';
 let os='Desktop';
 if(/Android/i.test(ua))os='Android';
 else if(/Windows/i.test(ua)||/Win/i.test(platform))os='Windows';
 else if(/iPhone|iPad|iPod/i.test(ua))os='iOS';
 else if(/Mac/i.test(platform)||/Mac OS/i.test(ua))os='macOS';
 else if(/Linux/i.test(platform)||/Linux/i.test(ua))os='Linux';
 const mobile=/Android|iPhone|iPad|iPod|Mobile/i.test(ua);
 const device=mobile?'Mobile':('ontouchstart' in window&&innerWidth<900?'Tablet':'Desktop');
 document.body.classList.add('device-'+os.toLowerCase());
 const el=document.getElementById('device-info');
 if(el)el.textContent=os+' · '+device+' · '+innerWidth+'×'+innerHeight;
}
function renderDevices(items){
 const box=document.getElementById('device-activity');box.replaceChildren();setText('device-count',(items||[]).length+' devices','');
 if(!items?.length){box.textContent='No DNS activity has been observed yet.';return;}
 const now=Date.now();
 for(const x of items){
  const c=document.createElement('div');c.className='device-item';const n=document.createElement('div');n.className='name';n.textContent=x.device_name||x.device_id||'Unidentified device';
  const profile=document.createElement('div');profile.className='line';profile.innerHTML='<span>Profile</span><span></span>';profile.lastChild.textContent=x.account_name||x.profile_id;
  const last=x.last_seen_at?new Date(x.last_seen_at).getTime():0;const active=last&&now-last<=180000;
  const l=document.createElement('div');l.className='line';l.innerHTML='<span>Status</span><strong></strong>';l.lastChild.textContent=x.last_status|| (active?'Active recently':'No recent DNS activity');l.lastChild.className=active?'ok':'error';
  const ip=document.createElement('div');ip.className='line';ip.innerHTML='<span>Client IP</span><span></span>';ip.lastChild.textContent=x.client_ip||'—';
  const domain=document.createElement('div');domain.className='line';domain.innerHTML='<span>Last domain</span><span></span>';domain.lastChild.textContent=x.last_domain||'—';
  const alerts=document.createElement('div');alerts.className='line';alerts.innerHTML='<span>Alerts / blocked</span><span></span>';alerts.lastChild.textContent=String(x.alert_count||0)+' / '+String(x.blocked_count||0);
  const deny=document.createElement('div');deny.className='line';deny.innerHTML='<span>Profile denylist</span><span></span>';deny.lastChild.textContent=String(x.denylist_count||0)+' entries';
  const time=document.createElement('div');time.className='line';time.innerHTML='<span>Last seen</span><span></span>';time.lastChild.textContent=formatDateTime(x.last_seen_at);
  const actions=document.createElement('div');const detail=document.createElement('button');detail.className='neutral';detail.textContent='Details';detail.onclick=()=>loadDeviceDetail(x.profile_id,x.device_id);
  const edit=document.createElement('button');edit.className='neutral';edit.textContent='Edit';edit.onclick=e=>{e.stopPropagation();editDevice(x);};actions.append(detail,edit);
  c.append(n,profile,l,ip,domain,alerts,deny,time,actions);box.append(c);
 }
}

function renderProfileHealth(items){
 const box=document.getElementById('profile-health');box.replaceChildren();
 setText('health-count',(items||[]).length+' profiles','');
 if(!items?.length){box.textContent='No monitored profiles configured.';return;}
 for(const item of items){
  const card=document.createElement('div');card.className='health-card';
  const name=document.createElement('div');name.className='name';name.textContent=item.name||item.profile_id;
  const status=document.createElement('div');status.className='line';
  const label=document.createElement('span');label.textContent=item.active?'Monitoring enabled':'Disabled';
  const value=document.createElement('strong');value.className=item.status==='degraded'?'error':(item.status==='healthy'?'ok':'muted');value.textContent=item.status==='degraded'?'Degraded':(item.status==='healthy'?'Healthy':(item.status==='disabled'?'Disabled':'Starting'));
  status.append(label,value);
  const poll=document.createElement('div');poll.className='line';poll.innerHTML='<span>Last success</span><span></span>';poll.lastChild.textContent=formatDateTime(item.last_success_at);
  const failures=document.createElement('div');failures.className='line';failures.innerHTML='<span>Consecutive failures</span><span></span>';failures.lastChild.textContent=String(item.consecutive_failures||0);
  const err=document.createElement('div');err.className='line';err.innerHTML='<span>Last error</span><span></span>';err.lastChild.textContent=item.last_error?formatDateTime(item.last_error_at):'None';
  card.append(name,status,poll,failures,err);box.append(card);
 }
}
function renderTimeline(events){
 const box=document.getElementById('event-timeline');box.replaceChildren();
 const items=Array.isArray(events)?events:[];
 const groups=new Map();
 for(const event of items){const key=event.profile_id||'system';if(!groups.has(key))groups.set(key,[]);groups.get(key).push(event);}
 setText('timeline-count',items.length+' events','');
 if(!groups.size){box.textContent='No timeline events available yet.';return;}
 for(const [profileId,group] of groups){
  const card=document.createElement('details');card.className='account';
  const summary=document.createElement('summary');summary.style.cursor='pointer';
  const unseen=group.filter(x=>x.alert_id&&!x.seen).length;
  summary.textContent=(profileId==='system'?'System':profileId)+' · '+group.length+' events'+(unseen?' · NEW '+unseen:'');
  card.append(summary);
  const list=document.createElement('div');list.className='timeline';list.style.marginTop='8px';
  for(const event of group.slice(0,30)){
   const row=document.createElement('div');row.className='timeline-item';const dot=document.createElement('span');dot.className='timeline-dot '+(event.kind||'warn');
   const middle=document.createElement('div');const title=document.createElement('strong');title.textContent=event.title||'Event';const detail=document.createElement('div');detail.className='muted';detail.textContent=event.detail||'';middle.append(title,detail);
   const time=document.createElement('span');time.className='muted';time.textContent=formatDateTime(event.time);row.append(dot,middle,time);list.append(row);
  }
  card.append(list);
  card.addEventListener('toggle',async()=>{if(!card.open||card.dataset.seen)return;card.dataset.seen='1';const ids=group.filter(x=>x.alert_id&&!x.seen).map(x=>x.alert_id);for(const id of ids){try{await api('/api/alerts/'+id+'/seen',{method:'POST',_skipAutoRefresh:true});}catch(e){}}if(ids.length)await refresh();});
  box.append(card);
 }
}
function alertPresentation(alert){
 const type=String(alert?.alert_type||'').toLowerCase();
 if(type==='denylist_match')return {category:'security_alert',label:'🚫 Blocked Site',description:'Blocked-site access'};
 if(type==='config_changed'||type==='config_change'||type==='configuration_action'||type==='configuration_undo')return {category:'profile_change',label:type==='configuration_undo'?'↩️ Config Undo':'🔧 Profile Change',description:'Profile configuration change'};
 if(type==='denylist_added'||type==='denylist_removed')return {category:'denylist_action',label:type==='denylist_added'?'➕ Denylist Added':'➖ Denylist Removed',description:'Denylist action'};
 if(type.startsWith('device_'))return {category:'device_activity',label:type==='device_new'?'📱 New Device':'📱 Device Activity',description:'Device activity'};
 return {category:'system_action',label:'⚙️ System Action',description:'System or operational action'};
}
function recentAlertTime(alert){return alert?.event_timestamp||alert?.created_at||'';}
function recentAlertIcon(presentation){
 const category=presentation?.category||'system_action';
 if(category==='security_alert')return '🚫';
 if(category==='profile_change')return '🔧';
 if(category==='denylist_action')return '🛡️';
 if(category==='device_activity')return '📱';
 return '⚙️';
}
function renderRecentAlerts(alerts){
 const box=document.getElementById('recent-alerts');if(!box)return;
 const all=Array.isArray(alerts)?alerts.slice().sort((a,b)=>String(recentAlertTime(b)).localeCompare(String(recentAlertTime(a)))):[];
 const count=document.getElementById('recent-alerts-count');
 setText('recent-alerts-count',all.length+' alerts','');
 box.replaceChildren();
 if(!all.length){
  const empty=document.createElement('div');empty.className='recent-alert-empty muted';empty.textContent='No recent alerts yet.';box.append(empty);return;
 }
 const groups=new Map();
 for(const alert of all){
  const key=String(alert.profile_id||'__unassigned__');
  if(!groups.has(key))groups.set(key,[]);
  groups.get(key).push(alert);
 }
 let shownUnseen=0;
 for(const [profileId,items] of groups){
  const accountName=items[0]?.account_name||profileId||'Unassigned profile';
  const recent=items.slice(0,6);
  const unseen=items.filter(x=>!x.seen_at).length;
  shownUnseen+=unseen;
  const card=document.createElement('section');card.className='recent-alert-account'+(unseen?' unseen':'');
  const head=document.createElement('div');head.className='recent-alert-account-head';
  const title=document.createElement('div');title.className='recent-alert-account-title';
  const strong=document.createElement('strong');strong.textContent=accountName;
  const sub=document.createElement('div');sub.className='muted';sub.textContent=profileId||'No profile ID';
  title.append(strong,sub);
  const actions=document.createElement('div');actions.className='recent-alert-actions';
  if(unseen){
   const mark=document.createElement('button');mark.className='neutral';mark.textContent='Mark all seen';mark.onclick=()=>markRecentAccountSeen(profileId,items.filter(x=>!x.seen_at).map(x=>x.id));actions.append(mark);
  }else{
   const seen=document.createElement('span');seen.className='recent-alert-seen';seen.textContent='✓ All seen';actions.append(seen);
  }
  head.append(title,actions);card.append(head);
  const counts=new Map();
  for(const x of items){
   const p=alertPresentation(x);counts.set(p.category,(counts.get(p.category)||0)+1);
  }
  const summary=document.createElement('div');summary.className='recent-alert-summary';
  const labels={security_alert:'🚫 Blocked',profile_change:'🔧 Profile',denylist_action:'🛡️ Denylist',device_activity:'📱 Device',system_action:'⚙️ System'};
  for(const [category,total] of counts){
   const pill=document.createElement('span');pill.className='pill';pill.textContent=(labels[category]||category)+' · '+total;summary.append(pill);
  }
  card.append(summary);
  const list=document.createElement('div');list.className='recent-alert-list';
  for(const x of recent){
   const p=alertPresentation(x);
   const row=document.createElement('div');row.className='recent-alert-item'+(x.seen_at?'':' unseen');
   const icon=document.createElement('div');icon.className='recent-alert-icon';icon.textContent=recentAlertIcon(p);
   const main=document.createElement('div');main.className='recent-alert-main';
   const type=document.createElement('div');type.className='recent-alert-type';type.textContent=p.label;
   const detail=document.createElement('div');detail.className='recent-alert-detail';detail.textContent=x.domain||x.reason||x.status||p.description;
   const meta=document.createElement('div');meta.className='recent-alert-meta';
   const bits=[];
   if(x.device_name||x.device_id)bits.push('Device: '+(x.device_name||x.device_id));
   if(x.severity)bits.push('Severity: '+String(x.severity).toUpperCase());
   if(x.risk_score!==undefined&&x.risk_score!==null)bits.push('Risk: '+x.risk_score+'/100');
   if(x.status)bits.push('Status: '+x.status);
   if(x.reason&&x.domain)bits.push(x.reason);
   meta.textContent=bits.slice(0,3).join(' · ');
   main.append(type,detail,meta);
   const side=document.createElement('div');side.className='recent-alert-actions';
   const time=document.createElement('span');time.className='recent-alert-time';time.textContent=formatDateTime(recentAlertTime(x));time.title=recentAlertTime(x);
   const seen=document.createElement('button');seen.className='neutral';seen.textContent=x.seen_at?'Seen':'NEW';
   seen.onclick=async()=>{if(x.seen_at)return;await api('/api/alerts/'+x.id+'/seen',{method:'POST',_skipAutoRefresh:true});await refresh();};
   side.append(time,seen);
   row.append(icon,main,side);list.append(row);
  }
  card.append(list);
  if(items.length>recent.length){
   const more=document.createElement('div');more.className='muted';more.style.cssText='margin-top:7px;font-size:11px;text-align:center';more.textContent='Showing latest '+recent.length+' of '+items.length+' alerts for this account.';card.append(more);
  }
  box.append(card);
 }
 if(count)count.title=shownUnseen+' unread alerts';
}
async function markRecentAccountSeen(profileId,ids){
 const pending=Array.isArray(ids)?ids.filter(Boolean):[];
 if(!pending.length)return;
 await Promise.all(pending.map(id=>api('/api/alerts/'+id+'/seen',{method:'POST',_skipAutoRefresh:true})));
 await refresh();
}
async function markAllRecentAlertsSeen(){
 const ids=window.__recentAlertsCache?.filter(x=>!x.seen_at).map(x=>x.id)||[];
 if(!ids.length){showActionToast('All recent alerts are already seen.','ok');return;}
 await Promise.all(ids.map(id=>api('/api/alerts/'+id+'/seen',{method:'POST',_skipAutoRefresh:true})));
 await refresh();
 showActionToast('All recent alerts marked as seen.','ok');
}
function filterAlerts(){
 const q=(document.getElementById('alert-search').value||'').toLowerCase().trim();
 const type=(document.getElementById('alert-type-filter')?.value||'').toLowerCase();
 let shown=0;
 document.querySelectorAll('#alerts tr').forEach(row=>{
  const matchText=!q||row.textContent.toLowerCase().includes(q);
  const matchType=!type||String(row.dataset.alertType||'').toLowerCase()===type||String(row.dataset.alertCategory||'').toLowerCase()===type;
  const match=matchText&&matchType;row.style.display=match?'':'none';if(match)shown++;
 });
 setText('alerts-count',shown+' shown','');
}
const transientStatusIds=new Set(['account-message','profile-edit-message','bulk-result','config-status','telegram-status','telegram-edit-message','alert-log-status','control-details']);
function setText(id,text,cls=''){
 const e=document.getElementById(id);if(!e)return;
 e.textContent=text;e.className=cls;
 if(transientStatusIds.has(id)){
  window.__statusTimers=window.__statusTimers||{};
  clearTimeout(window.__statusTimers[id]);
  if(text)window.__statusTimers[id]=setTimeout(()=>{e.textContent='';e.className='';},5000);
 }
}
function showActionToast(message,type='error'){
 const e=document.getElementById('action-toast');if(!e)return;
 e.textContent=message;e.className='toast show '+type;clearTimeout(window.__toastTimer);
 window.__toastTimer=setTimeout(()=>{e.className='toast';},5000);
}
let autoRefreshTimer=null;
function scheduleAutoRefresh(){
 clearTimeout(autoRefreshTimer);
 autoRefreshTimer=setTimeout(()=>refresh().catch(()=>{}),120);
}
async function api(path,options={}){
  try{
    const headers={...(options.headers||{})};
    if(!(options.body instanceof FormData))headers['Content-Type']=headers['Content-Type']||'application/json';
    const r=await fetch(path,{...options,headers});
    const d=await r.json().catch(()=>({}));
    if(r.status===401 && !options._authRetry){
      const token=window.prompt('Sentinel API authentication is enabled. Enter your API token:');
      if(token){
        const login=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token})});
        if(login.ok)return api(path,Object.assign({},options,{_authRetry:true}));
      }
    }
    if(!r.ok)throw new Error(d.error||'HTTP '+r.status);
    const method=String(options.method||'GET').toUpperCase();
    if(['POST','PATCH','PUT','DELETE'].includes(method) && !options._skipAutoRefresh) scheduleAutoRefresh();
    return d;
  }catch(e){
    const error=e instanceof TypeError?new Error('Dashboard could not reach the local API. Make sure Sentinel is running and try again.'):e;
    showActionToast(error.message,'error');
    throw error;
  }
}
async function controlMonitor(action){try{const d=await api('/api/monitor/'+action,{method:'POST'});setText('runtime',d.running?'Running':'Stopped',d.running?'ok':'muted');await refresh();showActionToast(action==='start'?'Monitoring started.':'Monitoring stopped.','ok');}catch(e){setText('runtime',e.message,'error');}}
async function discoverProfiles(){
 const form=document.getElementById('account-form');const apiKey=form.elements.api_key.value.trim();
 if(!apiKey){setText('account-message','Enter the NextDNS account API key first.','error');return;}
 try{
  const profiles=await api('/api/profiles/discover',{method:'POST',body:JSON.stringify({api_key:apiKey})});
  const picker=document.getElementById('profile-picker');picker.replaceChildren();picker.className='';
  if(!profiles.length){setText('account-message','No NextDNS profiles were returned for this API key.','error');return;}
  const title=document.createElement('div');title.textContent='Select a profile to monitor:';picker.append(title);
  const select=document.createElement('select');select.id='profile-select';select.style.cssText='width:100%;box-sizing:border-box;background:#0b1019;color:#e8edf7;border:1px solid #303b4e;border-radius:8px;padding:10px;margin:8px 0';
  for(const p of profiles){const o=document.createElement('option');o.value=p.id;o.textContent=p.name+' ('+p.id+')';select.append(o);}picker.append(select);
  const save=document.createElement('button');save.className='start';save.textContent='Monitor Selected Profile';save.onclick=()=>saveSelectedProfile(apiKey,profiles);picker.append(save);
  setText('account-message',profiles.length+' profile(s) loaded from NextDNS API.','ok');
 }catch(err){setText('account-message',err.message,'error');}
}
async function saveSelectedProfile(apiKey,profiles){
 const id=document.getElementById('profile-select').value;const p=profiles.find(x=>x.id===id)||{};
 try{
  await api('/api/setup/account',{method:'POST',body:JSON.stringify({api_key:apiKey,profile_id:id,profile_name:p.name||'',name:p.name||''})});
  setText('account-message','Selected profile is now monitored.','ok');refresh();
 }catch(err){setText('account-message',err.message,'error');}
}
bindDashboardListener('account-form','submit',e=>{e.preventDefault();discoverProfiles();});
bindDashboardListener('telegram-form','submit',async e=>{
 e.preventDefault();const d=Object.fromEntries(new FormData(e.target).entries());
 try{await api('/api/settings/telegram',{method:'POST',body:JSON.stringify(d)});setText('telegram-status','Telegram configured and encrypted locally.','ok');e.target.reset();refresh();}
 catch(err){setText('telegram-status',err.message,'error');}
});
async function toggleTelegramBot(id,enabled){try{await api('/api/settings/telegram/bots/'+id+'/enable',{method:'POST',body:JSON.stringify({enabled})});await refresh();}catch(e){setText('telegram-status',e.message,'error');}}
async function testTelegramBot(id){try{await api('/api/settings/telegram/bots/'+id+'/test',{method:'POST'});setText('telegram-status','Test notification sent.','ok');await refresh();}catch(e){setText('telegram-status',e.message,'error');}}
async function deleteTelegramBot(id){if(!confirm('Delete this Telegram bot?'))return;try{await api('/api/settings/telegram/bots/'+id,{method:'DELETE'});setText('telegram-status','Telegram bot deleted.','muted');await refresh();}catch(e){setText('telegram-status',e.message,'error');}}
async function editTelegramBot(id){
 try{const bots=await api('/api/settings/telegram/bots');const bot=bots.find(x=>Number(x.id)===Number(id));if(!bot)throw new Error('Telegram bot not found.');
  const form=document.getElementById('telegram-edit-form');form.dataset.botId=String(id);form.elements.name.value=bot.name||'Telegram Bot';form.elements.chat_id.value=bot.chat_id||'';form.elements.token.value='';
  document.getElementById('telegram-editor').classList.remove('hidden');setText('telegram-edit-message','Editing '+bot.name+'. Leave token blank to keep it.','muted');document.getElementById('telegram-editor').scrollIntoView({behavior:'smooth',block:'nearest'});
 }catch(e){setText('telegram-status',e.message,'error');}
}
async function deleteTelegramCredentials(){if(!confirm('Delete the saved Telegram bot token and chat ID from Sentinel?'))return;try{await api('/api/settings/telegram/credentials',{method:'DELETE'});setText('telegram-status','Telegram credentials deleted.','muted');refresh();}catch(e){setText('telegram-status',e.message,'error');}}
async function testTelegram(){try{await api('/api/settings/telegram/test',{method:'POST'});setText('telegram-status','Test notification sent.','ok');}catch(e){setText('telegram-status',e.message,'error');}}
async function enableTelegram(){try{const d=await api('/api/settings/telegram/enable',{method:'POST'});setText('telegram-status','Enabled · '+(d.status||'ready'),'ok');refresh();}catch(e){setText('telegram-status',e.message,'error');}}
async function disableTelegram(){try{await api('/api/settings/telegram',{method:'DELETE'});closeTelegramEditor();setText('telegram-status','Telegram disabled. Saved bot credentials were kept.','muted');refresh();}catch(e){setText('telegram-status',e.message,'error');}}
async function editTelegram(){const bots=await api('/api/settings/telegram/bots');if(bots.length)editTelegramBot(bots[0].id);}
function closeTelegramEditor(){
 document.getElementById('telegram-editor').classList.add('hidden');
 document.getElementById('telegram-edit-form').reset();
 setText('telegram-edit-message','','');
}
bindDashboardListener('telegram-edit-form','submit',async e=>{
 e.preventDefault();
 const d=Object.fromEntries(new FormData(e.target).entries());d.id=e.target.dataset.botId;
 if(!d.id){setText('telegram-edit-message','Select a Telegram bot to edit.','error');return;}
 try{
  await api('/api/settings/telegram/bots',{method:'POST',body:JSON.stringify(d)});
  closeTelegramEditor();
  setText('telegram-status','Telegram bot updated and encrypted locally.','ok');
  await refresh();
 }catch(err){setText('telegram-edit-message',err.message,'error');}
});

let editingProfileId='';

async function editProfile(id){
  editingProfileId=id;
  document.getElementById('profile-editor').classList.remove('hidden');
  try{
    const data=await api('/api/accounts/'+encodeURIComponent(id));
    const form=document.getElementById('profile-edit-form');
    form.elements.name.value=data.name||'';
    form.elements.profile_name.value=data.profile_name||'';
    form.elements.api_key.value='';
    const p=data.profile||{};
    const meta=document.getElementById('profile-meta');meta.replaceChildren();
    const fields=[
      ['Profile ID',data.profile_id],['Status',data.active?'Active':'Inactive'],
      ['Denylist',p.denylist_entries??0],['Allowlist',p.allowlist_entries??0],
      ['Blocklists',p.blocklists??0],['Parental Services',p.parental_services??0],
      ['Parental Categories',p.parental_categories??0],['Logs',p.logs_enabled?'Enabled':'Disabled'],
      ['Block Page',p.block_page_enabled?'Enabled':'Disabled'],['Web3',p.web3_enabled?'Enabled':'Disabled']
    ];
    for(const [label,value] of fields){
      const item=document.createElement('div');
      const strong=document.createElement('strong');strong.textContent=label;
      const valueNode=document.createElement('span');valueNode.textContent=String(value);
      item.append(strong,valueNode);meta.append(item);
    }
    document.getElementById('profile-editor').classList.remove('hidden');
    setText('profile-edit-message','Live profile information loaded from NextDNS API.','ok');
    document.getElementById('profile-editor').scrollIntoView({behavior:'smooth',block:'nearest'});
  }catch(e){
    document.getElementById('profile-editor').classList.remove('hidden');
    setText('profile-edit-message','Unable to load this profile: '+e.message,'error');
  }
}
async function clearProfileDenylistFromEditor(){
 if(!editingProfileId)return;
 if(!confirm('Remove every denylist entry from this profile? This affects only the selected profile.'))return;
 try{const d=await api('/api/denylist/'+encodeURIComponent(editingProfileId),{method:'DELETE'});setText('profile-edit-message','Cleared '+(d.removed||0)+' denylist entries.','ok');await refresh();}catch(e){setText('profile-edit-message','Clear denylist failed: '+e.message,'error');}
}
function closeProfileEditor(){
  editingProfileId='';
  document.getElementById('profile-editor').classList.add('hidden');
  document.getElementById('profile-edit-form').reset();
  setText('profile-edit-message','','');
}
bindDashboardListener('profile-edit-form','submit',async e=>{
  e.preventDefault();
  if(!editingProfileId)return;
  const profileId=editingProfileId;
  const data=Object.fromEntries(new FormData(e.target).entries());
  const submit=e.target.querySelector('button[type="submit"]');
  if(submit)submit.disabled=true;
  setText('profile-edit-message','Saving profile changes…','muted');
  try{
    const result=await api('/api/accounts/'+encodeURIComponent(profileId),{method:'PATCH',body:JSON.stringify(data)});
    await refresh();
    closeProfileEditor();
    setText('account-message','Profile '+(result.profile_name||profileId)+' updated successfully.','ok');
  }catch(err){
    setText('profile-edit-message','Save failed: '+err.message,'error');
  }finally{
    if(submit)submit.disabled=false;
  }
});

async function deleteAccount(id){
 if(!confirm('Delete this profile and its local state?'))return;
 try{await api('/api/accounts/'+encodeURIComponent(id),{method:'DELETE'});await refresh();setText('account-message','Profile deleted successfully.','ok');}
 catch(e){setText('account-message','Delete failed: '+e.message,'error');}
}
async function toggleAccount(id,active){try{await api('/api/accounts/'+encodeURIComponent(id)+'/toggle',{method:'POST',body:JSON.stringify({active})});await refresh();setText('account-message',active?'Profile enabled successfully.':'Profile disabled successfully.','ok');}catch(e){setText('account-message','Action failed: '+e.message,'error');}}
async function renderGroupedDenylist(accounts){
 const box=document.getElementById('denylist');if(!box)return;
 box.replaceChildren();
 if(!accounts?.length){box.textContent='No monitored profiles configured.';return;}
 for(const account of accounts){
  const details=document.createElement('details');details.className='account';
  const summary=document.createElement('summary');summary.style.cursor='pointer';summary.textContent=(account.name||account.profile_id)+' · '+(account.profile_name||account.profile_id);
  const body=document.createElement('div');body.className='mini-list';body.textContent='Expand to load live denylist…';
  details.append(summary,body);
  details.addEventListener('toggle',async()=>{
   if(!details.open||details.dataset.loaded)return;
   details.dataset.loaded='1';
   try{
    const list=await api('/api/denylist/'+encodeURIComponent(account.profile_id));body.replaceChildren();
    const head=document.createElement('div');head.className='muted';head.textContent=list.length+' live entries';body.append(head);
    for(const domain of list.slice(0,1000)){
     const row=document.createElement('div');row.className='mini-item';const name=document.createElement('span');name.textContent=domain;
     const b=document.createElement('button');b.className='stop';b.textContent='Remove';b.onclick=async()=>{document.getElementById('deny-profile').value=account.profile_id;await profileDeny('remove',domain);details.dataset.loaded='';details.open=true;};
     row.append(name,b);body.append(row);
    }
   }catch(e){body.textContent=e.message;}
  });
  box.append(details);
 }
}
async function showDenylist(id){
 document.getElementById('deny-profile').value=id;
 navigateToTarget('profiles','denylist');
 await showSelectedDenylist();
}
async function showSelectedDenylist(){
 const id=document.getElementById('deny-profile').value;
 if(!id){setText('denylist','Select a profile first.','error');return;}
 try{
  const list=await api('/api/denylist/'+encodeURIComponent(id));const box=document.getElementById('denylist');box.replaceChildren();
  const h=document.createElement('div');h.className='muted';h.textContent=list.length+' live entries';box.append(h);
  for(const d of list.slice(0,500)){
   const row=document.createElement('div');row.className='mini-item';
   const name=document.createElement('span');name.textContent=d;
   const b=document.createElement('button');b.className='stop';b.textContent='Remove';b.onclick=()=>profileDeny('remove',d);
   row.append(name,b);box.append(row);
  }
 }catch(e){setText('denylist',e.message,'error');}
}
async function profileDeny(action,explicitDomain=''){
 const id=document.getElementById('deny-profile').value;
 const domain=(explicitDomain||document.getElementById('deny-domain').value).trim();
 if(!id){setText('bulk-result','Select the target profile first.','error');return;}
 if(!domain){setText('bulk-result','Enter a domain first.','error');return;}
 if(!confirm((action==='add'?'Add ':'Remove ')+domain+' '+(action==='add'?'to':'from')+' the selected profile?'))return;
 try{
  const opts=action==='add'
   ?{method:'POST',body:JSON.stringify({domain})}
   :{method:'DELETE'};
  const d=await api('/api/denylist/'+encodeURIComponent(id)+(action==='remove'?'/'+encodeURIComponent(domain):''),opts);
  setText('bulk-result',action.toUpperCase()+' succeeded for '+id+'. '+(d.entries?.length??0)+' entries now active.','ok');
  document.getElementById('deny-domain').value='';
  await refresh();
  document.getElementById('deny-profile').value=id;
  await showSelectedDenylist();
 }catch(e){setText('bulk-result','Action failed: '+e.message,'error');}
}
async function bulkDeny(action){
 if(!confirm((action==='add'?'Add':'Remove')+' this domain across all active profiles?'))return;
 const domain=document.getElementById('deny-domain').value.trim();if(!domain){setText('bulk-result','Enter a domain.','error');return;}
 try{
  const d=await api('/api/denylist/bulk',{method:'POST',body:JSON.stringify({domain,action})});
  const failed=(d.results||[]).filter(x=>x.status==='failed').map(x=>(x.profile_name||x.profile_id)+': '+x.reason).join(' | ');
  setText('bulk-result',action.toUpperCase()+': '+d.successes+' succeeded, '+d.failures+' failed, '+d.skipped+' skipped.'+(failed?' Failures: '+failed:''),d.failures?'error':'ok');
  await refresh();
 }catch(e){setText('bulk-result','Action failed: '+e.message,'error');}
}
function configChangeDiff(before,after,path=''){
 const changes=[];const keys=new Set([...Object.keys(before||{}),...Object.keys(after||{})]);
 for(const key of keys){
  const p=path?path+'.'+key:key;const a=before?.[key],b=after?.[key];
  if(a&&b&&typeof a==='object'&&typeof b==='object'&&!Array.isArray(a)&&!Array.isArray(b))changes.push(...configChangeDiff(a,b,p));
  else if(JSON.stringify(a)!==JSON.stringify(b)){
   if(a===undefined)changes.push({field:p,type:'added',before:'',after:b});
   else if(b===undefined)changes.push({field:p,type:'removed',before:a,after:''});
   else changes.push({field:p,type:'changed',before:a,after:b});
  }
 }
 return changes;
}
async function loadConfigChanges(){
 try{
  const items=await api('/api/config-changes');const box=document.getElementById('config-changes');box.replaceChildren();
  if(!items.length){box.textContent='No configuration changes detected.';return;}
  for(const x of items.slice(0,50)){
   const details=document.createElement('details');details.className='account';const summary=document.createElement('summary');summary.style.cursor='pointer';
   summary.textContent=x.profile_id+' · '+x.change_type+' · '+formatDateTime(x.changed_at)+(x.undone_at?' · Undone':'');
   const body=document.createElement('div');body.className='mini-list';const meta=document.createElement('div');meta.className='muted';meta.textContent='Trigger: '+(x.source||'unknown')+' · Time: '+formatDateTime(x.changed_at);body.append(meta);
   let before={},after={};try{before=JSON.parse(x.before_json||'{}');after=JSON.parse(x.after_json||'{}');}catch(e){}
   const diffs=configChangeDiff(before,after);
   if(!diffs.length){const empty=document.createElement('div');empty.className='muted';empty.textContent='No field-level difference recorded.';body.append(empty);}
   for(const diff of diffs.slice(0,100)){
    const row=document.createElement('div');row.className='mini-item';const left=document.createElement('strong');left.textContent=diff.field;const right=document.createElement('span');right.textContent=diff.type==='added'?'Added: '+JSON.stringify(diff.after):diff.type==='removed'?'Removed: '+JSON.stringify(diff.before):JSON.stringify(diff.before)+' → '+JSON.stringify(diff.after);row.append(left,right);body.append(row);
   }
   const actions=document.createElement('div');const b=document.createElement('button');b.className='neutral';b.textContent=x.undone_at?'Undone':'Undo';b.disabled=!!x.undone_at;b.onclick=async()=>{b.disabled=true;try{await api('/api/config-changes/'+x.id+'/undo',{method:'POST'});await refresh();await loadConfigChanges();}catch(e){b.disabled=false;setText('account-message','Undo failed: '+e.message,'error');}};actions.append(b);body.append(actions);
   details.append(summary,body);box.append(details);
  }
 }catch(e){setText('config-status','Unable to load configuration changes: '+e.message,'error');}
}

function renderConfigReadable(value,path=''){
 const box=document.getElementById('config-readable');box.replaceChildren();
 const walk=(obj,prefix)=>{if(obj===null||typeof obj!=='object'){const row=document.createElement('div');row.className='mini-item';row.innerHTML='<strong></strong><span></span>';row.firstChild.textContent=prefix||'value';row.lastChild.textContent=String(obj);box.append(row);return;}for(const [key,val] of Object.entries(obj)){const label=(prefix?prefix+'.':'')+key;if(val&&typeof val==='object'&&!Array.isArray(val)){const head=document.createElement('div');head.className='mini-item';head.innerHTML='<strong></strong><span></span>';head.firstChild.textContent=label;head.lastChild.textContent='section';box.append(head);walk(val,label);}else{const row=document.createElement('div');row.className='mini-item';row.innerHTML='<strong></strong><span></span>';row.firstChild.textContent=label;row.lastChild.textContent=Array.isArray(val)?(val.length+' item(s)'):String(val);box.append(row);}}};
 walk(value,path);
}
function configLabel(label){const raw=String(label??'').replace(/([a-z])([A-Z])/g,'$1 $2').replace(/[_-]+/g,' ').trim();return raw?raw.charAt(0).toUpperCase()+raw.slice(1):'Value';}
function buildConfigControl(value,path,label,parent){
 if(value&&typeof value==='object'&&!Array.isArray(value)){
  const details=document.createElement('details');details.open=true;details.style.margin='6px 0';const summary=document.createElement('summary');summary.style.cursor='pointer';summary.textContent=configLabel(label);details.append(summary);
  for(const [key,val] of Object.entries(value))buildConfigControl(val,path.concat(key),key,details);parent.append(details);return;
 }
 const row=document.createElement('label');row.style.margin='6px 0';row.textContent=configLabel(label);
 if(Array.isArray(value)){const input=document.createElement('textarea');input.rows=Math.min(8,Math.max(2,value.length+1));input.dataset.path=JSON.stringify(path);input.dataset.kind='array-json';input.value=JSON.stringify(value,null,2);input.style.width='100%';row.append(input);}
 else{const input=document.createElement('input');input.dataset.path=JSON.stringify(path);if(typeof value==='boolean'){input.type='checkbox';input.checked=value;input.dataset.kind='boolean';}else if(typeof value==='number'){input.type='number';input.step=Number.isInteger(value)?'1':'any';input.value=String(value);input.dataset.kind='number';}else{input.type='text';input.value=value==null?'':String(value);input.dataset.kind='string';}row.append(input);}
 parent.append(row);
}
function renderConfigForm(value){const box=document.getElementById('config-form');box.replaceChildren();configFormSource=JSON.parse(JSON.stringify(value||{}));if(!value||typeof value!=='object'){box.textContent='No editable configuration was returned.';return;}for(const [key,val] of Object.entries(value))buildConfigControl(val,[key],key,box);}
function collectConfigForm(){const result=JSON.parse(JSON.stringify(configFormSource||{}));document.querySelectorAll('#config-form [data-path]').forEach(input=>{const path=JSON.parse(input.dataset.path);let value;if(input.dataset.kind==='boolean')value=!!input.checked;else if(input.dataset.kind==='number')value=input.value===''?null:Number(input.value);else if(input.dataset.kind==='array-json'){try{value=JSON.parse(input.value||'[]');}catch(e){throw new Error('Invalid array JSON for '+path.join('.'));}}else value=input.value;setConfigPath(result,path,value);});return result;}
function clearConfigForm(){if(configFormSource)renderConfigForm(configFormSource);}
async function loadConfigSection(){const id=document.getElementById('config-profile').value;const section=document.getElementById('config-section').value;if(!id)return;try{const d=await api('/api/profiles/'+encodeURIComponent(id)+'/config/'+encodeURIComponent(section));renderConfigForm(d);renderConfigReadable(d);setText('config-status','Live configuration loaded. Edit the fields below and apply when ready.','ok');}catch(e){setText('config-status','Load failed: '+e.message,'error');}}
async function saveConfigSection(){const id=document.getElementById('config-profile').value;const section=document.getElementById('config-section').value;let data;try{data=collectConfigForm();}catch(e){setText('config-status',e.message,'error');return;}try{const preview=await api('/api/profiles/'+encodeURIComponent(id)+'/config/'+encodeURIComponent(section),{method:'PATCH',body:JSON.stringify(Object.assign({},data,{_preview:true}))});const changed=preview.changed_fields||[];if(!changed.length){setText('config-status','No changes detected. Nothing will be sent to NextDNS.','muted');return;}if(!confirm('Fields changed: '+changed.join(', ')+'\\n\\nApply these changes to the selected NextDNS profile?'))return;await api('/api/profiles/'+encodeURIComponent(id)+'/config/'+encodeURIComponent(section),{method:'PATCH',body:JSON.stringify(data)});setText('config-status','Change applied successfully and verified against the live profile.','ok');await refresh();await loadConfigChanges();await loadConfigSection();}catch(e){setText('config-status','Change failed: '+e.message,'error');}}

async function loadAlertLogSettings(){
 try{
  const d=await api('/api/settings/alert-logs');
  const checkbox=document.getElementById('save-alert-logs');
  checkbox.checked=!!d.enabled;
  setText('alert-log-status',d.enabled?'Automatic file saving is enabled.':'Automatic file saving is disabled.','muted');
 }catch(e){setText('alert-log-status',e.message,'error');}
}
async function setAlertLogSaving(enabled){
 try{
  const d=await api('/api/settings/alert-logs',{method:'POST',body:JSON.stringify({enabled})});
  setText('alert-log-status',d.enabled?'Automatic saving enabled.':'Automatic saving disabled.','ok');
 }catch(e){
  document.getElementById('save-alert-logs').checked=!enabled;
  setText('alert-log-status',e.message,'error');
 }
}
async function exportAlertLogs(){
 try{
  const d=await api('/api/settings/alert-logs/export',{method:'POST'});
  setText('alert-log-status',d.count+' alert(s) saved to '+d.path+'.','ok');
 }catch(e){setText('alert-log-status',e.message,'error');}
}
bindDashboardListener('save-alert-logs','change',e=>setAlertLogSaving(e.target.checked));

let lastAlertId=(()=>{try{return Number(localStorage.getItem('sentinel_last_alert_id')||0)}catch(e){return 0}})();
let notificationPermissionRequested=false;
function notifyNewDenylistAlerts(alerts){
 const fresh=alerts.filter(x=>Number(x.id||0)>lastAlertId && String(x.alert_type||'')==='denylist_match');
 const newest=Math.max(lastAlertId,...alerts.map(x=>Number(x.id||0)));
 if(lastAlertId && fresh.length){
   const x=fresh[fresh.length-1];
   const title='NextDNS Sentinel · Denylist match';
   const body=(x.domain||'Unknown domain')+' on '+(x.account_name||'profile');
   showActionToast('Denylist alert: '+body,'error');
   if('Notification' in window && Notification.permission==='granted' && 'serviceWorker' in navigator){
     navigator.serviceWorker.ready.then(reg=>{
       if(reg && typeof reg.showNotification==='function'){
         return reg.showNotification(title,{body,tag:'sentinel-alert-'+String(x.id||''),renotify:false});
       }
     }).catch(()=>{});
   }
 } else if(!notificationPermissionRequested && 'Notification' in window && Notification.permission==='default'){
   notificationPermissionRequested=true;
   Notification.requestPermission().catch(()=>{});
 }
 if(newest>lastAlertId){try{localStorage.setItem('sentinel_last_alert_id',String(newest))}catch(e){}}
 lastAlertId=Math.max(lastAlertId,newest);
}

async function refresh(){
 try{
  const rt=await api('/api/runtime');setText('runtime',rt.running?'Running':'Stopped',rt.running?'ok':'muted');
  try{
  const tg=await api('/api/settings/telegram');
  setText('telegram-status',tg.enabled?'Enabled · @'+(tg.bot_username||'bot')+' · '+(tg.chat_title||tg.chat_id):(tg.configured?'Disabled · Saved bot available to enable.':'Disabled · No Telegram bot configured.'),tg.enabled?'ok':'muted');
  const botCard=document.getElementById('telegram-bot-card');if(botCard){
   botCard.replaceChildren();const bots=await api('/api/settings/telegram/bots');
   if(!bots.length){const empty=document.createElement('div');empty.className='muted';empty.textContent='No Telegram bots configured.';botCard.append(empty);}
   for(const bot of bots){
    const item=document.createElement('div');item.className='account';const info=document.createElement('div');
    const title=document.createElement('strong');title.textContent=bot.name+' · '+(bot.bot_username?'@'+bot.bot_username:'unknown');
    const detail=document.createElement('div');detail.className='muted';detail.textContent=(bot.enabled?'Working':'Disabled')+' · '+(bot.chat_title||bot.chat_id||'chat')+' · Last sent: '+formatDateTime(bot.last_notification_at)+(bot.last_error?' · Error: '+bot.last_error:'');info.append(title,detail);
    const actions=document.createElement('div');actions.className='actions';
    const toggle=document.createElement('button');toggle.className=bot.enabled?'stop':'start';toggle.textContent=bot.enabled?'Disable':'Enable';toggle.onclick=()=>toggleTelegramBot(bot.id,!bot.enabled);
    const edit=document.createElement('button');edit.className='neutral';edit.textContent='Edit';edit.onclick=()=>editTelegramBot(bot.id);
    const test=document.createElement('button');test.className='neutral';test.textContent='Test';test.onclick=()=>testTelegramBot(bot.id);
    const del=document.createElement('button');del.className='stop';del.textContent='Delete';del.onclick=()=>deleteTelegramBot(bot.id);actions.append(toggle,edit,test,del);item.append(info,actions);botCard.append(item);
   }
  }
 }catch(e){setText('telegram-status','Telegram status error: '+e.message,'error');}
  const s=await api('/api/stats');const stats=document.getElementById('stats');stats.replaceChildren();
  const cards=[
    ['Monitored Profiles',s.accounts],['Active Profiles',s.active_accounts],['Alerts Total',s.alerts],['Denylist Entries',s.denylist_entries],['Poll Interval',s.poll_interval_seconds+'s']
  ];
  const cardTargets={
    'Monitored Profiles':['profiles','accounts'],
    'Active Profiles':['overview','profile-health'],
    'Alerts Total':['security','alerts'],
    'Denylist Entries':['profiles','denylist'],
    'Poll Interval':['overview','health']
  };
  for(const [label,value] of cards){
    const card=document.createElement('div');card.className='card';card.style.cursor='pointer';card.tabIndex=0;
    const l=document.createElement('div');l.className='muted';l.textContent=label;const val=document.createElement('div');val.className='value';val.textContent=value;card.append(l,val);
    const target=cardTargets[label];if(target){card.onclick=()=>navigateToTarget(target[0],target[1]);card.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();navigateToTarget(target[0],target[1]);}}}
    stats.append(card);
  }
  const analytics=await api('/api/analytics');renderAnalytics(analytics);renderIntelligence(analytics);loadIncidents();loadDomains();loadSentinelHealth();
  const health=document.getElementById('health');health.className='status '+(s.last_error?'error':'ok');health.textContent=s.last_error?'Monitor error: '+s.last_error+' · '+formatDateTime(s.last_error_at):'Monitor healthy · Last successful poll: '+formatDateTime(s.last_success_at);
  const heroDot=document.getElementById('hero-dot');heroDot.className='dot '+(s.last_error?'':'ok');setText('hero-status',s.last_error?'Attention required':'Monitoring healthy',s.last_error?'error':'ok');
  const healthData=await api('/api/health');renderProfileHealth(healthData);
  const timelineData=await api('/api/timeline');renderTimeline(timelineData);
  const devices=await api('/api/devices');renderDevices(devices);
  const accounts=await api('/api/accounts');const box=document.getElementById('accounts');box.replaceChildren();
  renderGroupedDenylist(accounts);
  if(!accounts.length){box.textContent='No profiles configured. Add one above.';}
  else{
   const wrap=document.createElement('div');wrap.className='table-wrap';
   const table=document.createElement('table');table.innerHTML='<thead><tr><th>Account</th><th>NextDNS Profile</th><th>Profile ID</th><th>Status</th><th>Actions</th></tr></thead><tbody></tbody>';
   const body=table.querySelector('tbody');
   for(const a of accounts){
    const tr=document.createElement('tr');
    [a.name,a.profile_name,a.profile_id,a.active?'Active':'Inactive'].forEach(v=>{const td=document.createElement('td');td.textContent=v||'—';tr.append(td);});
    const actions=document.createElement('td');
    const b=document.createElement('button');b.className=a.active?'stop':'start';b.textContent=a.active?'Disable':'Enable';b.onclick=()=>toggleAccount(a.profile_id,!a.active);
    const v=document.createElement('button');v.className='neutral';v.textContent='Denylist';v.onclick=()=>showDenylist(a.profile_id);
    const edit=document.createElement('button');edit.className='neutral';edit.textContent='Edit';edit.onclick=()=>editProfile(a.profile_id);
    const del=document.createElement('button');del.className='stop';del.textContent='Delete';del.onclick=()=>deleteAccount(a.profile_id);
    actions.append(b,v,edit,del);tr.append(actions);body.append(tr);
   }
   wrap.append(table);box.append(wrap);
  }
  const cfgSelect=document.getElementById('config-profile');const oldCfg=cfgSelect.value;cfgSelect.replaceChildren();
  const denySelect=document.getElementById('deny-profile');const oldDeny=denySelect.value;denySelect.replaceChildren();
  for(const a of accounts){
   const o=document.createElement('option');o.value=a.profile_id;o.textContent=a.name+' · '+a.profile_name+' ('+a.profile_id+')';cfgSelect.append(o);
   const d=document.createElement('option');d.value=a.profile_id;d.textContent=a.name+' · '+a.profile_name+' ('+a.profile_id+')';denySelect.append(d);
  }
  if(oldCfg && [...cfgSelect.options].some(o=>o.value===oldCfg))cfgSelect.value=oldCfg;
  if(oldDeny && [...denySelect.options].some(o=>o.value===oldDeny))denySelect.value=oldDeny;
  if(denySelect.value && localStorage.getItem('sentinel_active_page')==='profiles') await showSelectedDenylist();
  const alerts=await api('/api/alerts');window.__recentAlertsCache=alerts;notifyNewDenylistAlerts(alerts);renderRecentAlerts(alerts);const body=document.getElementById('alerts');body.replaceChildren();
  renderTimeline(healthData,alerts);
  for(const x of alerts){
   const tr=document.createElement('tr');const presentation=alertPresentation(x);tr.dataset.alertType=x.alert_type||'';tr.dataset.alertCategory=presentation.category;if(!x.seen_at)tr.style.background='rgba(53,199,111,.10)';
   const vals=[x.event_timestamp,x.account_name,x.device_name||x.device_id||'Unidentified',x.domain,x.severity||'—',(x.risk_score??'—')+'/100',x.status,x.reason,x.notification_status];
   const timeTd=document.createElement('td');formatTimestampCell(timeTd,x.event_timestamp);tr.append(timeTd);
   const typeTd=document.createElement('td');const typeStrong=document.createElement('strong');typeStrong.textContent=presentation.label;typeTd.append(typeStrong);typeTd.title=presentation.description;tr.append(typeTd);
   vals.slice(1).forEach(v=>{const td=document.createElement('td');td.textContent=v??'';tr.append(td);});
   const td=document.createElement('td');const b=document.createElement('button');b.className='neutral';b.textContent=x.seen_at?'Seen':'NEW';b.onclick=async()=>{await api('/api/alerts/'+x.id+'/seen',{method:'POST'});refresh()};td.append(b);tr.append(td);body.append(tr);
  }
  filterAlerts();
 }catch(e){setText('health','Dashboard error: '+e.message,'error');showActionToast('Refresh failed: '+e.message,'error');}
}
function dashboardErrorMessage(error){
 const message=error?.message||String(error||'Unknown dashboard error');
 console.error('NextDNS Sentinel dashboard error:',error);
 return message;
}
function showDashboardError(message){
 const health=document.getElementById('health');
 if(health){health.className='status error';health.textContent='Dashboard error: '+message;}
 if(typeof showActionToast==='function')showActionToast('Dashboard error: '+message,'error');
}
function bindDashboardListener(id,event,handler){
 const el=document.getElementById(id);
 if(el)el.addEventListener(event,handler);
}
function dashboardPagePanelIds(){
 return {
  overview:['stats','health','profile-health','event-timeline','hero-dot','runtime'],
  analytics:['alert-chart','top-domains','risk-overview','sentinel-health'],
  devices:['device-activity','device-editor'],
  security:['incidents','domain-intelligence','global-search','operations-center','alerts','alert-search','alert-type-filter'],
  profiles:['account-form','accounts','profile-editor','config-changes','config-profile','config-readable','config-form','config-section','deny-profile','deny-domain','denylist'],
  notifications:['telegram-form','telegram-status','telegram-bot-card','telegram-editor'],
  operations:['control-summary','rules-list','maintenance-seconds','suppression-fingerprint','control-details','api-auth-token'],
  data:['restore-form','restore-file','save-alert-logs','alert-log-status']
 };
}
function topLevelDashboardPanel(el){
 if(!el)return null;
 const main=document.querySelector('.app-content main');
 if(!main)return el.closest('.panel, .analytics, .grid');
 let node=el;
 while(node.parentElement && node.parentElement!==main){
  node=node.parentElement;
 }
 if(node.parentElement!==main)return null;
 if(!node.matches('.panel, .analytics, .grid'))return null;
 return node;
}
function setupDashboardPages(){
 const map=dashboardPagePanelIds();
 const pageByContainer=new Map();
 for(const [page,ids] of Object.entries(map)){
  for(const id of ids){
   const container=topLevelDashboardPanel(document.getElementById(id));
   if(container&&!pageByContainer.has(container))pageByContainer.set(container,page);
  }
 }
 const main=document.querySelector('.app-content main');
 if(main){
  main.querySelectorAll(':scope > *').forEach(container=>{
   const page=pageByContainer.get(container);
   if(page)container.dataset.page=page;
   else if(container.id!=='stats')delete container.dataset.page;
  });
 }
 const stats=document.getElementById('stats');
 if(stats)stats.dataset.page='overview';
}
function navigateToTarget(page,targetId){
 const allowed=Object.prototype.hasOwnProperty.call(dashboardPagePanelIds(),page)?page:'overview';
 const target=targetId?String(targetId):'';
 if(target){
  const targetEl=document.getElementById(target);
  if(!targetEl)console.warn('Dashboard target not found:',target);
 }
 if((localStorage.getItem('sentinel_active_page')||'overview')===allowed){
  showPage(allowed);
  if(target)requestAnimationFrame(()=>document.getElementById(target)?.scrollIntoView({behavior:'smooth',block:'start'}));
 }else{
  if(target)sessionStorage.setItem('sentinel_scroll_target',target);
  showPage(allowed);
 }
}
function scrollToPendingTarget(page){
 const target=sessionStorage.getItem('sentinel_scroll_target');
 if(!target)return;
 sessionStorage.removeItem('sentinel_scroll_target');
 setTimeout(()=>document.getElementById(target)?.scrollIntoView({behavior:'smooth',block:'start'}),80);
}
function showPage(page){
 const allowed=Object.prototype.hasOwnProperty.call(dashboardPagePanelIds(),page)?page:'overview';
 localStorage.setItem('sentinel_active_page',allowed);
 setupDashboardPages();
 const main=document.querySelector('.app-content main');
 if(main){
  main.querySelectorAll(':scope > [data-page]').forEach(container=>{
   container.style.display=container.dataset.page===allowed?'':'none';
  });
 }
 const stats=document.getElementById('stats');
 if(stats)stats.style.display=allowed==='overview'?'grid':'none';
 document.querySelectorAll('.nav-btn').forEach(button=>button.classList.toggle('active',button.dataset.page===allowed));
 try{
  if(allowed==='analytics'){loadRangeAnalytics();loadRiskBaseline();}
  if(allowed==='operations')loadControlCenter();
  if(allowed==='security'){loadIncidents();loadDomains();}
  if(allowed==='devices')refresh();
  if(allowed==='profiles')loadConfigChanges();
  if(allowed==='notifications')refresh();
  if(allowed==='data')loadAlertLogSettings();
 }catch(error){showDashboardError(dashboardErrorMessage(error));}
 if(window.innerWidth<=900)toggleSidebar(false);
 scrollToPendingTarget(allowed);
}
function toggleSidebar(force){
 const sidebar=document.getElementById('sidebar');
 if(!sidebar)return;
 const open=typeof force==='boolean'?force:!sidebar.classList.contains('open');
 sidebar.classList.toggle('open',open);
}
document.addEventListener('click',event=>{
 const target=event.target.closest?.('[data-nav-page]');
 if(!target)return;
 event.preventDefault();
 navigateToTarget(target.dataset.navPage,target.dataset.navTarget||'');
});
document.addEventListener('click',event=>{
 const sidebar=document.getElementById('sidebar');
 if(!sidebar?.classList.contains('open'))return;
 if(sidebar.contains(event.target)||event.target.closest?.('#sidebar-toggle'))return;
 toggleSidebar(false);
});
function dashboardBoot(){
 const steps=[
  ['page setup',()=>setupDashboardPages()],
  ['initial page',()=>showPage(localStorage.getItem('sentinel_active_page')||'overview')],
  ['device detection',()=>detectDevice()],
  ['alert search binding',()=>bindDashboardListener('alert-search','input',filterAlerts)],
  ['alert type binding',()=>bindDashboardListener('alert-type-filter','change',filterAlerts)],
  ['alert log settings',()=>loadAlertLogSettings()],
  ['config changes',()=>loadConfigChanges()],
  ['control center',()=>loadControlCenter()],
  ['initial refresh',()=>refresh()]
 ];
 for(const [name,fn] of steps){
  try{fn();}
  catch(error){console.error('Dashboard boot step failed:',name,error);showDashboardError(name+': '+dashboardErrorMessage(error));}
 }
 try{window.addEventListener('resize',detectDevice);}catch(error){console.error(error);}
 if(window.__sentinelRefreshTimer){
  clearInterval(window.__sentinelRefreshTimer);
  window.__sentinelRefreshTimer=null;
 }
}
window.addEventListener('error',event=>{
 const message=event?.error?.message||event?.message;
 if(message)showDashboardError(message);
});
window.addEventListener('unhandledrejection',event=>{
 const message=event?.reason?.message||String(event?.reason||'Unknown promise rejection');
 showDashboardError(message);
});

async function loadRiskBaseline(){try{const [risk,base]=await Promise.all([api('/api/risk-history?days=30'),api('/api/baseline')]);const riskText=risk.slice(-10).map(x=>x.day+': avg '+Number(x.avg_risk||0).toFixed(1)+' · max '+x.max_risk+' · '+x.alerts+' alerts').join(' | ');const baseText=base.slice(0,12).map(x=>x.bucket_hour+':00 '+Number(x.baseline||0).toFixed(1)+' avg').join(' · ');setText('control-details','Risk history: '+(riskText||'No data')+' || Baseline: '+(baseText||'No data'),'muted')}catch(e){setText('control-details',e.message,'error')}}
async function runRetention(){const days=Math.max(1,Number(document.getElementById('retention-days').value)||30);if(!confirm('Clean Sentinel data older than '+days+' days?'))return;try{const d=await api('/api/retention',{method:'POST',body:JSON.stringify({days})});setText('control-details','Retention cleanup removed '+d.deleted+' records.','ok');await refresh();await loadControlCenter();}catch(e){setText('control-details',e.message,'error')}}
async function showConfigDiff(){try{const accounts=await api('/api/accounts');if(!accounts.length){setText('control-details','No profiles configured.','muted');return}const d=await api('/api/config-diff/'+encodeURIComponent(accounts[0].profile_id));setText('control-details',d.changed?d.diff.map(x=>x.field+': '+JSON.stringify(x.before)+' → '+JSON.stringify(x.after)).join(' | '):'No recent configuration diff for '+accounts[0].profile_id,'muted')}catch(e){setText('control-details',e.message,'error')}}
async function configureApiAuth(){
 const token=document.getElementById('api-auth-token').value.trim();if(!token)return alert('Enter an API token.');
 try{const d=await api('/api/auth/configure',{method:'POST',body:JSON.stringify({token})});setText('control-details',d.enabled?'API authentication enabled.':'API authentication unchanged.','ok');document.getElementById('api-auth-token').value='';}catch(e){setText('control-details',e.message,'error')}
}
async function logoutApiAuth(){try{await api('/api/auth/logout',{method:'POST'});setText('control-details','API session logged out.','muted')}catch(e){setText('control-details',e.message,'error')}}
async function loadControlCenter(){
 try{
  const d=await api('/api/control-center');const box=document.getElementById('control-summary');box.replaceChildren();
  const rows=[['Safe Mode',d.safe_mode?'Enabled':'Disabled'],['Rules',String(d.rules?.length||0)],['Maintenance',d.maintenance?(d.maintenance.reason||'Active'):'Inactive'],['Database',d.diagnostics?.database?'OK':'Error'],['Schema',d.diagnostics?.schema?'OK':'Error']];
  for(const [a,b] of rows){const x=document.createElement('div');x.className='mini-item';x.innerHTML='<strong></strong><span></span>';x.firstChild.textContent=a;x.lastChild.textContent=b;box.append(x);}
  const rl=document.getElementById('rules-list');rl.replaceChildren();
  for(const r of d.rules||[]){const x=document.createElement('div');x.className='mini-item';x.innerHTML='<span></span><button type="button" class="stop">Delete</button>';x.firstChild.textContent=r.name+' · '+(r.enabled?'Enabled':'Disabled');x.lastChild.onclick=async()=>{await api('/api/rules/'+r.id,{method:'DELETE'});loadControlCenter()};rl.append(x);}
 }catch(e){setText('control-summary',e.message,'error')}
}
async function loadRangeAnalytics(){
 const h=document.getElementById('analytics-range').value;try{const d=await api('/api/analytics?hours='+h);renderAnalytics(d);renderIntelligence(d);}catch(e){setText('health',e.message,'error')}
}
async function saveRule(){
 const name=document.getElementById('rule-name').value.trim();let rule={};
 try{rule=JSON.parse(document.getElementById('rule-json').value||'{}')}catch(e){alert('Rule JSON is invalid.');return}
 if(!name)return alert('Rule name is required.');
 await api('/api/rules',{method:'POST',body:JSON.stringify({name,rule,enabled:true})});document.getElementById('rule-name').value='';document.getElementById('rule-json').value='';loadControlCenter();
}
async function enableMaintenance(){
 const seconds=Math.max(60,Number(document.getElementById('maintenance-seconds').value)||3600);const reason=document.getElementById('maintenance-reason').value.trim();
 await api('/api/maintenance',{method:'POST',body:JSON.stringify({scope:'global',seconds,reason})});loadControlCenter();
}
async function addSuppression(){
 const fingerprint=document.getElementById('suppression-fingerprint').value.trim();const seconds=Math.max(30,Number(document.getElementById('suppression-seconds').value)||600);
 if(!fingerprint)return alert('Fingerprint is required.');
 await api('/api/suppressions',{method:'POST',body:JSON.stringify({fingerprint,seconds,reason:'Dashboard suppression'})});loadControlCenter();
}
async function toggleSafeMode(){
 const d=await api('/api/control-center');const enabled=!d.safe_mode;await api('/api/safe-mode',{method:'POST',body:JSON.stringify({enabled})});loadControlCenter();
}
async function loadDiagnostics(){const d=await api('/api/diagnostics');setText('control-details',Object.entries(d).map(([k,v])=>k+': '+(v?'OK':'FAIL')).join(' · '),Object.values(d).every(Boolean)?'ok':'error');}
async function loadIncidentMetrics(){const d=await api('/api/incident-metrics');setText('control-details','Incidents: '+d.total_incidents+' · Open: '+d.open_incidents+' · Resolved: '+d.resolved_incidents+' · MTTR: '+d.mean_time_to_resolve_seconds+'s · Alerts: '+d.total_alerts,'muted');}
async function loadRateLimits(){const d=await api('/api/control-center');setText('control-details',(d.rate_limits||[]).map(x=>x.endpoint+' · retry '+x.retry_after+'s · '+formatDateTime(x.created_at)).join(' | ')||'No rate-limit events recorded.','muted');}
async function exportSettings(){const d=await api('/api/settings/export');const blob=new Blob([JSON.stringify(d,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='nextdns-sentinel-settings.json';a.click();URL.revokeObjectURL(a.href);}
async function importSettings(input){if(!input.files?.[0])return;try{const text=await input.files[0].text();const d=await api('/api/settings/import',{method:'POST',body:text});setText('control-details','Imported '+JSON.stringify(d.imported),'ok');loadControlCenter();}catch(e){setText('control-details',e.message,'error')}input.value='';}


// Start the dashboard only after every dashboard function has been declared.
// This prevents initialization from running against the temporal-dead-zone of
// later const/let declarations and makes boot ordering deterministic.
function startDashboardWhenReady(){
 if(document.readyState==='loading'){
  document.addEventListener('DOMContentLoaded',dashboardBoot,{once:true});
 }else{
  dashboardBoot();
 }
}
startDashboardWhenReady();
</script>
</body>
</html>"""

def request_json() -> dict[str, Any]:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def create_app(store: Store, sentinel: Sentinel, features: FeatureStore) -> Flask:
    app = Flask(__name__)
    @app.after_request
    def _dashboard_no_cache(response):
        if request.path == "/" or request.path.startswith("/assets/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response

    app.secret_key = SECRET_KEY
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")

    # Keep dashboard navigation icons self-contained so the single-file app does
    # not depend on a separate static-assets directory.
    dashboard_icons = {
        "dashboard.svg": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#aebbd0" stroke-width="1.8"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>',
        "overview.svg": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#aebbd0" stroke-width="1.8"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.7"/></svg>',
        "features.svg": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#aebbd0" stroke-width="1.8"><path d="M4 19V9M10 19V5M16 19v-7M22 19V3"/><path d="M2 19h21"/></svg>',
        "project.svg": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#aebbd0" stroke-width="1.8"><rect x="4" y="3" width="16" height="18" rx="2"/><path d="M9 7h6M8 17h8M8 13h3"/></svg>',
        "security.svg": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#aebbd0" stroke-width="1.8"><path d="M12 3 20 6v5c0 5-3.2 8.3-8 10-4.8-1.7-8-5-8-10V6l8-3Z"/><path d="m8.5 12 2.2 2.2 4.8-5"/></svg>',
        "config.svg": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#aebbd0" stroke-width="1.8"><path d="M4 6h16M4 12h16M4 18h16"/><circle cx="9" cy="6" r="2"/><circle cx="15" cy="12" r="2"/><circle cx="11" cy="18" r="2"/></svg>',
        "process.svg": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#aebbd0" stroke-width="1.8"><rect x="3" y="4" width="7" height="5" rx="1"/><rect x="14" y="15" width="7" height="5" rx="1"/><path d="M10 6.5h3a3 3 0 0 1 3 3V15M16 12l3 3-3 3"/></svg>',
        "storage.svg": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#aebbd0" stroke-width="1.8"><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v7c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 12v7c0 1.7 3.6 3 8 3s8-1.3 8-3v-7"/></svg>',
    }

    @app.get("/assets/icons/<path:icon>")
    def dashboard_icon(icon: str) -> Any:
        svg = dashboard_icons.get(icon)
        if svg is None:
            return jsonify({"error": "Icon not found."}), 404
        return app.response_class(svg, mimetype="image/svg+xml")

    @app.before_request
    def safe_mode_guard():
        if request.path.startswith("/api/") and store.setting("api_auth_hash",""):
            if request.path not in {"/api/auth/status","/api/auth/login","/api/auth/configure","/api/auth/logout"} and not session.get("sentinel_authenticated"):
                token=request.headers.get("Authorization","")
                supplied=token[7:] if token.lower().startswith("bearer ") else ""
                if not supplied or not hashlib.sha256(supplied.encode()).hexdigest()==store.setting("api_auth_hash",""):
                    return jsonify({"error":"Sentinel API authentication required."}),401
        if request.path.startswith("/api/") and request.method in {"POST","PATCH","DELETE"}:
            protected=("/api/denylist","/api/config-changes/","/api/profiles/")
            if store.setting("safe_mode","0")=="1" and request.path.startswith(protected):
                if request.path=="/api/profiles/discover":
                    return None
                return jsonify({"error":"Safe Mode is enabled. NextDNS configuration changes are blocked until Safe Mode is disabled."}),423
        return None

    @app.get("/api/auth/status")
    def api_auth_status() -> Any:
        return jsonify({"enabled":bool(store.setting("api_auth_hash","")),"authenticated":bool(session.get("sentinel_authenticated"))})

    @app.post("/api/auth/configure")
    def api_auth_configure() -> Any:
        if store.setting("api_auth_hash","") and not session.get("sentinel_authenticated"):
            return jsonify({"error":"Authentication is already configured."}),403
        token=str(request_json().get("token","")).strip()
        if len(token)<16: return jsonify({"error":"Use an API token with at least 16 characters."}),400
        store.set_setting("api_auth_hash",hashlib.sha256(token.encode()).hexdigest())
        session["sentinel_authenticated"]=True
        features.audit("api_auth_configure","security","api",details={"enabled":True})
        return jsonify({"enabled":True,"authenticated":True})

    @app.post("/api/auth/login")
    def api_auth_login() -> Any:
        token=str(request_json().get("token","")).strip()
        expected=store.setting("api_auth_hash","")
        if not expected or hashlib.sha256(token.encode()).hexdigest()!=expected:
            return jsonify({"error":"Invalid API token."}),401
        session["sentinel_authenticated"]=True
        return jsonify({"authenticated":True})

    @app.post("/api/auth/logout")
    def api_auth_logout() -> Any:
        session.pop("sentinel_authenticated",None)
        return jsonify({"authenticated":False})

    @app.get("/")
    def index() -> str:
        if store.setting("api_auth_hash","") and not session.get("sentinel_authenticated"):
            return render_template_string(AUTH_PAGE), 401
        return render_template_string(DASHBOARD)

    @app.get("/api/stats")
    def api_stats() -> Any:
        return jsonify(store.stats())

    @app.get("/api/health")
    def api_health() -> Any:
        return jsonify(store.monitor_health())

    @app.get("/api/alerts")
    def api_alerts() -> Any:
        return jsonify(features.alerts(200))

    @app.get("/api/timeline")
    def api_timeline() -> Any:
        events=[]
        for alert in features.alerts(100):
            events.append({"time":alert.get("event_timestamp") or alert.get("created_at") or "",
                           "title":alert.get("domain") or str(alert.get("alert_type") or "Security event").replace("_"," ").title(),
                           "detail":alert.get("reason") or alert.get("status") or "Security event",
                           "kind":"warn","profile_id":alert.get("profile_id",""),"alert_id":alert.get("id"),"seen":bool(alert.get("seen_at"))})
        for change in store.config_changes(100):
            events.append({"time":change.get("changed_at") or "","title":"Configuration change",
                           "detail":f'{change.get("profile_id","")} · {change.get("change_type","")}',
                           "kind":"config","profile_id":change.get("profile_id",""),"change_id":change.get("id")})
        for audit in features.audit_entries(100):
            events.append({"time":audit.get("created_at") or "",
                           "title":str(audit.get("action") or "Audit event").replace("_"," ").title(),
                           "detail":audit.get("target_id") or audit.get("target_type") or "Sentinel action",
                           "kind":"audit","profile_id":audit.get("profile_id",""),"audit_id":audit.get("id")})
        events.sort(key=lambda item:str(item.get("time") or ""),reverse=True)
        return jsonify(events[:200])

    @app.get("/api/config-changes")
    def api_config_changes() -> Any:
        return jsonify(store.config_changes())

    @app.post("/api/config-changes/<int:change_id>/undo")
    def api_config_undo(change_id:int) -> Any:
        changes=store.config_changes(200)
        change=next((x for x in changes if x["id"]==change_id),None)
        if not change: return jsonify({"error":"Change not found."}),404
        if change.get("undone_at"): return jsonify({"error":"This configuration change was already undone."}),409
        account=next((a for a in store.accounts() if a["profile_id"]==change["profile_id"]),None)
        if not account: return jsonify({"error":"Profile is no longer configured locally."}),404
        try:
            before=json.loads(change["before_json"]); after=json.loads(change["after_json"])
            client=NextDNSClient(account["api_key"])
            current=config_snapshot(client.profile(change["profile_id"]))
            if current!=after:
                return jsonify({"error":"Undo refused: the profile changed again after this audit event."}),409
            rollback={k:before[k] for k in before if before.get(k)!=after.get(k)}
            if not rollback:
                return jsonify({"error":"Nothing to undo."}),409
            client._patch(f"/profiles/{change['profile_id']}",rollback)
            verified=config_snapshot(client.profile(change["profile_id"]))
            if verified!=before:
                return jsonify({"error":"Undo was sent but the live profile did not match the previous configuration."}),502
            store.mark_change_undone(change_id)
            store.save_config_snapshot(change["profile_id"],before)
            features.audit("configuration_undo","profile",change["profile_id"],change["profile_id"],{"change_id":change_id,"fields":sorted(rollback)})
            key=hashlib.sha256(f"config_undo:{change['profile_id']}:{change_id}:{utc_now()}".encode()).hexdigest()
            store.add_alert(change["profile_id"],account["name"],"","",f"Configuration change #{change_id} was undone","configuration_undo","",utc_now(),key,"configuration_action",source="sentinel_dashboard")
            alert_id=sentinel.enrich_alert(key,account,"",f"Configuration change #{change_id} was undone","configuration_undo","","",utc_now(),"","","","",False)
            delivered=sentinel.notify(account,"",f"Configuration change #{change_id} was undone","configuration_undo","",event_time=utc_now(),alert_id=alert_id)
            if delivered: store.mark_alert_notified(key)
            else: store.mark_notification_failed(key)
            return jsonify({"undone":True,"change_id":change_id,"profile_id":change["profile_id"],"fields":sorted(rollback),"alert_id":alert_id})
        except Exception as exc:
            logging.exception("Configuration undo failed for change %s",change_id)
            return jsonify({"error":str(exc)}),400

    @app.get("/api/devices")
    def api_devices() -> Any:
        return jsonify(store.device_states())

    @app.post("/api/alerts/<int:alert_id>/seen")
    def api_alert_seen(alert_id: int) -> Any:
        return jsonify({"seen":store.mark_alert_seen(alert_id)})

    @app.get("/api/analytics")
    def api_analytics() -> Any:
        hours=max(1,min(720,int(request.args.get("hours","24"))))
        base=store.alert_analytics(hours)
        base["intelligence"]=features.analytics()
        return jsonify(base)

    @app.get("/api/incidents")
    def api_incidents() -> Any:
        return jsonify(features.incidents(request.args.get("status",""), int(request.args.get("limit","100"))))

    @app.get("/api/incidents/<int:incident_id>")
    def api_incident(incident_id:int) -> Any:
        item=features.incident(incident_id)
        return jsonify(item) if item else (jsonify({"error":"Incident not found."}),404)

    @app.post("/api/incidents/<int:incident_id>/status")
    def api_incident_status(incident_id:int) -> Any:
        data=request_json(); status=str(data.get("status","")).lower()
        if not features.set_incident_status(incident_id,status):
            return jsonify({"error":"Invalid incident status or incident not found."}),400
        features.audit("incident_status","incident",str(incident_id),details={"status":status})
        sentinel.notify_report("Incident status updated",[f"Incident: #{incident_id}",f"Status: {status.upper()}"])
        return jsonify({"updated":True,"status":status})

    @app.get("/api/audit")
    def api_audit() -> Any:
        return jsonify(features.audit_entries(int(request.args.get("limit","200"))))

    @app.get("/api/delivery")
    def api_delivery() -> Any:
        return jsonify(features.delivery_history(int(request.args.get("limit","200"))))

    @app.get("/api/bulk-history")
    def api_bulk_history() -> Any:
        return jsonify(features.bulk_history(int(request.args.get("limit","100"))))

    @app.get("/api/domains")
    def api_domains() -> Any:
        return jsonify(features.domain_intelligence(int(request.args.get("limit","200"))))

    @app.get("/api/search")
    def api_search() -> Any:
        return jsonify(features.search(request.args.get("q","").strip(), int(request.args.get("limit","100"))))

    @app.get("/api/devices/<profile_id>/<path:device_id>")
    def api_device_detail(profile_id:str,device_id:str) -> Any:
        return jsonify(features.device_detail(profile_id,device_id))

    @app.patch("/api/devices/<profile_id>/<path:device_id>")
    def api_device_update(profile_id:str,device_id:str) -> Any:
        data=request_json()
        if not store.update_device_properties(profile_id,device_id,data):
            return jsonify({"error":"No valid device properties were provided or device was not found."}),400
        features.audit("device_update","device",device_id,profile_id,{"fields":sorted(data)})
        return jsonify({"updated":True,"device":next((d for d in store.device_states() if d["profile_id"]==profile_id and d["device_id"]==device_id),{})})

    @app.get("/api/export/json")
    def api_export_json() -> Any:
        return jsonify(features.export_json())

    @app.get("/api/export/csv")
    def api_export_csv() -> Any:
        from flask import Response
        return Response(features.export_csv(),mimetype="text/csv",
                        headers={"Content-Disposition":"attachment; filename=nextdns-sentinel-alerts.csv"})

    @app.get("/api/backup")
    def api_backup() -> Any:
        if not DB_PATH.exists():
            return jsonify({"error":"Database file does not exist yet."}),404
        return send_file(DB_PATH,as_attachment=True,download_name="nextdns-sentinel-backup.db")

    @app.post("/api/restore")
    def api_restore() -> Any:
        upload=request.files.get("backup")
        if upload is None or not upload.filename:
            return jsonify({"error":"Select a SQLite backup file."}),400
        temp_path=None
        was_running=sentinel.is_running()
        try:
            with tempfile.NamedTemporaryFile(prefix="sentinel-restore-",suffix=".db",delete=False) as tmp:
                temp_path=Path(tmp.name)
                upload.save(tmp)
            rollback_path=DB_PATH.with_suffix(".pre-restore.db")
            with sqlite3.connect(temp_path) as source:
                integrity=source.execute("PRAGMA integrity_check").fetchone()
                if not integrity or str(integrity[0]).lower()!="ok":
                    raise sqlite3.DatabaseError("SQLite integrity check failed.")
                if DB_PATH.exists():
                    shutil.copy2(DB_PATH,rollback_path)
                if was_running:
                    sentinel.stop()
                with sqlite3.connect(DB_PATH) as dest:
                    source.backup(dest)
            if was_running:
                sentinel.start()
            features.heartbeat("restored",{"rollback":str(rollback_path) if rollback_path.exists() else ""})
            features.audit("database_restore","database",str(DB_PATH),details={"filename":upload.filename,"rollback":str(rollback_path) if rollback_path.exists() else ""})
            return jsonify({"restored":True,"running":sentinel.is_running()})
        except sqlite3.Error as exc:
            return jsonify({"error":f"Invalid SQLite backup: {exc}"}),400
        except Exception as exc:
            return jsonify({"error":str(exc)}),400
        finally:
            if temp_path:
                try: temp_path.unlink(missing_ok=True)
                except OSError: pass

    @app.get("/api/sentinel/health")
    def api_sentinel_health() -> Any:
        result=features.health()
        result["runtime"]=sentinel.is_running()
        result["telegram_configured"]=bool(sentinel.telegram_token and sentinel.telegram_chat_id)
        return jsonify(result)

    @app.get("/api/runtime")
    def api_runtime() -> Any:
        return jsonify({
            "running": sentinel.is_running(),
            "telegram_configured": bool(
                sentinel.telegram_token and sentinel.telegram_chat_id
            ),
        })

    @app.get("/api/accounts")
    def api_accounts() -> Any:
        accounts = []
        for account in store.accounts():
            accounts.append({
                "profile_id": account["profile_id"],
                "name": account["name"],
                "profile_name": account["profile_name"],
                "active": bool(account["active"]),
                "added_at": account["added_at"],
            })
        return jsonify(accounts)

    @app.get("/api/settings/alert-logs")
    def api_alert_log_settings() -> Any:
        return jsonify({
            "enabled": store.save_alert_logs_enabled(),
            "path": str(ALERT_LOG_PATH),
        })

    @app.post("/api/settings/alert-logs")
    def api_alert_log_settings_save() -> Any:
        data = request_json()
        enabled = bool(data.get("enabled"))
        store.set_save_alert_logs_enabled(enabled)
        count = 0
        if enabled:
            count = store.export_alerts_to_file()
        return jsonify({
            "enabled": enabled,
            "path": str(ALERT_LOG_PATH),
            "exported": count,
        })

    @app.post("/api/settings/alert-logs/export")
    def api_alert_log_export() -> Any:
        count = store.export_alerts_to_file()
        return jsonify({"saved": True, "count": count, "path": str(ALERT_LOG_PATH)})

    @app.get("/api/denylist/<profile_id>")
    def api_denylist(profile_id: str) -> Any:
        if not store.account_exists(profile_id):
            return jsonify({"error": "Account not found."}), 404
        return jsonify(store.denylist_entries(profile_id))

    @app.delete("/api/denylist/<profile_id>")
    def api_denylist_clear(profile_id: str) -> Any:
        account=next((a for a in store.accounts() if a["profile_id"]==profile_id),None)
        if not account: return jsonify({"error":"Account not found."}),404
        try:
            client=NextDNSClient(account["api_key"]); current=client.denylist(profile_id)
            for domain in current:
                client.remove_denylist(profile_id,domain)
            store.replace_denylist(profile_id,[])
            key=hashlib.sha256(f"action:denylist_clear:{profile_id}:{utc_now()}".encode()).hexdigest()
            store.add_alert(profile_id,account["name"],"","",f"All denylist entries removed from Sentinel dashboard","denylist_removed","",utc_now(),key,"configuration_action",source="sentinel_dashboard")
            features.audit("denylist_clear","profile",profile_id,profile_id,{"removed":len(current)})
            return jsonify({"cleared":True,"removed":len(current),"entries":[]})
        except Exception as exc: return jsonify({"error":str(exc)}),400

    @app.post("/api/denylist/<profile_id>")
    def api_denylist_add(profile_id: str) -> Any:
        data=request_json(); domain=normalize_domain(str(data.get("domain","")))
        account=next((a for a in store.accounts() if a["profile_id"]==profile_id),None)
        if not account: return jsonify({"error":"Account not found."}),404
        try:
            client=NextDNSClient(account["api_key"]); client.add_denylist(profile_id,domain)
            current=client.denylist(profile_id); store.replace_denylist(profile_id,current)
            key=hashlib.sha256(f"action:denylist_add:{profile_id}:{domain}:{utc_now()}".encode()).hexdigest()
            store.add_alert(profile_id,account["name"],domain,domain,f"Denylist entry added by Sentinel dashboard","denylist_added","",utc_now(),key,"configuration_action",source="sentinel_dashboard")
            alert_id=sentinel.enrich_alert(key,account,domain,"Denylist entry added by Sentinel dashboard","denylist_added",domain,"",utc_now(),"","","","",False)
            delivered=sentinel.notify(account,domain,"Denylist entry added by Sentinel dashboard","denylist_added",domain,event_time=utc_now(),alert_id=alert_id)
            if delivered: store.mark_alert_notified(key)
            else: store.mark_notification_failed(key)
            features.audit("denylist_add","profile",profile_id,profile_id,{"domain":domain})
            return jsonify({"saved":True,"domain":domain,"entries":current})
        except Exception as exc: return jsonify({"error":str(exc)}),400

    @app.delete("/api/denylist/<profile_id>/<path:domain>")
    def api_denylist_remove(profile_id: str, domain: str) -> Any:
        account=next((a for a in store.accounts() if a["profile_id"]==profile_id),None)
        if not account: return jsonify({"error":"Account not found."}),404
        try:
            client=NextDNSClient(account["api_key"]); client.remove_denylist(profile_id,domain)
            current=client.denylist(profile_id); store.replace_denylist(profile_id,current)
            normalized=normalize_domain(domain)
            key=hashlib.sha256(f"action:denylist_remove:{profile_id}:{normalized}:{utc_now()}".encode()).hexdigest()
            store.add_alert(profile_id,account["name"],normalized,normalized,f"Denylist entry removed by Sentinel dashboard","denylist_removed","",utc_now(),key,"configuration_action",source="sentinel_dashboard")
            alert_id=sentinel.enrich_alert(key,account,normalized,"Denylist entry removed by Sentinel dashboard","denylist_removed",normalized,"",utc_now(),"","","","",False)
            delivered=sentinel.notify(account,normalized,"Denylist entry removed by Sentinel dashboard","denylist_removed",normalized,event_time=utc_now(),alert_id=alert_id)
            if delivered: store.mark_alert_notified(key)
            else: store.mark_notification_failed(key)
            features.audit("denylist_remove","profile",profile_id,profile_id,{"domain":normalized})
            return jsonify({"removed":True,"domain":normalized,"entries":current})
        except Exception as exc: return jsonify({"error":str(exc)}),400

    @app.post("/api/denylist/bulk")
    def api_denylist_bulk() -> Any:
        data=request_json(); domain=normalize_domain(str(data.get("domain",""))); action=str(data.get("action","")).lower()
        if action not in {"add","remove"} or not domain: return jsonify({"error":"Provide domain and action=add|remove."}),400
        results=[]
        for account in store.accounts():
            if not account["active"]:
                results.append({"profile_id":account["profile_id"],"profile_name":account["profile_name"],"status":"skipped","reason":"Profile is inactive."}); continue
            try:
                client=NextDNSClient(account["api_key"])
                (client.add_denylist if action=="add" else client.remove_denylist)(account["profile_id"],domain)
                current=client.denylist(account["profile_id"]); store.replace_denylist(account["profile_id"],current)
                results.append({"profile_id":account["profile_id"],"profile_name":account["profile_name"],"status":"success","reason":"API operation completed."})
            except Exception as exc:
                results.append({"profile_id":account["profile_id"],"profile_name":account["profile_name"],"status":"failed","reason":str(exc)})
        successes=sum(r["status"]=="success" for r in results); failures=sum(r["status"]=="failed" for r in results); skipped=sum(r["status"]=="skipped" for r in results)
        operation_id=features.record_bulk("denylist_"+action,domain,results)
        features.audit("bulk_denylist","all_profiles",domain,details={"action":action,"operation_id":operation_id,"successes":successes,"failures":failures,"skipped":skipped})
        if sentinel.telegram_token and sentinel.telegram_chat_id:
            report_lines=[
                f"Action: {action.upper()}",
                f"Domain: {domain}",
                f"Operation: #{operation_id}",
                f"Profiles: {len(results)}",
                f"Success: {successes} · Failed: {failures} · Skipped: {skipped}",
            ]
            report_lines.extend(
                f"• {r.get('profile_name') or r.get('profile_id')}: {r.get('status','unknown').upper()} — {r.get('reason','')}"
                for r in results[:25]
            )
            if len(results)>25:
                report_lines.append(f"• … {len(results)-25} additional profiles omitted from Telegram report.")
            sentinel.notify_report("Bulk denylist action",report_lines)
        return jsonify({"domain":domain,"action":action,"operation_id":operation_id,"results":results,"successes":successes,"failures":failures,"skipped":skipped})

    @app.post("/api/monitor/start")
    def api_monitor_start() -> Any:
        try:
            count = sentinel.start()
            features.audit("monitor_start","runtime","monitor",details={"accounts":count})
            sentinel.notify_report("Sentinel monitoring started",[f"Active monitoring threads: {count}"])
            return jsonify({"running": sentinel.is_running(), "accounts": count})
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/monitor/stop")
    def api_monitor_stop() -> Any:
        sentinel.stop()
        features.audit("monitor_stop","runtime","monitor")
        sentinel.notify_report("Sentinel monitoring stopped",["Monitoring was stopped from the dashboard."])
        return jsonify({"running": False})

    @app.post("/api/profiles/discover")
    def api_profiles_discover() -> Any:
        data = request_json()
        api_key = str(data.get("api_key", "")).strip()
        if not api_key:
            return jsonify({"error": "NextDNS API key is required."}), 400
        try:
            profiles = NextDNSClient(api_key).profiles()
            return jsonify([
                {
                    "id": str(profile.get("id", "")),
                    "name": str(profile.get("name") or profile.get("profile_name") or profile.get("id") or "NextDNS Profile"),
                }
                for profile in profiles
                if profile.get("id")
            ])
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/profiles/<profile_id>/config/<section>")
    def api_profile_config_get(profile_id:str,section:str)->Any:
        allowed={"profile","security","privacy","parentalControl","settings","denylist","allowlist"}
        if section not in allowed: return jsonify({"error":"Unsupported configuration section."}),400
        account=next((a for a in store.accounts() if a["profile_id"]==profile_id),None)
        if not account: return jsonify({"error":"Account not found."}),404
        try:
            client=NextDNSClient(account["api_key"])
            if section=="profile": data=client.profile(profile_id)
            else: data=client._get(f"/profiles/{profile_id}/{section}").get("data",{})
            return jsonify(data)
        except Exception as exc: return jsonify({"error":str(exc)}),400

    @app.patch("/api/profiles/<profile_id>/config/<section>")
    def api_profile_config_patch(profile_id:str,section:str)->Any:
        allowed={"profile","security","privacy","parentalControl","settings"}
        if section not in allowed: return jsonify({"error":"Unsupported configuration section."}),400
        data=request_json()
        account=next((a for a in store.accounts() if a["profile_id"]==profile_id),None)
        if not account: return jsonify({"error":"Account not found."}),404
        if not isinstance(data,dict):
            return jsonify({"error":"Configuration payload must be a JSON object."}),422
        preview=bool(data.pop("_preview",False))
        if not data and not preview:
            return jsonify({"error":"Configuration payload is empty."}),422
        try:
            client=NextDNSClient(account["api_key"])
            before=config_snapshot(client.profile(profile_id))
            current_section=before if section=="profile" else before.get(section,{})
            if not isinstance(current_section,dict):
                current_section={}
            proposed=dict(current_section)
            proposed.update(data)
            if preview:
                changed=sorted(k for k in set(current_section)|set(proposed) if current_section.get(k)!=proposed.get(k))
                return jsonify({"preview":True,"section":section,"changed_fields":changed,"before":current_section,"proposed":proposed})
            path=f"/profiles/{profile_id}" if section=="profile" else f"/profiles/{profile_id}/{section}"
            result=client._patch(path,data)
            live=client.profile(profile_id); after=config_snapshot(live)
            if before!=after:
                change_type=config_change_summary(before,after)
                change_id=store.add_config_change(profile_id,before,after,change_type,"sentinel_dashboard")
                key=hashlib.sha256(f"config_action:{profile_id}:{change_id}".encode()).hexdigest()
                store.add_alert(profile_id,account["name"],"","",f"Configuration changed from Sentinel dashboard: {change_type}","config_changed","",utc_now(),key,"config_change",source="sentinel_dashboard")
                alert_id=sentinel.enrich_alert(key,account,"",f"Configuration changed from Sentinel dashboard: {change_type}","config_changed","","",utc_now(),"","","","",False)
                delivered=sentinel.notify(account,"",f"Configuration changed from Sentinel dashboard: {change_type}","config_changed","",event_time=utc_now(),alert_id=alert_id)
                if delivered: store.mark_alert_notified(key)
                else: store.mark_notification_failed(key)
                features.audit("profile_config_patch","profile",profile_id,profile_id,{"section":section,"change_id":change_id})
            store.save_config_snapshot(profile_id,after)
            return jsonify({"saved":True,"section":section,"response":result,"profile":live})
        except Exception as exc: return jsonify({"error":str(exc)}),400

    @app.get("/api/accounts/<profile_id>")
    def api_account_detail(profile_id: str) -> Any:
        accounts = store.accounts()
        account = next((a for a in accounts if a["profile_id"] == profile_id), None)
        if not account:
            return jsonify({"error": "Account not found."}), 404
        try:
            profile_response = NextDNSClient(account["api_key"])._get(f"/profiles/{profile_id}")
            profile = profile_response.get("data", profile_response)
            if not isinstance(profile, dict):
                raise NextDNSError("NextDNS returned an unexpected profile response.")
            denylist = profile.get("denylist", [])
            allowlist = profile.get("allowlist", [])
            privacy = profile.get("privacy", {})
            parental = profile.get("parentalControl", {})
            settings = profile.get("settings", {})
            logs = settings.get("logs", {}) if isinstance(settings, dict) else {}
            block_page = settings.get("blockPage", {}) if isinstance(settings, dict) else {}
            return jsonify({
                "profile_id": profile_id,
                "name": account["name"],
                "profile_name": str(profile.get("name") or account["profile_name"] or profile_id),
                "active": bool(account["active"]),
                "added_at": account["added_at"],
                "api_key_configured": bool(account["api_key"]),
                "profile": {
                    "denylist_entries": len(denylist) if isinstance(denylist, list) else 0,
                    "allowlist_entries": len(allowlist) if isinstance(allowlist, list) else 0,
                    "blocklists": len(privacy.get("blocklists", [])) if isinstance(privacy, dict) and isinstance(privacy.get("blocklists", []), list) else 0,
                    "parental_services": len(parental.get("services", [])) if isinstance(parental, dict) and isinstance(parental.get("services", []), list) else 0,
                    "parental_categories": len(parental.get("categories", [])) if isinstance(parental, dict) and isinstance(parental.get("categories", []), list) else 0,
                    "logs_enabled": bool(logs.get("enabled")) if isinstance(logs, dict) else False,
                    "block_page_enabled": bool(block_page.get("enabled")) if isinstance(block_page, dict) else False,
                    "web3_enabled": bool(settings.get("web3")) if isinstance(settings, dict) else False,
                },
            })
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400

    @app.patch("/api/accounts/<profile_id>")
    def api_account_update(profile_id: str) -> Any:
        accounts = store.accounts()
        account = next((a for a in accounts if a["profile_id"] == profile_id), None)
        if not account:
            return jsonify({"error": "Account not found."}), 404
        data = request_json()
        display_name = str(data.get("name", account["name"])).strip()
        profile_name = str(data.get("profile_name", account["profile_name"])).strip()
        new_api_key = str(data.get("api_key", "")).strip()
        if not display_name:
            return jsonify({"error": "Local display name is required."}), 400
        if not profile_name:
            return jsonify({"error": "NextDNS profile name is required."}), 400
        api_key = new_api_key or account["api_key"]
        profile_running = bool((sentinel.profile_threads or {}).get(profile_id) and (sentinel.profile_threads or {}).get(profile_id).is_alive())
        try:
            client = NextDNSClient(api_key)
            profile_response = client._get(f"/profiles/{profile_id}")
            profile = profile_response.get("data", profile_response)
            if not isinstance(profile, dict):
                raise NextDNSError("NextDNS returned an unexpected profile response.")
            current_profile_name = str(profile.get("name") or profile_id)
            if profile_name != current_profile_name:
                client.update_profile_name(profile_id, profile_name)
            # Editing local/API profile identity must not depend on denylist availability.
            if profile_running:
                sentinel.stop_profile(profile_id)
            store.upsert_account({
                "profile_id": profile_id,
                "name": display_name,
                "profile_name": profile_name,
                "api_key": api_key,
                "active": bool(account["active"]),
                "added_at": account["added_at"],
            })
            if profile_running:
                sentinel.start_profile(profile_id)
            features.audit("local_profile_update","profile",profile_id,profile_id,{"display_name":display_name,"profile_name":profile_name,"api_key_rotated":bool(new_api_key)})
            sentinel.notify_report("Profile settings updated",[
                f"Profile: {profile_id}",
                f"Display name: {display_name}",
                f"API key rotated: {'yes' if new_api_key else 'no'}",
            ])
            return jsonify({
                "saved": True,
                "profile_id": profile_id,
                "name": display_name,
                "profile_name": profile_name,
                "running": sentinel.is_running(),
            })
        except Exception as exc:
            if profile_running and not ((sentinel.profile_threads or {}).get(profile_id) and (sentinel.profile_threads or {}).get(profile_id).is_alive()):
                try:
                    sentinel.start_profile(profile_id)
                except Exception:
                    pass
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/setup/account")
    def api_setup_account() -> Any:
        data = request_json()
        profile_id = str(data.get("profile_id", "")).strip()
        api_key = str(data.get("api_key", "")).strip()
        name = str(data.get("name", "")).strip()
        profile_name = str(data.get("profile_name", "")).strip()

        if not profile_id or not api_key:
            return jsonify({"error": "API key and a profile selected from the API are required."}), 400

        try:
            # The profile ID comes from the API response; users never enter it manually.
            client = NextDNSClient(api_key)
            profile = client._get(f"/profiles/{profile_id}").get("data", {})
            if not isinstance(profile, dict):
                raise NextDNSError(f"NextDNS returned an unexpected profile response for {profile_id}.")
            resolved_name = profile_name or str(profile.get("name") or profile_id)
            resolved_display = name or resolved_name
            store.upsert_account({
                "profile_id": profile_id,
                "name": resolved_display,
                "profile_name": resolved_name,
                "api_key": api_key,
                "active": True,
                "added_at": utc_now(),
            })
            if not ((sentinel.profile_threads or {}).get(profile_id) and (sentinel.profile_threads or {}).get(profile_id).is_alive()):
                sentinel.start_profile(profile_id)
            return jsonify({"saved": True, "running": sentinel.is_running()})
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/accounts/<profile_id>/toggle")
    def api_account_toggle(profile_id: str) -> Any:
        if not store.account_exists(profile_id):
            return jsonify({"error": "Account not found."}), 404
        data = request_json()
        active = bool(data.get("active"))
        if not active:
            sentinel.stop_profile(profile_id)
        store.set_account_active(profile_id, active)
        features.audit("profile_monitor_toggle","profile",profile_id,profile_id,{"active":active})
        sentinel.notify_report("Profile monitoring changed",[
            f"Profile: {profile_id}",
            f"Monitoring: {'enabled' if active else 'disabled'}",
        ])
        if active:
            try:
                sentinel.start_profile(profile_id)
            except RuntimeError as exc:
                return jsonify({"error": str(exc)}), 400
        return jsonify({"active": active, "running": sentinel.is_running()})

    @app.delete("/api/accounts/<profile_id>")
    def api_account_delete(profile_id: str) -> Any:
        if not store.account_exists(profile_id):
            return jsonify({"error": "Account not found."}), 404
        sentinel.stop_profile(profile_id)
        features.audit("profile_delete","profile",profile_id,profile_id,{"profile_id":profile_id})
        sentinel.notify_report("Profile removed from Sentinel",[
            f"Profile: {profile_id}",
            "Local monitoring state was deleted.",
        ])
        store.delete_account(profile_id)
        remaining = [a for a in store.accounts() if a["active"]]
        if remaining:
            for account in remaining:
                sentinel.start_profile(account["profile_id"])
        return jsonify({"deleted": True, "running": sentinel.is_running()})

    @app.post("/api/settings/telegram")
    def api_telegram_save() -> Any:
        data = request_json()
        token = str(data.get("token", "")).strip()
        chat_id = str(data.get("chat_id", "")).strip()
        if not token:
            token = store.get_secret("telegram_token")
        if not chat_id:
            chat_id = store.get_secret("telegram_chat_id")
        if not token or not chat_id:
            return jsonify({"error": "Telegram bot token and chat ID are required."}), 400
        try:
            identity = validate_telegram_credentials(token, chat_id)
            store.set_secret("telegram_token", token)
            store.set_secret("telegram_chat_id", chat_id)
            store.set_setting("telegram_bot_username", str(identity["bot"].get("username") or ""))
            store.set_setting("telegram_bot_name", str(identity["bot"].get("first_name") or ""))
            store.set_setting("telegram_chat_title", str(identity["chat"].get("title") or identity["chat"].get("first_name") or identity["chat"].get("username") or ""))
            store.set_setting("telegram_enabled", "1")
            store.set_setting("telegram_last_test_at", "")
            store.set_setting("telegram_last_error", "")
            sentinel.telegram_token = token
            sentinel.telegram_chat_id = chat_id
            features.audit("telegram_configured","settings","telegram",details={"chat_id":chat_id})
            return jsonify({"configured": True, "status": "enabled", "bot_username": str(identity["bot"].get("username") or ""), "bot_name": str(identity["bot"].get("first_name") or ""), "chat_title": str(identity["chat"].get("title") or identity["chat"].get("first_name") or identity["chat"].get("username") or "")})
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/settings/telegram/bots")
    def api_telegram_bots_get() -> Any:
        return jsonify([{"id":b["id"],"name":b["name"],"enabled":bool(b["enabled"]),"bot_username":b["bot_username"],
                        "bot_name":b["bot_name"],"chat_title":b["chat_title"],"chat_id":b["chat_id"],
                        "last_notification_at":b["last_notification_at"],"last_error":b["last_error"],
                        "token_configured":bool(b["token"])} for b in store.telegram_bots()])

    @app.post("/api/settings/telegram/bots")
    def api_telegram_bot_save() -> Any:
        data=request_json()
        try: bot_id=int(data["id"]) if data.get("id") is not None else None
        except (TypeError,ValueError): return jsonify({"error":"Bot id must be an integer."}),400
        name=str(data.get("name") or "Telegram Bot").strip(); token=str(data.get("token") or "").strip(); chat_id=str(data.get("chat_id") or "").strip()
        if bot_id:
            existing=next((b for b in store.telegram_bots() if int(b["id"])==bot_id),None)
            if not existing: return jsonify({"error":"Telegram bot not found."}),404
            token=token or existing["token"]; chat_id=chat_id or existing["chat_id"]
        if not token or not chat_id: return jsonify({"error":"Telegram bot token and chat ID are required."}),400
        try:
            identity=validate_telegram_credentials(token,chat_id)
            saved_id=store.save_telegram_bot(bot_id,name,token,chat_id,bool(data.get("enabled",True)),identity)
            features.audit("telegram_bot_save","telegram_bot",str(saved_id),details={"name":name})
            return jsonify({"saved":True,"id":saved_id})
        except Exception as exc: return jsonify({"error":str(exc)}),400

    @app.post("/api/settings/telegram/bots/<int:bot_id>/enable")
    def api_telegram_bot_enable(bot_id:int) -> Any:
        enabled=bool(request_json().get("enabled"))
        if not store.set_telegram_bot_enabled(bot_id,enabled): return jsonify({"error":"Telegram bot not found."}),404
        features.audit("telegram_bot_enable" if enabled else "telegram_bot_disable","telegram_bot",str(bot_id))
        return jsonify({"enabled":enabled})

    @app.post("/api/settings/telegram/bots/<int:bot_id>/test")
    def api_telegram_bot_test(bot_id:int) -> Any:
        bot=next((b for b in store.telegram_bots() if int(b["id"])==bot_id),None)
        if not bot: return jsonify({"error":"Telegram bot not found."}),404
        ok,reason=send_telegram_result(bot["token"],bot["chat_id"],"<b>NextDNS Sentinel</b>\nTest notification.",parse_mode="HTML")
        store.mark_telegram_bot_result(bot_id,ok,"" if ok else reason)
        if not ok: return jsonify({"error":reason}),502
        return jsonify({"sent":True,"message":reason,"sent_at":utc_now()})

    @app.delete("/api/settings/telegram/bots/<int:bot_id>")
    def api_telegram_bot_delete(bot_id:int) -> Any:
        if not store.delete_telegram_bot(bot_id): return jsonify({"error":"Telegram bot not found."}),404
        features.audit("telegram_bot_delete","telegram_bot",str(bot_id))
        return jsonify({"deleted":True})

    @app.get("/api/settings/telegram")
    def api_telegram_get() -> Any:
        token = store.get_secret("telegram_token")
        chat_id = store.get_secret("telegram_chat_id")
        return jsonify({
            "configured": bool(token and chat_id),
            "enabled": bool(token and chat_id and store.setting("telegram_enabled","1")=="1"),
            "status": "enabled" if token and chat_id and store.setting("telegram_enabled","1")=="1" else "disabled",
            "chat_id": chat_id,
            "token_configured": bool(token),
            "bot_username": store.setting("telegram_bot_username", ""),
            "bot_name": store.setting("telegram_bot_name", ""),
            "chat_title": store.setting("telegram_chat_title", ""),
            "last_test_at": store.setting("telegram_last_test_at", ""),
            "last_error": store.setting("telegram_last_error", ""),
        })

    @app.post("/api/settings/telegram/enable")
    def api_telegram_enable() -> Any:
        token = store.get_secret("telegram_token")
        chat_id = store.get_secret("telegram_chat_id")
        if not token or not chat_id:
            return jsonify({"error":"No saved Telegram credentials exist. Save a bot first."}),400
        try:
            validate_telegram_credentials(token,chat_id)
            store.set_setting("telegram_enabled","1")
            sentinel.telegram_token=token
            sentinel.telegram_chat_id=chat_id
            features.audit("telegram_enabled","settings","telegram")
            return jsonify({"enabled":True,"status":"enabled"})
        except Exception as exc:
            return jsonify({"error":str(exc)}),400

    @app.delete("/api/settings/telegram")
    def api_telegram_delete() -> Any:
        token = store.get_secret("telegram_token")
        chat_id = store.get_secret("telegram_chat_id")
        if not token or not chat_id:
            return jsonify({"configured":False,"enabled":False,"status":"disabled"})
        store.set_setting("telegram_enabled","0")
        sentinel.telegram_token = ""
        sentinel.telegram_chat_id = ""
        features.audit("telegram_disabled","settings","telegram")
        return jsonify({"configured":True,"enabled":False,"status":"disabled"})

    @app.delete("/api/settings/telegram/credentials")
    def api_telegram_credentials_delete() -> Any:
        store.set_setting("telegram_enabled","0")
        store.set_setting("telegram_bot_username","")
        store.set_setting("telegram_bot_name","")
        store.set_setting("telegram_chat_title","")
        store.set_setting("telegram_last_test_at","")
        store.set_setting("telegram_last_error","")
        store.delete_secret("telegram_token")
        store.delete_secret("telegram_chat_id")
        sentinel.telegram_token = ""
        sentinel.telegram_chat_id = ""
        features.audit("telegram_credentials_deleted","settings","telegram")
        return jsonify({"configured":False,"enabled":False,"status":"disabled"})
    
    @app.post("/api/settings/telegram/test")
    def api_telegram_test() -> Any:
        if not sentinel.telegram_token or not sentinel.telegram_chat_id or store.setting("telegram_enabled","1")!="1":
            return jsonify({"error": "Telegram is disabled or not configured. Enable the bot first."}), 400
        ok, reason = send_telegram_result(
            sentinel.telegram_token,
            sentinel.telegram_chat_id,
            "NextDNS Sentinel test notification.",
        )
        store.set_setting("telegram_last_test_at", utc_now())
        store.set_setting("telegram_last_error", "" if ok else reason)
        if not ok:
            return jsonify({"error": reason}), 502
        return jsonify({"sent": True, "message": reason, "tested_at": store.setting("telegram_last_test_at","")})

    @app.get("/api/risk-history")
    def api_risk_history() -> Any:
        method=getattr(features,"risk_history",None)
        if not callable(method): return jsonify([])
        try: return jsonify(method(request.args.get("profile_id",""),int(request.args.get("days","30"))))
        except Exception:
            logging.exception("Risk history load failed")
            return jsonify([])

    @app.get("/api/baseline")
    def api_baseline() -> Any:
        method=getattr(features,"baseline_view",None)
        if not callable(method): return jsonify([])
        try: return jsonify(method(request.args.get("profile_id","")))
        except Exception:
            logging.exception("Baseline load failed")
            return jsonify([])
    @app.get("/api/live")
    def api_live() -> Any:
        return jsonify(features.live_snapshot())

    @app.get("/api/incident-metrics")
    def api_incident_metrics() -> Any:
        return jsonify(features.incident_metrics())

    @app.get("/api/config-diff/<profile_id>")
    def api_config_diff(profile_id:str)->Any:
        return jsonify(features.config_diff(profile_id))

    @app.get("/api/settings/export")
    def api_settings_export() -> Any:
        return jsonify(features.export_settings())

    @app.post("/api/settings/import")
    def api_settings_import() -> Any:
        data=request_json()
        if not isinstance(data,dict): return jsonify({"error":"Invalid settings document."}),400
        result=features.import_settings(data); features.audit("settings_import","settings","local",details=result)
        return jsonify({"imported":result})
    @app.get("/api/control-center")
    def api_control_center() -> Any:
        try:
            rules_method = getattr(features, "rules", None)
            rules = rules_method() if callable(rules_method) else []
            maintenance_method = getattr(features, "maintenance_active", None)
            maintenance = maintenance_method() if callable(maintenance_method) else None
            diagnostics_method = getattr(features, "diagnostics", None)
            diagnostics = diagnostics_method() if callable(diagnostics_method) else {"database": False, "encryption": bool(SECRET_KEY), "schema": False}
            rate_limits_method = getattr(features, "rate_limit_history", None)
            rate_limits = rate_limits_method(20) if callable(rate_limits_method) else []
            return jsonify({
                "rules": rules,
                "maintenance": maintenance,
                "safe_mode": store.setting("safe_mode","0")=="1",
                "api_auth": bool(store.setting("api_auth_hash","")),
                "diagnostics": diagnostics,
                "rate_limits": rate_limits,
            })
        except Exception as exc:
            logging.exception("Control Center load failed")
            return jsonify({
                "error": f"Control Center could not load: {exc}",
                "rules": [],
                "maintenance": None,
                "safe_mode": store.setting("safe_mode","0")=="1",
                "api_auth": bool(store.setting("api_auth_hash","")),
                "diagnostics": {"database": False, "encryption": bool(SECRET_KEY), "schema": False},
                "rate_limits": [],
            }), 503

    @app.get("/api/rules")
    def api_rules() -> Any: return jsonify(features.rules())

    @app.post("/api/rules")
    def api_rule_save() -> Any:
        data=request_json(); name=str(data.get("name","")).strip(); rule=data.get("rule") or {}
        if not name: return jsonify({"error":"Rule name is required."}),400
        if not isinstance(rule, dict): return jsonify({"error":"Rule definition must be a JSON object."}),400
        allowed_actions={"","suppress","ignore","escalate"}
        action=str(rule.get("action","")).lower()
        if action not in allowed_actions: return jsonify({"error":"Unsupported rule action."}),400
        try:
            rule_id=int(data["id"]) if data.get("id") is not None else None
        except (TypeError,ValueError):
            return jsonify({"error":"Rule id must be an integer."}),400
        rid=features.save_rule(rule_id,name,rule,bool(data.get("enabled",True)))
        features.audit("rule_save","rule",str(rid),details={"name":name,"action":action})
        return jsonify({"saved":True,"id":rid})

    @app.delete("/api/rules/<int:rule_id>")
    def api_rule_delete(rule_id:int)->Any:
        ok=features.delete_rule(rule_id)
        if ok: features.audit("rule_delete","rule",str(rule_id))
        return jsonify({"deleted":ok})

    @app.post("/api/suppressions")
    def api_suppression_add()->Any:
        data=request_json(); fp=str(data.get("fingerprint","")).strip()
        seconds=int(data.get("seconds",600)); reason=str(data.get("reason",""))
        if not fp: return jsonify({"error":"fingerprint is required."}),400
        sid=features.add_suppression(fp,seconds,reason); features.audit("alert_suppression","alert",fp,details={"seconds":seconds,"reason":reason})
        return jsonify({"created":True,"id":sid})

    @app.post("/api/maintenance")
    def api_maintenance_add()->Any:
        data=request_json(); seconds=int(data.get("seconds",3600)); scope=str(data.get("scope","global")); profile_id=str(data.get("profile_id",""))
        if scope not in {"global","profile"}: return jsonify({"error":"scope must be global or profile."}),400
        mid=features.add_maintenance(scope,profile_id,seconds,str(data.get("reason","")))
        features.audit("maintenance_start","maintenance",str(mid),profile_id,{"seconds":seconds,"scope":scope})
        sentinel.notify_report("Maintenance mode enabled",[f"Scope: {scope}",f"Profile: {profile_id or 'all'}",f"Duration: {seconds}s"])
        return jsonify({"created":True,"id":mid})

    @app.post("/api/safe-mode")
    def api_safe_mode()->Any:
        enabled=bool(request_json().get("enabled")); store.set_setting("safe_mode","1" if enabled else "0")
        features.audit("safe_mode","settings","safe_mode",details={"enabled":enabled})
        return jsonify({"enabled":enabled})

    @app.post("/api/retention")
    def api_retention()->Any:
        data=request_json(); days=int(data.get("days",30))
        deleted=features.cleanup(days); features.audit("database_retention","database",details={"days":days,"deleted":deleted})
        return jsonify({"deleted":deleted,"days":days})

    @app.get("/api/diagnostics")
    def api_diagnostics()->Any:
        result=features.diagnostics(); result["runtime"]=sentinel.is_running(); result["telegram"]=bool(sentinel.telegram_token and sentinel.telegram_chat_id)
        return jsonify(result)

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
    ) or store.get_secret("telegram_token")
    telegram_chat_id = os.getenv(
        config.get("telegram_chat_id_env", "TELEGRAM_CHAT_ID"), ""
    ) or store.get_secret("telegram_chat_id")
    telegram_enabled = store.setting("telegram_enabled","1") == "1"
    if not telegram_enabled:
        telegram_token = ""
        telegram_chat_id = ""
    features = FeatureStore(DB_PATH)
    sentinel = Sentinel(store, features, telegram_token, telegram_chat_id)

    if args.dashboard or not args.monitor:
        if args.host not in {"127.0.0.1", "localhost", "::1"}:
            logging.warning(
                "Dashboard is exposed beyond localhost. "
                "This application does not provide dashboard authentication."
            )
        if not sentinel.is_running() and any(a["active"] for a in store.accounts()):
            try:
                sentinel.start()
            except RuntimeError as exc:
                logging.error("Automatic monitor start failed: %s", exc)
        logging.info("Dashboard available at http://%s:%s", args.host, args.port)
        create_app(store, sentinel, features).run(host=args.host, port=args.port, debug=False)
    elif args.monitor:
        sentinel.run()


if __name__ == "__main__":
    main()