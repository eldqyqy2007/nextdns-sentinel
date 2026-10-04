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
from concurrent.futures import ThreadPoolExecutor
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
            ("sentinel_health", "DELETE FROM sentinel_health WHERE rowid NOT IN (SELECT MAX(rowid) FROM sentinel_health GROUP BY key)",
             "CREATE UNIQUE INDEX IF NOT EXISTS idx_sentinel_health_key_unique ON sentinel_health(key)"),
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
            severity=[dict(r) for r in db.execute("""
                SELECT COALESCE(NULLIF(m.severity,''),CASE
                    WHEN COALESCE(m.risk_score,0)>=80 THEN 'critical'
                    WHEN COALESCE(m.risk_score,0)>=60 THEN 'high'
                    WHEN COALESCE(m.risk_score,0)>=35 THEN 'medium'
                    ELSE 'low' END) severity,COUNT(*) count
                FROM alerts a LEFT JOIN alert_metadata m ON m.alert_id=a.id
                GROUP BY 1 ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END
            """).fetchall()]
            risk=[dict(r) for r in db.execute("""
                SELECT COALESCE(NULLIF(m.domain_risk,''),di.risk,'unknown') domain_risk,COUNT(*) count
                FROM alerts a
                LEFT JOIN alert_metadata m ON m.alert_id=a.id
                LEFT JOIN domain_intelligence di ON di.domain=a.domain
                WHERE a.domain<>''
                GROUP BY 1 ORDER BY count DESC
            """).fetchall()]
            open_incidents=db.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('open','investigating')").fetchone()[0]
            incidents=[dict(r) for r in db.execute("""
                SELECT id,profile_id,title,severity,risk_score,status,summary,alert_count,domain,device_id,updated_at
                FROM incidents ORDER BY updated_at DESC LIMIT 12
            """).fetchall()]
            recent_risk=[dict(r) for r in db.execute("""
                SELECT a.id,a.profile_id,a.account_name,a.domain,a.alert_type,a.reason,a.status,
                       COALESCE(NULLIF(m.severity,''),CASE WHEN a.alert_type='denylist_match' THEN 'high' ELSE 'medium' END) severity,
                       COALESCE(m.risk_score,CASE WHEN a.alert_type='denylist_match' THEN 65 ELSE 20 END) risk_score,
                       COALESCE(NULLIF(m.domain_risk,''),di.risk,'low') domain_risk,
                       COALESCE(m.risk_factors,'[]') risk_factors,a.event_timestamp,a.created_at
                FROM alerts a
                LEFT JOIN alert_metadata m ON m.alert_id=a.id
                LEFT JOIN domain_intelligence di ON di.domain=a.domain
                ORDER BY a.id DESC LIMIT 20
            """).fetchall()]
            return {"severity":severity,"domain_risk":risk,"open_incidents":open_incidents,
                    "incidents":incidents,"recent_risk":recent_risk}

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
            row=db.execute("SELECT before_json,after_json,change_type,changed_at AS created_at,undone_at FROM config_changes WHERE profile_id=? ORDER BY id DESC LIMIT 1",(profile_id,)).fetchone()
        if not row: return {"profile_id":profile_id,"changed":False,"diff":[]}
        before=unwrap_profile_data(_loads(row["before_json"],{})); after=unwrap_profile_data(_loads(row["after_json"],{})); diff=[]
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

    def end_maintenance(self):
        with self._connect() as db:
            cur=db.execute("UPDATE maintenance_windows SET ends_at=? WHERE ends_at>?",(now_iso(),now_iso()))
            return cur.rowcount

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



APP_NAME = "NextDNS Sentinel"
DB_PATH = Path(os.getenv("NEXTDNS_SENTINEL_DB", "data/sentinel.db"))
CONFIG_PATH = Path(os.getenv("NEXTDNS_SENTINEL_CONFIG", "config.json"))
LOG_LEVEL = os.getenv("NEXTDNS_SENTINEL_LOG_LEVEL", "INFO").upper()
HTTP_TIMEOUT = float(os.getenv("NEXTDNS_SENTINEL_HTTP_TIMEOUT", "10"))
CHECK_INTERVAL = max(1, int(os.getenv("NEXTDNS_SENTINEL_INTERVAL", "5")))
INITIAL_LOOKBACK = max(30, int(os.getenv("NEXTDNS_SENTINEL_INITIAL_LOOKBACK", "60")))
POLL_OVERLAP_MS = max(0, int(os.getenv("NEXTDNS_SENTINEL_POLL_OVERLAP_MS", "180000")))
ALERT_COOLDOWN = max(0, int(os.getenv("NEXTDNS_SENTINEL_ALERT_COOLDOWN", "10")))
CONFIG_CHECK_EVERY = max(1, int(os.getenv("NEXTDNS_SENTINEL_CONFIG_CHECK_EVERY", "3")))
NOTIFICATION_MAX_AGE = max(60, int(os.getenv("NEXTDNS_SENTINEL_NOTIFICATION_MAX_AGE", "600")))
NOTIFICATION_GRACE_SECONDS = 5
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


def local_tz():
    name = os.getenv("NEXTDNS_SENTINEL_TZ", "").strip()
    if name:
        try:
            from zoneinfo import ZoneInfo
            return ZoneInfo(name)
        except Exception:
            pass
    return datetime.now().astimezone().tzinfo


def fmt_dt12(value: Any, with_date: bool = True) -> str:
    """Human readable 12-hour local time with English digits, e.g. 02 Oct 2026 · 3:21:05 PM (UTC+3)."""
    try:
        dt = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return str(value) if value else "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(local_tz())
    off = dt.strftime("%z") or "+0000"
    label = "UTC" + off[:3] + (":" + off[3:] if off[3:] not in ("", "00") else "")
    clock = dt.strftime("%I:%M:%S %p").lstrip("0")
    return (dt.strftime("%d %b %Y · ") if with_date else "") + clock + " (" + label + ")"


def origin_of(source: str) -> tuple[str, str]:
    source = str(source or "")
    if source == "sentinel_dashboard":
        return "dashboard", "Dashboard (changed by you)"
    if source == "nextdns_profile":
        return "app", "NextDNS app / profile (changed outside Sentinel)"
    if source == "nextdns_logs":
        return "device", "Device DNS activity"
    return "system", "Sentinel system"


def alert_category(alert_type: str, status: str = "") -> str:
    alert_type = str(alert_type or ""); status = str(status or "")
    if alert_type == "denylist_match":
        return "site"
    if status in ("denylist_added", "denylist_removed"):
        return "denylist"
    if alert_type in ("config_change", "configuration_action") or status in ("config_changed", "configuration_undo"):
        return "profile"
    if "device" in alert_type or status.startswith("device"):
        return "device"
    return "other"


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
            _bot_cols = {r[1] for r in db.execute("PRAGMA table_info(telegram_bots)")}
            for _col in ("alert_types", "quiet_start", "quiet_end"):
                if _col not in _bot_cols:
                    db.execute(f"ALTER TABLE telegram_bots ADD COLUMN {_col} TEXT NOT NULL DEFAULT ''")
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
            for _tbl,_cols in (
                ("accounts","profile_id"),("device_state","profile_id,device_id"),
                ("monitor_state","profile_id"),("settings","key"),
                ("config_snapshots","profile_id"),("denylist","profile_id,domain"),
            ):
                if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(_tbl,)).fetchone():
                    db.execute(f"DELETE FROM {_tbl} WHERE rowid NOT IN (SELECT MAX(rowid) FROM {_tbl} GROUP BY {_cols})")
                    db.execute(f"CREATE UNIQUE INDEX IF NOT EXISTS idx_{_tbl}_upsert_unique ON {_tbl}({_cols})")

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

    def set_telegram_bot_prefs(self, bot_id: int, alert_types: str, quiet_start: str, quiet_end: str) -> bool:
        valid = {"site", "profile", "denylist", "device", "system"}
        types = ",".join(x for x in str(alert_types or "").split(",") if x in valid)
        def hhmm(v: str) -> str:
            v = str(v or "").strip()
            return v if len(v) == 5 and v[2] == ":" and v[:2].isdigit() and v[3:].isdigit() and int(v[:2]) < 24 and int(v[3:]) < 60 else ""
        a, b = hhmm(quiet_start), hhmm(quiet_end)
        if not (a and b):
            a = b = ""
        with sqlite3.connect(self.path) as db:
            cur = db.execute("UPDATE telegram_bots SET alert_types=?,quiet_start=?,quiet_end=?,updated_at=? WHERE id=?", (types, a, b, utc_now(), bot_id))
            return cur.rowcount > 0

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
            if ok:
                db.execute("UPDATE telegram_bots SET last_notification_at=?,last_error='',updated_at=? WHERE id=?",(utc_now(),utc_now(),bot_id))
            else:
                db.execute("UPDATE telegram_bots SET last_error=?,updated_at=? WHERE id=?",(error,utc_now(),bot_id))

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

    def event_exists(self, profile_id: str, domain: str, event_timestamp: str, device_id: str, client_ip: str) -> bool:
        """The same DNS query can be returned by several overlapping log polls; count it once."""
        with sqlite3.connect(self.path) as db:
            return db.execute(
                "SELECT 1 FROM alerts WHERE profile_id=? AND domain=? AND event_timestamp=? AND device_id=? AND client_ip=? AND alert_type='denylist_match' LIMIT 1",
                (profile_id, domain, event_timestamp, device_id, client_ip),
            ).fetchone() is not None

    def repeat_info(self, profile_id: str, domain: str, device_id: str = "") -> tuple[int, str]:
        """Attempts that were recorded but not announced since the last notification for this domain/device."""
        with sqlite3.connect(self.path) as db:
            last = db.execute(
                "SELECT MAX(notified_at) FROM alerts WHERE profile_id=? AND domain=? AND alert_type='denylist_match' AND notified_at!='' AND (?='' OR device_id=?)",
                (profile_id, domain, device_id, device_id),
            ).fetchone()
            since = (last[0] if last and last[0] else (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat())
            row = db.execute(
                "SELECT COUNT(*),MIN(COALESCE(NULLIF(event_timestamp,''),created_at)) FROM alerts WHERE profile_id=? AND domain=? AND alert_type='denylist_match' AND notification_status='suppressed' AND created_at>? AND (?='' OR device_id=?)",
                (profile_id, domain, since, device_id, device_id),
            ).fetchone()
        return int(row[0] or 0), str(row[1] or "")

    def was_recently_notified(
        self, profile_id: str, domain: str, cooldown_seconds: int, device_id: str = ""
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
                WHERE profile_id=? AND domain=? AND alert_type='denylist_match' AND notified_at>=?
                  AND (?='' OR device_id=?)
                ORDER BY id DESC LIMIT 1
                """,
                (profile_id, domain, cutoff, device_id, device_id),
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
    def claim_alert_id(self, alert_id: int, stale_seconds: int = 90) -> bool:
        """Atomically reserve an alert for sending so two threads never send it twice."""
        now = utc_now()
        stale = (datetime.now(timezone.utc) - timedelta(seconds=stale_seconds)).isoformat()
        with sqlite3.connect(self.path) as db:
            cur = db.execute(
                "UPDATE alerts SET notification_status='sending', last_notification_attempt_at=? "
                "WHERE id=? AND notified_at='' AND (notification_status='pending' OR "
                "(notification_status='sending' AND last_notification_attempt_at<?))",
                (now, alert_id, stale),
            )
            return cur.rowcount > 0

    def requeue_skipped_notifications(self) -> int:
        """Alerts that were skipped as 'old' are important: put them back in the delivery queue."""
        with sqlite3.connect(self.path) as db:
            cur = db.execute("UPDATE alerts SET notification_status='pending',next_retry_at='' WHERE notified_at='' AND notification_status='stale'")
            return cur.rowcount

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
                WHERE event_key=? AND notification_status IN ('pending','sending')
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
                      AND ns.state IN ('created','seen')
                      AND (a.next_retry_at='' OR a.next_retry_at<=?)
                      AND a.created_at<=?
                    ORDER BY a.id ASC LIMIT ?
                    """,
                    (
                        profile_id, utc_now(),
                        (datetime.now(timezone.utc) - timedelta(seconds=NOTIFICATION_GRACE_SECONDS)).isoformat(),
                        limit,
                    ),
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
        hours = max(1, min(720, int(hours)))
        now = datetime.now(timezone.utc)
        start_iso = (now - timedelta(hours=hours)).isoformat()
        with sqlite3.connect(self.path) as db:
            db.row_factory = sqlite3.Row
            rows = [dict(r) for r in db.execute(
                """SELECT profile_id,account_name,domain,status,alert_type,reason,device_id,device_name,source,
                          COALESCE(NULLIF(event_timestamp,''),created_at) AS ts
                   FROM alerts
                   WHERE ((event_timestamp >= ? AND event_timestamp <> '') OR (event_timestamp = '' AND created_at >= ?))
                   ORDER BY id DESC""", (start_iso, start_iso)).fetchall()]
            profile_names = {r[0]: r[1] for r in db.execute("SELECT profile_id,profile_name FROM accounts").fetchall()}
            device_rows = [dict(r) for r in db.execute("SELECT profile_id,device_id,device_name,device_model,client_ip,last_seen_at,last_domain,last_status FROM device_state").fetchall()]
            account_names = {r[0]: r[1] for r in db.execute("SELECT profile_id,name FROM accounts").fetchall()}
        cats = ("site", "profile", "denylist", "device", "other")
        end_hour = now.replace(minute=0, second=0, microsecond=0)
        buckets: dict[str, dict[str, int]] = {}
        for i in range(hours - 1, -1, -1):
            buckets[(end_hour - timedelta(hours=i)).isoformat()] = {c: 0 for c in cats}
        category_counts = {c: 0 for c in cats}
        status_counts: dict[str, int] = {}
        type_counts: dict[str, int] = {}
        origin_counts = {"dashboard": 0, "app": 0, "device": 0, "system": 0}
        domains: dict[str, dict[str, Any]] = {}
        devices: dict[str, dict[str, Any]] = {}
        profile_rows: dict[str, dict[str, Any]] = {}
        for row in rows:
            cat = alert_category(row["alert_type"], row["status"])
            category_counts[cat] += 1
            type_counts[str(row["alert_type"] or "unknown")] = type_counts.get(str(row["alert_type"] or "unknown"), 0) + 1
            status_counts[str(row["status"] or "unknown")] = status_counts.get(str(row["status"] or "unknown"), 0) + 1
            origin_counts[origin_of(row["source"])[0]] += 1
            try:
                dt = datetime.fromisoformat(str(row["ts"]).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                hour = dt.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0).isoformat()
                if hour in buckets:
                    buckets[hour][cat] += 1
            except (TypeError, ValueError):
                pass
            if row["domain"] and cat in ("site", "denylist"):
                d = domains.setdefault(str(row["domain"]), {"domain": str(row["domain"]), "count": 0, "visits": 0, "added": 0, "removed": 0, "last": "", "last_visit": ""})
                d["count"] += 1
                if cat == "site":
                    d["visits"] += 1
                    d["last_visit"] = d["last_visit"] or str(row["ts"])
                elif row["status"] == "denylist_added":
                    d["added"] += 1
                elif row["status"] == "denylist_removed":
                    d["removed"] += 1
                d["last"] = d["last"] or str(row["ts"])
            if cat == "site" and (row["device_id"] or row["device_name"]):
                key = f"{row['profile_id']}|{row['device_id']}"
                dv = devices.setdefault(key, {"device": row["device_name"] or row["device_id"], "account_name": row["account_name"], "count": 0})
                dv["count"] += 1
            pid = str(row["profile_id"] or "unknown")
            item = profile_rows.setdefault(pid, {"profile_id": pid, "account_name": str(row["account_name"] or pid),
                                                 "profile_name": str(profile_names.get(pid) or ""), "total_alerts": 0,
                                                 "blocked_count": 0, "categories": {c: 0 for c in cats},
                                                 "domains": {}, "recent_events": []})
            item["total_alerts"] += 1
            item["categories"][cat] += 1
            if cat == "site":
                item["blocked_count"] += 1
                dk = str(row["domain"] or "unknown")
                item["domains"][dk] = item["domains"].get(dk, 0) + 1
            if len(item["recent_events"]) < 25:
                item["recent_events"].append({k: row[k] for k in ("domain", "status", "alert_type", "reason", "device_name", "ts")})
        for item in profile_rows.values():
            item["top_domains"] = [{"domain": k, "count": v} for k, v in sorted(item["domains"].items(), key=lambda x: (-x[1], x[0]))[:10]]
            item.pop("domains", None)
        return {
            "hours": hours,
            "profiles": sorted(profile_rows.values(), key=lambda x: (-x["total_alerts"], x["account_name"].lower())),
            "timeline": [{"time": k, "count": sum(v.values()), **v} for k, v in buckets.items()],
            "categories": category_counts,
            "origins": origin_counts,
            "statuses": status_counts,
            "top_domains": sorted((d for d in domains.values() if d["visits"] > 0), key=lambda x: (-x["visits"], x["domain"]))[:12],
            "denylist_changes": sorted((d for d in domains.values() if d["added"] or d["removed"]), key=lambda x: (-(x["added"] + x["removed"]), x["domain"]))[:12],
            "devices": sorted(
                ({"profile_id": r["profile_id"], "account_name": account_names.get(r["profile_id"], r["profile_id"]),
                  "device": r["device_name"] or r["device_id"], "model": r["device_model"], "ip": r["client_ip"],
                  "last_seen_at": r["last_seen_at"], "last_domain": r["last_domain"],
                  "visits": devices.get(f"{r['profile_id']}|{r['device_id']}", {}).get("count", 0)} for r in device_rows),
                key=lambda x: str(x["last_seen_at"] or ""), reverse=True),
            "total_24h": len(rows),
            "by_type": type_counts,
        }


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


def unwrap_profile_data(value: Any) -> Any:
    """NextDNS wraps payloads as {"data": {...}}; older stored snapshots kept that wrapper."""
    while isinstance(value,dict) and set(value)=={"data"} and isinstance(value["data"],dict):
        value=value["data"]
    return value

def config_snapshot(profile: dict[str,Any]) -> dict[str,Any]:
    value=json.loads(json.dumps(profile,sort_keys=True,default=str))
    value=unwrap_profile_data(value)
    if isinstance(value,dict):
        for volatile in ("id","meta","setup","updatedAt","createdAt"):
            value.pop(volatile,None)
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
    parse_mode: str = "HTML", silent: bool = False,
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
                    "disable_notification": "true" if silent else "false",
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

    ORIGIN_ICON = {"dashboard": "🖥", "app": "📱", "device": "🌐", "system": "⚙️"}
    REPORT_KINDS = {
        "denylist_match": ("🚫 BLOCKED SITE VISITED", "A device just tried to open a site that is on your denylist.", "site"),
        "denylist_added": ("➕ SITE ADDED TO DENYLIST", "A domain was added to this profile's denylist.", "denylist"),
        "denylist_removed": ("➖ SITE REMOVED FROM DENYLIST", "A domain was removed from this profile's denylist.", "denylist"),
        "config_changed": ("🔧 PROFILE SETTINGS CHANGED", "A setting on this profile was modified.", "profile"),
        "configuration_undo": ("↩️ CHANGE UNDONE", "A previous settings change was reverted.", "profile"),
        "device_inactive": ("📴 DEVICE WENT SILENT", "A device stopped sending DNS queries to NextDNS.", "device"),
        "device_new": ("📱 NEW DEVICE SEEN", "A device appeared on this profile for the first time.", "device"),
        "security_event": ("🛡️ SECURITY EVENT", "Sentinel recorded an event on this profile.", "system"),
    }

    @staticmethod
    def _flatten(value: Any, prefix: str = "", out: dict[str, str] | None = None) -> dict[str, str]:
        out = {} if out is None else out
        if isinstance(value, dict):
            for k, v in value.items():
                Sentinel._flatten(v, f"{prefix} › {k}" if prefix else str(k), out)
        else:
            out[prefix or "value"] = json.dumps(value, ensure_ascii=False, default=str)
        return out

    def _change_lines(self, profile_id: str) -> list[str]:
        latest = next((c for c in self.store.config_changes(50) if c.get("profile_id") == profile_id), None)
        if not latest:
            return []
        lines = []
        if latest.get("change_type"):
            lines.append(f"▸ <b>Section:</b> {html_escape(str(latest['change_type']))}")
        try:
            before = self._flatten(unwrap_profile_data(json.loads(latest.get("before_json") or "{}")))
            after = self._flatten(unwrap_profile_data(json.loads(latest.get("after_json") or "{}")))
        except (TypeError, ValueError):
            return lines
        shown = 0
        for key in sorted(set(before) | set(after)):
            if before.get(key) != after.get(key):
                shown += 1
                if shown <= 12:
                    lines.append(f"▸ <code>{html_escape(key)}</code>: {html_escape(before.get(key, '—')[:80])} → <b>{html_escape(after.get(key, '—')[:80])}</b>")
        if shown > 12:
            lines.append(f"▸ …and {shown - 12} more change(s)")
        return lines

    def build_report(self, account: dict[str, Any], domain: str, reason: str, status: str, matched: str,
                     client_ip: str, event_time: str, device_id: str, device_name: str, device_model: str,
                     protocol: str, encrypted: bool, context: dict[str, Any],
                     repeats: int = 0, repeat_since: str = "") -> tuple[str, str]:
        alert_type = str(context.get("alert_type") or "").lower()
        status_l = str(status or context.get("status") or "").lower()
        kinds = self.REPORT_KINDS
        kind = "denylist_match" if alert_type == "denylist_match" else (status_l if status_l in kinds else (alert_type if alert_type in kinds else "security_event"))
        title, sentence, category = kinds[kind]
        origin_key, origin_label = origin_of(str(context.get("source") or ("nextdns_logs" if kind == "denylist_match" else "")))
        e = html_escape
        lines = [f"<b>{title}</b>", f"<i>{e(sentence)}</i>", ""]
        created = str(context.get("created_at") or "")
        try:
            late = (datetime.now(timezone.utc) - datetime.fromisoformat((event_time or created).replace("Z", "+00:00"))).total_seconds() if (event_time or created) else 0
        except ValueError:
            late = 0
        if late > 120 and kind != "device_inactive":
            mins = int(late // 60)
            ago = f"{mins} min" if mins < 120 else f"{mins // 60} h"
            lines.insert(0, f"⏳ <b>DELAYED ALERT</b> — this happened {ago} ago while Sentinel or the bot was offline")
        if domain:
            lines.append(f"🌐 <b>{e(domain)}</b>")
            if matched and matched != domain:
                lines.append(f"▸ Matched rule: <code>{e(matched)}</code>")
        lines.append(f"👤 <b>Account:</b> {e(str(account.get('name') or '—'))}")
        profile_name = str(account.get("profile_name") or "").strip()
        lines.append(f"📂 <b>NextDNS profile:</b> {e(profile_name) if profile_name else '—'} · <code>{e(str(account.get('profile_id') or ''))}</code>")
        if device_name or device_id:
            model = f" ({e(device_model)})" if device_model else ""
            lines.append(f"📱 <b>Device:</b> {e(device_name or device_id)}{model}")
        if client_ip:
            lines.append(f"🌍 <b>IP address:</b> <code>{e(client_ip)}</code>")
        if kind == "denylist_match":
            lines.append(f"⛔ <b>Result:</b> {e(str(status or 'blocked').upper())}" + (f" · {e(protocol)}" if protocol else "") + (" · encrypted" if encrypted else ""))
        elif kind == "device_inactive":
            lines.append(f"🕘 <b>Last DNS activity:</b> {e(fmt_dt12(event_time))}")
        elif reason and kind not in ("config_changed", "configuration_undo"):
            lines.append(f"📝 <b>Details:</b> {e(reason)}")
        if kind in ("config_changed", "configuration_undo"):
            lines.extend(self._change_lines(str(account.get("profile_id") or "")))
        if kind == "denylist_match" and repeats > 0:
            since = f" (first at {e(fmt_dt12(repeat_since, False).split(' (')[0])})" if repeat_since else ""
            lines.append(f"🔁 <b>{repeats}</b> more attempt{'s' if repeats != 1 else ''} since the last alert{since}")
        lines.append("━━━━━━━━━━━━━━")
        when = event_time if kind in ("denylist_match", "device_inactive") and event_time else utc_now()
        lines.append(f"🕒 <b>When:</b> {e(fmt_dt12(when if kind != 'device_inactive' else utc_now()))}")
        lines.append(f"{self.ORIGIN_ICON.get(origin_key, '⚙️')} <b>Origin:</b> {e(origin_label)}")
        return "\n".join(lines), category

    @staticmethod
    def _bot_wants(bot: dict[str, Any], category: str) -> bool:
        wanted = [x for x in str(bot.get("alert_types") or "").split(",") if x]
        return not wanted or not category or category in wanted

    @staticmethod
    def _bot_quiet_now(bot: dict[str, Any]) -> bool:
        a, b = str(bot.get("quiet_start") or ""), str(bot.get("quiet_end") or "")
        if not a or not b:
            return False
        now = datetime.now(local_tz()).strftime("%H:%M")
        return (a <= now < b) if a < b else (now >= a or now < b)

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
        repeats: int = 0,
        repeat_since: str = "",
    ) -> bool:
        if self.features and alert_id and not self.store.claim_alert_id(int(alert_id)):
            # Another sender already delivered (or is delivering) this alert.
            logging.debug("Alert %s already claimed; skipping duplicate Telegram send.", alert_id)
            return True
        context = self.features.alert_context(alert_id) if self.features and alert_id else {}
        message, category = self.build_report(account, domain, reason, status, matched, client_ip, event_time,
                                              device_id, device_name, device_model, protocol, encrypted,
                                              context, repeats, repeat_since)
        return self._send_all(message, category)

    def _send_all(self, message: str, category: str = "", parse_mode: str = "HTML") -> bool:
        """Send to every enabled bot that wants this kind of report, in parallel."""
        destinations = self.store.telegram_destinations()
        if destinations:
            targets = [b for b in destinations if self._bot_wants(b, category)]
            if not targets:
                return True  # every bot opted out of this kind of report; nothing to deliver
            def one(bot: dict[str, Any]) -> bool:
                ok, why = send_telegram_result(bot["token"], bot["chat_id"], message, retries=1,
                                               parse_mode=parse_mode, silent=self._bot_quiet_now(bot))
                self.store.mark_telegram_bot_result(int(bot["id"]), ok, "" if ok else why)
                return ok
            with ThreadPoolExecutor(max_workers=min(8, len(targets))) as pool:
                return any(list(pool.map(one, targets)))
        return False  # no enabled bot: nothing is sent anywhere

    def notify_report(self, title: str, lines: list[str], alert_id: int | None = None, origin: str = "dashboard") -> bool:
        label = origin_of({"dashboard": "sentinel_dashboard", "app": "nextdns_profile", "device": "nextdns_logs"}.get(origin, ""))[1]
        body = "\n".join("▸ " + html_escape(str(x)) for x in lines)
        message = (f"<b>🛡️ {html_escape(title)}</b>\n\n{body}\n━━━━━━━━━━━━━━\n"
                   f"🕒 <b>When:</b> {html_escape(fmt_dt12(utc_now()))}\n"
                   f"{self.ORIGIN_ICON.get(origin, '⚙️')} <b>Origin:</b> {html_escape(label)}")
        ok = self._send_all(message, "system")
        if self.features and alert_id:
            self.features.delivery(alert_id, "telegram", "sent" if ok else "failed")
        return ok

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
            try:
                if not getattr(self, "_requeued", False):
                    self._requeued = True
                    requeued = self.store.requeue_skipped_notifications()
                    if requeued:
                        logging.info("Re-queued %d alert(s) that were previously skipped as old.", requeued)
            except Exception:
                logging.debug("Re-queue of skipped alerts failed", exc_info=True)
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
                if iteration == 1 or iteration % CONFIG_CHECK_EVERY == 0:
                    try:
                        live_profile=client.profile(profile_id)
                        live_snapshot=config_snapshot(live_profile)
                        previous=self.store.config_snapshot(profile_id)
                        recent_dashboard = False
                        try:
                            mark = self.store.setting(f"dash_mark:{profile_id}", "")
                            recent_dashboard = bool(mark) and (datetime.now(timezone.utc) - datetime.fromisoformat(mark)).total_seconds() < 8
                        except (TypeError, ValueError):
                            recent_dashboard = False
                        if recent_dashboard:
                            pass  # the dashboard just changed this profile and stored its own snapshot
                        elif previous is not None and previous != live_snapshot:
                            def deny_ids(snap: dict[str, Any]) -> set[str]:
                                out = set()
                                for item in (snap.get("denylist") or []):
                                    out.add(str(item.get("id") or item.get("domain") or "") if isinstance(item, dict) else str(item))
                                out.discard("")
                                return out
                            before_deny, after_deny = deny_ids(previous), deny_ids(live_snapshot)
                            sections = [k for k in sorted(set(previous) | set(live_snapshot)) if previous.get(k) != live_snapshot.get(k)]
                            others = [k for k in sections if k != "denylist"]
                            change_id = self.store.add_config_change(profile_id, previous, live_snapshot, config_change_summary(previous, live_snapshot), "nextdns_profile")
                            def raise_alert(domain: str, reason: str, status: str, label: str) -> None:
                                key = hashlib.sha256(f"app:{label}:{profile_id}:{domain}:{change_id}".encode()).hexdigest()
                                self.store.add_alert(profile_id, account["name"], domain, domain, reason, status, "", utc_now(), key, "config_change", source="nextdns_profile")
                                alert_id = self.enrich_alert(key, account, domain, reason, status, domain, "", utc_now(), "", "", "", "", False)
                                delivered = self.notify(account, domain, reason, status, domain, event_time=utc_now(), alert_id=alert_id)
                                if delivered:
                                    self.store.mark_alert_notified(key)
                                    if self.features and alert_id: self.features.delivery(alert_id, "telegram", "sent")
                                else:
                                    self.store.mark_notification_failed(key)
                                    if self.features and alert_id: self.features.delivery(alert_id, "telegram", "failed")
                            for domain in sorted(after_deny - before_deny):
                                raise_alert(domain, "Denylist entry added in the NextDNS app", "denylist_added", "add")
                            for domain in sorted(before_deny - after_deny):
                                raise_alert(domain, "Denylist entry removed in the NextDNS app", "denylist_removed", "remove")
                            if others:
                                raise_alert("", "Configuration changed in the NextDNS app: " + ", ".join(others), "config_changed", "cfg")
                        if not recent_dashboard:
                            self.store.save_config_snapshot(profile_id,live_snapshot)
                    except Exception as exc:
                        logging.warning("Profile configuration snapshot failed for %s: %s",account["name"],exc)
                    if iteration == 1 or iteration % 20 == 0:
                        removed = self.store.cleanup_alerts(ALERT_RETENTION_DAYS)
                        if removed:
                            logging.info("Removed %d old delivered alerts.", removed)
                    fresh_denylist = set(client.denylist(profile_id))
                    if fresh_denylist != denylist:
                        logging.info("Loaded %d denylist entries for %s", len(fresh_denylist), account["name"])
                    denylist = fresh_denylist
                    self.store.replace_denylist(profile_id, list(denylist))
                else:
                    # Entries added from the dashboard are written to the local store immediately;
                    # pick them up on every poll so a newly blocked site is detected right away.
                    local_denylist = set(self.store.denylist_entries(profile_id))
                    if local_denylist != denylist:
                        denylist = local_denylist

                last_poll_ms = self.store.get_poll_ms(profile_id)
                now_ms = int(time.time() * 1000)
                from_ms = (
                    max(last_poll_ms - POLL_OVERLAP_MS, 0)
                    if last_poll_ms
                    else now_ms - INITIAL_LOOKBACK * 1000
                )

                logs, checkpoint_ms = client.logs(profile_id, from_ms)
                try:
                    newest_log = max((event_timestamp(l) for l in logs), default="")
                    self.store.set_setting(f"logstat:{profile_id}", json.dumps({"polled_at": utc_now(), "count": len(logs), "newest": newest_log}))
                except Exception:
                    logging.debug("Could not record log intake statistics.", exc_info=True)
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

                    if self.store.event_exists(profile_id, domain, event_time, device_id, client_ip):
                        continue
                    key = event_key(profile_id, log)
                    matched = find_matching_domain(domain, denylist) or matched_domain(log)
                    reason = event_reason(log) or "Custom denylist match"

                    recently_notified = self.store.was_recently_notified(
                        profile_id, domain, ALERT_COOLDOWN, device_id
                    )
                    repeats, repeat_since = self.store.repeat_info(profile_id, domain, device_id)
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
                                repeats=repeats, repeat_since=repeat_since,
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
<button onclick="login()">Sign in</button><button onclick="turnOff()" style="background:#2a3550;color:#e8edf7;margin-top:8px">Turn protection OFF</button><div class="muted" style="margin-top:10px">Turning protection off needs the same token.</div><div id="error" class="error"></div></div>
<script>async function login(){const e=document.getElementById('error');e.textContent='';try{const r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:document.getElementById('token').value})});const d=await r.json();if(!r.ok)throw new Error(d.error||'Authentication failed');location.reload()}catch(x){e.textContent=x.message}}async function turnOff(){const e=document.getElementById('error');e.textContent='';try{const r=await fetch('/api/auth/disable',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:document.getElementById('token').value})});const d=await r.json();if(!r.ok)throw new Error(d.error||'Could not turn protection off');location.reload()}catch(x){e.textContent=x.message}}</script></body></html>"""

DASHBOARD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NextDNS Sentinel</title>
<style>:root{color-scheme:dark}*{box-sizing:border-box}body{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:radial-gradient(circle at 15% 0%,#14243a 0,#080b12 36%);color:#e8edf7;margin:0;padding:24px;line-height:1.45}main{max-width:1250px;margin:auto}h1{margin:0;font-size:32px;letter-spacing:-.6px}h2{margin:0 0 12px;font-size:18px}h3{margin:0 0 10px}.muted{color:#8c98aa}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:18px 0}.card,.panel{background:linear-gradient(145deg,rgba(16,22,33,.97),rgba(11,16,25,.97));border:1px solid #263248;border-radius:16px;padding:17px;margin-bottom:14px;box-shadow:0 12px 35px rgba(0,0,0,.16)}.value{font-size:29px;font-weight:750;margin-top:3px}.card .muted{text-transform:capitalize;font-size:12px;letter-spacing:.4px}.status{margin:10px 0;padding:11px 13px;border-radius:10px;background:#101621;border:1px solid #263248}.ok{color:#9af0bb}.error{color:#ffb4b4}.neutral-text{color:#b8c4d8}button{border:1px solid transparent;border-radius:9px;padding:9px 13px;font-weight:700;cursor:pointer;margin:3px;transition:transform .15s,filter .15s}button:hover{filter:brightness(1.08);transform:translateY(-1px)}.start{background:#35c76f;color:#07140b}.stop{background:#ef6b73;color:#21080a}.neutral{background:#29364a;color:#e8edf7}input,select{width:100%;box-sizing:border-box;background:#0b1019;color:#e8edf7;border:1px solid #303b4e;border-radius:9px;padding:10px;margin:5px 0 10px}label{display:block;font-size:13px;color:#aeb8c8}form{max-width:560px}table{width:100%;border-collapse:collapse;background:#101621;border-radius:14px;overflow:hidden}th,td{text-align:left;padding:10px;border-bottom:1px solid #202a3a;font-size:13px}th{color:#9eabc0;font-size:12px;text-transform:uppercase;letter-spacing:.5px}tbody tr:hover{background:#141d2a}code{color:#9ed0ff}.hidden{display:none}
#event-timeline,#device-activity,#profile-health,#accounts,#grouped-denylist,#incidents,#domain-intelligence{max-height:440px;overflow:auto}
.table-wrap{max-height:520px;overflow:auto}
@media(min-width:901px){.table-wrap table{min-width:1020px}}
.type-badge{display:inline-block;font-size:11px;padding:2px 8px;border-radius:99px;background:#172235;color:#aebbd0;white-space:nowrap}
.type-badge.site{background:rgba(239,107,115,.18);color:#ff9aa0}.type-badge.cfg{background:rgba(239,201,95,.16);color:#efc95f}.type-badge.dev{background:rgba(94,160,255,.16);color:#8fbaff}.type-badge.sys{background:rgba(85,217,138,.14);color:#7be0a6}
.modal-back{position:fixed;inset:0;background:rgba(0,0,0,.62);z-index:60;display:flex;align-items:center;justify-content:center;padding:14px}
.modal-box{background:#0f1520;border:1px solid #263248;border-radius:16px;max-width:920px;width:100%;max-height:86vh;display:flex;flex-direction:column}
.modal-box header{display:flex;justify-content:space-between;align-items:center;padding:14px 16px;border-bottom:1px solid #202a3a}
.modal-box .modal-body{overflow:auto;padding:12px 16px}
.modal-box table{width:100%}.account{padding:12px 0;border-bottom:1px solid #202a3a}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;margin:10px 0}.meta div{background:#0b1019;border:1px solid #202a3a;border-radius:8px;padding:9px}.meta strong{display:block;font-size:12px;color:#8c98aa;margin-bottom:3px}.hero{display:flex;justify-content:space-between;gap:18px;align-items:center;padding:22px 24px;margin-bottom:14px}.hero-copy{min-width:0}.eyebrow{font-size:11px;text-transform:uppercase;letter-spacing:1.6px;color:#7f91aa;font-weight:800}.hero-badge{border:1px solid #2d405c;background:#0c1420;border-radius:12px;padding:10px 13px;white-space:nowrap}.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px;background:#65758d}.dot.ok{background:#35c76f}.analytics{display:grid;grid-template-columns:minmax(0,2fr) minmax(260px,1fr);gap:14px}.chart{height:230px;display:flex;align-items:flex-end;gap:6px;padding:18px 8px 28px;border-top:1px solid #202a3a}.bar-wrap{height:100%;flex:1;display:flex;align-items:flex-end;justify-content:center;position:relative;min-width:4px}.bar{width:100%;max-width:22px;min-height:3px;border-radius:6px 6px 2px 2px;background:linear-gradient(180deg,#55d98a,#2e9e68);transition:height .3s}.bar-label{position:absolute;bottom:-24px;font-size:10px;color:#75839a;white-space:nowrap}.bar-value{position:absolute;top:-18px;font-size:10px;color:#aebbd0}.panel{transition:transform .18s ease,border-color .18s ease}.panel:hover{border-color:#34435d}.table-wrap table{min-width:760px}.table-wrap th{position:sticky;top:0;background:#101621;z-index:2}.sidebar .nav-btn{opacity:.86}.sidebar .nav-btn.active{opacity:1;box-shadow:inset 3px 0 #55d98a;background:#172235}.status.error{box-shadow:0 0 0 1px rgba(239,107,115,.12)}.toast{position:fixed;right:20px;bottom:20px;z-index:1000;max-width:min(520px,calc(100vw - 40px));padding:12px 15px;border:1px solid #34435d;border-radius:12px;background:#101621;box-shadow:0 14px 40px rgba(0,0,0,.35);opacity:0;pointer-events:none;transform:translateY(8px);transition:.2s}.toast.show{opacity:1;transform:translateY(0)}.toast.ok{border-color:#2f8b58}.toast.error{border-color:#a54d55}.mini-list{display:grid;gap:8px}.mini-item{display:flex;justify-content:space-between;gap:10px;padding:9px 10px;background:#0b1019;border:1px solid #202a3a;border-radius:9px}.progress{height:5px;background:#202a3a;border-radius:99px;overflow:hidden;margin-top:5px}.progress>span{display:block;height:100%;background:#55d98a}.section-head{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:10px}.pill{font-size:11px;padding:4px 8px;border-radius:99px;background:#172235;color:#aebbd0}@media(max-width:800px){body{padding:12px}.analytics{grid-template-columns:1fr}.hero{align-items:flex-start;flex-direction:column}.hero-badge{width:100%}}.device-badge{font-size:11px;padding:5px 9px;border:1px solid #2d405c;border-radius:99px;background:#101a28;color:#b8c4d8}.health-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:10px}.health-card{padding:12px;background:#0b1019;border:1px solid #202a3a;border-radius:10px}.health-card .name{font-weight:750}.health-card .line{display:flex;justify-content:space-between;gap:8px;font-size:12px;margin-top:5px}.timeline{display:grid;gap:8px}.timeline-item{display:grid;grid-template-columns:8px 1fr auto;gap:10px;align-items:center;padding:9px 10px;background:#0b1019;border:1px solid #202a3a;border-radius:9px}.timeline-dot{width:8px;height:8px;border-radius:50%;background:#55d98a}.timeline-dot.warn{background:#efc95f}.timeline-dot.error{background:#ef6b73}.table-wrap{overflow-x:auto;border-radius:14px}.device-state{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px}.device-item{padding:10px;background:#0b1019;border:1px solid #202a3a;border-radius:10px}.device-item .name{font-weight:750}.device-item .line{font-size:12px;display:flex;justify-content:space-between;margin-top:5px}body.device-android{padding:12px}body.device-android main{max-width:100%}body.device-android h1{font-size:26px}body.device-android .card{padding:14px}body.device-android button{min-height:42px}body.device-android input,body.device-android select{min-height:44px}body.device-windows{padding:28px}@media(max-width:560px){.grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.value{font-size:23px}.card{padding:13px}.chart{gap:2px;height:200px}.bar{max-width:12px}.bar-label{font-size:8px;transform:rotate(-35deg);transform-origin:top left}.section-head{align-items:flex-start;flex-direction:column}.hero-badge{white-space:normal}.timeline-item{grid-template-columns:8px minmax(0,1fr);}.timeline-item>strong{grid-column:2}}.app-shell{display:flex;min-height:calc(100vh - 48px);max-width:1500px;margin:auto}.sidebar{width:245px;flex:0 0 245px;background:rgba(9,14,22,.96);border:1px solid #263248;border-radius:18px;padding:14px;position:sticky;top:24px;height:calc(100vh - 48px);overflow:auto;z-index:50}.sidebar-brand{display:flex;align-items:center;gap:10px;padding:10px 8px 16px;border-bottom:1px solid #202a3a;margin-bottom:12px}.sidebar-brand img{width:30px;height:30px}.nav-label{font-size:10px;text-transform:uppercase;letter-spacing:1.3px;color:#66758c;font-weight:800;padding:10px}.nav-btn{width:100%;display:flex;align-items:center;gap:10px;text-align:left;background:transparent;color:#aebbd0;border:1px solid transparent;padding:10px 11px;margin:2px 0}.nav-btn:hover{background:#111b29;border-color:#24334a;transform:none}.nav-btn.active{background:#162238;border-color:#2d405c;color:#e8edf7}.nav-btn img{width:18px;height:18px}.app-content{min-width:0;flex:1;padding-left:16px}.page-view{display:none}.page-view.active{display:block}.sidebar-toggle{display:none}@media(max-width:900px){.app-shell{display:block}.sidebar{position:fixed;left:12px;top:12px;bottom:12px;height:auto;width:270px;transform:translateX(-120%);transition:transform .2s;box-shadow:0 20px 60px rgba(0,0,0,.5)}.sidebar.open{transform:translateX(0)}.sidebar-toggle{display:flex;position:fixed;left:18px;top:18px;width:44px;height:44px;z-index:60;align-items:center;justify-content:center;background:#162238;color:#e8edf7;border:1px solid #30415a;border-radius:11px}.sidebar-toggle svg{width:22px;height:22px}.app-content{padding-left:0}.hero{padding-top:72px}} .toast{position:fixed;right:20px;bottom:20px;z-index:1000;max-width:min(520px,calc(100vw - 40px));padding:12px 15px;border:1px solid #344766;border-radius:12px;background:rgba(10,16,27,.96);box-shadow:0 18px 50px rgba(0,0,0,.35);font-size:13px;display:none}.toast.show{display:block}.toast.error{color:#ffd0d0;border-color:#6a3640}.toast.ok{color:#c8ffdc;border-color:#2f6b4b}.action-cell{white-space:nowrap}.scalable-list{max-height:430px;overflow:auto;padding-right:3px}.scalable-list::-webkit-scrollbar{width:7px}.scalable-list::-webkit-scrollbar-thumb{background:#30415a;border-radius:8px}#alerts,#accounts,#denylist,#device-activity,#event-timeline,#config-changes,#telegram-bot-card{max-height:430px;overflow:auto;padding-right:3px}.table-wrap{max-height:520px;overflow:auto}.table-wrap table{min-width:760px}.section-head h2{letter-spacing:-.2px}.panel{backdrop-filter:blur(8px)}.start{background:linear-gradient(135deg,#35d487,#25ad73);box-shadow:0 6px 18px rgba(37,173,115,.16)}.neutral{background:linear-gradient(135deg,#263852,#1d2a3f)}.stop{background:linear-gradient(135deg,#ef6b73,#c94f5b)}.pretty-json{margin:5px 0 0;white-space:pre-wrap;overflow:auto;font:11px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;color:#c9d4e5;background:#080d15;border:1px solid #202a3a;border-radius:8px;padding:8px;max-width:min(760px,70vw)}
.json-diff-row{align-items:flex-start}
.json-diff-row>strong{min-width:180px}
.pretty-json{white-space:pre-wrap}
.recent-alerts-panel{border-color:#334766;background:linear-gradient(145deg,rgba(18,27,41,.98),rgba(10,15,24,.98));box-shadow:0 14px 38px rgba(0,0,0,.22)}
.recent-alerts-head{align-items:flex-start}
.recent-alerts-head h2{display:flex;align-items:center;gap:8px}
.recent-alerts-dot{width:9px;height:9px;border-radius:50%;background:#efc95f;box-shadow:0 0 12px rgba(239,201,95,.55)}
.recent-alerts-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:10px}
.recent-alert-account{background:#0b1019;border:1px solid #263248;border-radius:12px;padding:12px;min-width:0}
.recent-alert-account.unseen{border-color:#3a506f}
.recent-alert-account-head{display:flex;justify-content:space-between;align-items:flex-start;gap:10px;margin-bottom:9px}
.recent-alert-account-title{min-width:0}
.recent-alert-account-title strong{display:block;font-size:15px}
.recent-alert-account-title .muted{font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.recent-alert-summary{display:flex;gap:5px;flex-wrap:wrap;margin-top:7px}
.recent-alert-summary .pill{font-size:10px}
.recent-alert-list{display:grid;gap:7px;max-height:360px;overflow:auto;padding-right:2px}
.recent-alert-item{display:grid;grid-template-columns:30px minmax(0,1fr) auto;gap:9px;align-items:start;padding:9px;background:#101621;border:1px solid #202a3a;border-radius:10px}
.recent-alert-item.unseen{border-left:3px solid #efc95f;background:#121b29}
.recent-alert-icon{width:28px;height:28px;display:grid;place-items:center;border-radius:8px;background:#172235;font-size:15px}
.recent-alert-main{min-width:0}
.recent-alert-type{font-weight:800;font-size:12px}
.recent-alert-detail{font-size:12px;margin-top:3px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.recent-alert-meta{display:flex;gap:7px;flex-wrap:wrap;margin-top:5px;font-size:10px;color:#8c98aa}
.recent-alert-time{font-size:10px;color:#8c98aa;white-space:nowrap}
.recent-alert-actions{display:flex;align-items:center;gap:3px}
.recent-alert-actions button{padding:6px 8px;font-size:10px;margin:0}
.recent-alert-seen{color:#9af0bb}
.recent-alert-new{color:#efc95f}
.recent-alert-empty{padding:16px;text-align:center;background:#0b1019;border:1px dashed #263248;border-radius:10px}
@media(max-width:700px){.recent-alerts-grid{grid-template-columns:1fr}
.recent-alert-item{grid-template-columns:28px minmax(0,1fr)}}
/* ===== Sentinel theme v2: refined palette, depth, readable density ===== */
:root{--bg0:#070a11;--bg1:#0b1019;--bg2:#101826;--line:#1f2b3f;--line2:#2c3d58;--tx:#e9eef8;--tx2:#9fb0c9;--tx3:#6f819d;--acc:#4f9dff;--acc2:#7c6cff;--good:#3ddc97;--warn:#f5c451;--bad:#ff6b7a;--info:#5ad1e6}
body{background:radial-gradient(1100px 600px at 12% -8%,rgba(79,157,255,.16),transparent 60%),radial-gradient(900px 500px at 100% 0%,rgba(124,108,255,.12),transparent 55%),var(--bg0)!important;color:var(--tx)}
h1{background:linear-gradient(90deg,#fff,#a9c8ff);-webkit-background-clip:text;background-clip:text;color:transparent}
h2{font-size:17px;font-weight:700;letter-spacing:-.2px;display:flex;align-items:center;gap:8px}
h2::before{content:"";width:4px;height:16px;border-radius:3px;background:linear-gradient(180deg,var(--acc),var(--acc2));flex:none}
.muted{color:var(--tx2)!important}
.card,.panel{background:linear-gradient(160deg,rgba(17,25,39,.96),rgba(11,16,26,.96))!important;border:1px solid var(--line)!important;border-radius:18px!important;box-shadow:0 14px 40px rgba(0,0,0,.28),inset 0 1px 0 rgba(255,255,255,.03)!important}
.panel:hover{border-color:var(--line2)!important}
/* stat cards: colored accent rail */
#stats .card{position:relative;overflow:hidden;cursor:pointer;transition:transform .15s,border-color .15s}
#stats .card::before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--acc)}
#stats .card:nth-child(2)::before{background:var(--good)}#stats .card:nth-child(3)::before{background:var(--bad)}#stats .card:nth-child(4)::before{background:var(--warn)}#stats .card:nth-child(5)::before{background:var(--info)}
#stats .card:hover{transform:translateY(-2px);border-color:var(--acc)!important}
#stats .value{font-size:32px;background:linear-gradient(90deg,#fff,#b9d4ff);-webkit-background-clip:text;background-clip:text;color:transparent}
/* buttons */
button{border-radius:10px!important;letter-spacing:.1px}
button.start{background:linear-gradient(135deg,#2fd68a,#1fae6e)!important;color:#04150d!important}
button.stop{background:linear-gradient(135deg,#ff7b87,#e0505f)!important;color:#240709!important}
button.neutral{background:#1a2638!important;border:1px solid var(--line2)!important;color:var(--tx)!important}
button.neutral:hover{background:#22314a!important;border-color:var(--acc)!important}
button:not(.neutral):not(.start):not(.stop):not(.nav-btn){background:linear-gradient(135deg,var(--acc),var(--acc2));color:#fff}
button:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--acc);outline-offset:2px}
/* inputs */
input,select,textarea{background:#0a111c!important;border:1px solid var(--line2)!important;border-radius:10px!important;color:var(--tx)!important}
input:focus,select:focus,textarea:focus{border-color:var(--acc)!important;box-shadow:0 0 0 3px rgba(79,157,255,.18)}
/* tables */
table{background:transparent!important}
thead th{position:sticky;top:0;background:#0e1623!important;z-index:1;color:var(--tx3)!important}
tbody tr:nth-child(even){background:rgba(255,255,255,.015)}
tbody tr:hover{background:rgba(79,157,255,.07)!important}
th,td{border-bottom:1px solid var(--line)!important}
/* status strips */
.status{border-radius:12px!important;background:rgba(15,22,34,.9)!important;border:1px solid var(--line2)!important}
.ok{color:var(--good)!important}.error{color:var(--bad)!important}
.account,details.account{background:rgba(255,255,255,.02);border:1px solid var(--line);border-radius:14px;padding:10px 12px;margin:8px 0}
details.account[open]{border-color:var(--line2);background:rgba(79,157,255,.04)}
details.account>summary{font-weight:700;list-style:none}
details.account>summary::-webkit-details-marker{display:none}
details.account>summary::before{content:"▸";display:inline-block;margin-right:8px;color:var(--acc);transition:transform .15s}
details.account[open]>summary::before{transform:rotate(90deg)}
/* badges */
.type-badge{font-weight:700;letter-spacing:.2px;border:1px solid transparent}
.type-badge.site{border-color:rgba(255,107,122,.35)}.type-badge.cfg{border-color:rgba(245,196,81,.35)}.type-badge.dev{border-color:rgba(90,209,230,.35);background:rgba(90,209,230,.12);color:#8fe3f2}.type-badge.sys{border-color:rgba(61,220,151,.3)}
/* sidebar */
.sidebar{background:linear-gradient(180deg,rgba(14,21,33,.97),rgba(8,12,19,.97))!important;border:1px solid var(--line)!important}
.nav-btn{border-radius:11px!important;transition:background .15s,transform .15s}
.nav-btn:hover{background:rgba(79,157,255,.10)!important;transform:none}
.nav-btn.active{background:linear-gradient(90deg,rgba(79,157,255,.22),rgba(124,108,255,.10))!important;box-shadow:inset 3px 0 0 var(--acc)}
/* scrollbars */
*{scrollbar-width:thin;scrollbar-color:#2c3d58 transparent}
::-webkit-scrollbar{width:9px;height:9px}::-webkit-scrollbar-thumb{background:#2c3d58;border-radius:8px}::-webkit-scrollbar-track{background:transparent}
.modal-box{background:linear-gradient(160deg,#111a2a,#0b111b)!important;border-color:var(--line2)!important;box-shadow:0 30px 80px rgba(0,0,0,.6)}

.dirty-tag{display:none;margin:6px 0;padding:4px 11px;border-radius:99px;background:rgba(245,196,81,.16);color:#f5c451;font-weight:700;font-size:12px;border:1px solid rgba(245,196,81,.4)}
label.changed{background:rgba(245,196,81,.10);border-radius:8px;padding:3px 7px;outline:1px solid rgba(245,196,81,.35)}
.row3{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.rule-builder label{margin-top:8px}
.pending-pill{position:fixed;right:18px;bottom:18px;z-index:70;background:linear-gradient(135deg,#4f9dff,#7c6cff)!important;color:#fff!important;border:0;padding:11px 16px!important;border-radius:99px!important;box-shadow:0 10px 30px rgba(79,157,255,.45);animation:pillIn .25s ease}
@keyframes pillIn{from{transform:translateY(14px);opacity:0}to{transform:none;opacity:1}}
@media(max-width:860px){body{padding:10px}.grid{grid-template-columns:repeat(2,1fr)}}

/* ===== v4: feedback, badges, cards, charts, telegram, devices, mobile ===== */
#toast-stack{position:fixed;top:16px;right:16px;z-index:90;display:flex;flex-direction:column;gap:8px;max-width:min(420px,calc(100vw - 32px))}
.toast-item{display:flex;align-items:center;gap:10px;padding:11px 14px;border-radius:12px;background:#101a2b;border:1px solid var(--line2);box-shadow:0 12px 34px rgba(0,0,0,.45);animation:tIn .22s ease;font-size:13.5px}
.toast-item.out{opacity:0;transform:translateX(16px);transition:.3s}
.toast-item.ok{border-color:rgba(61,220,151,.5)}.toast-item.ok .toast-ico{color:var(--good)}
.toast-item.error{border-color:rgba(255,107,122,.55)}.toast-item.error .toast-ico{color:var(--bad)}
.toast-item.info{border-color:rgba(90,209,230,.5)}.toast-item.info .toast-ico{color:var(--info)}
.toast-msg{flex:1}.toast-x{background:transparent!important;border:0;color:var(--tx3)!important;padding:0 4px!important;font-size:18px}
@keyframes tIn{from{transform:translateX(20px);opacity:0}to{transform:none;opacity:1}}
.state-chip{display:inline-block;padding:3px 10px;border-radius:99px;font-size:11.5px;font-weight:800;letter-spacing:.3px;border:1px solid transparent;white-space:nowrap}
.state-chip.ok{background:rgba(61,220,151,.14);color:var(--good);border-color:rgba(61,220,151,.4)}
.state-chip.bad{background:rgba(255,107,122,.14);color:var(--bad);border-color:rgba(255,107,122,.4)}
.state-chip.warn{background:rgba(245,196,81,.14);color:var(--warn);border-color:rgba(245,196,81,.4)}
.state-chip.muted{background:rgba(139,155,181,.12);color:var(--tx2);border-color:rgba(139,155,181,.3)}
.cat-badge{display:inline-flex;align-items:center;gap:4px;padding:2px 9px;border-radius:99px;font-size:11.5px;font-weight:700;background:color-mix(in srgb,var(--c) 15%,transparent);color:var(--c);border:1px solid color-mix(in srgb,var(--c) 40%,transparent);white-space:nowrap}
.origin-badge{display:inline-flex;align-items:center;gap:4px;padding:2px 9px;border-radius:8px;font-size:11.5px;font-weight:700;white-space:nowrap;border:1px solid transparent}
.o-dash{background:rgba(79,157,255,.14);color:#8fbaff;border-color:rgba(79,157,255,.4)}
.o-app{background:rgba(61,220,151,.13);color:#7be0a6;border-color:rgba(61,220,151,.4)}
.o-dev{background:rgba(255,159,107,.13);color:#ffb68c;border-color:rgba(255,159,107,.4)}
.o-sys{background:rgba(139,155,181,.12);color:#aab6cc;border-color:rgba(139,155,181,.3)}
.pill.new-pill{background:rgba(61,220,151,.18)!important;color:var(--good)!important;font-weight:800}
.pill.bad{background:rgba(255,107,122,.16)!important;color:var(--bad)!important}
.small{font-size:12px}.chips{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0}
button.mini{padding:4px 9px!important;font-size:12px!important}
.kv{display:flex;gap:6px;font-size:13px;line-height:1.5}.kv em{font-style:normal;color:var(--tx3);min-width:max-content}.kv span{color:var(--tx);word-break:break-word}
/* recent alerts */
.recent-alert-empty{text-align:center;padding:26px 10px;border:1px dashed var(--line2);border-radius:14px}.recent-alert-empty .big{font-size:34px;color:var(--good)}
.recent-account{border:1px solid var(--line2);border-radius:14px;padding:12px;margin:10px 0;background:rgba(255,255,255,.015)}
.recent-account-head{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}
.recent-list{display:flex;flex-direction:column;gap:8px;margin-top:6px}
.recent-item{display:flex;gap:10px;align-items:flex-start;padding:10px;border-radius:12px;background:#0c1422;border:1px solid var(--line);border-left:4px solid var(--c)}
.recent-ico{font-size:20px;line-height:1}.recent-main{flex:1;min-width:0}
.recent-title{display:flex;flex-wrap:wrap;gap:8px;align-items:center}.recent-domain{font-family:ui-monospace,monospace;color:var(--c);font-weight:700}
.recent-meta,.recent-foot{display:flex;flex-wrap:wrap;gap:6px 14px;margin-top:5px;align-items:center}
/* stat cards */
.stat-card{position:relative;overflow:hidden;cursor:pointer}.stat-card::before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--c)}
.stat-sub{display:flex;flex-wrap:wrap;gap:5px;margin-top:6px}.stat-chip{font-size:11px;padding:2px 8px;border-radius:99px;background:rgba(255,255,255,.05);color:var(--tx2)}
.spark{margin-top:8px;height:34px}.spark svg{width:100%;height:34px}
#ov-insights{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:18px}
.ov-col h3{margin:0 0 8px}.act-row{display:flex;justify-content:space-between;gap:10px;padding:8px 0;border-bottom:1px solid var(--line)}.act-meta{display:flex;gap:6px;flex-wrap:wrap;align-items:center;justify-content:flex-end}
.hbar-row{display:grid;grid-template-columns:minmax(90px,38%) 1fr 36px;gap:10px;align-items:center;margin:7px 0;font-size:13px}.hbar-row.big{grid-template-columns:minmax(110px,34%) 1fr 44px}
.hbar-label{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.hbar{height:11px;border-radius:99px;background:#16223a;overflow:hidden}.hbar-fill{display:block;height:100%;border-radius:99px}
/* timeline */
.tl-list{display:flex;flex-direction:column;gap:10px;margin-top:10px}
.tl-item{display:flex;gap:10px;padding:10px;border-radius:12px;background:#0c1422;border:1px solid var(--line);border-left:4px solid var(--c)}.tl-item.unseen{box-shadow:0 0 0 1px rgba(61,220,151,.4)}
.tl-dot{font-size:18px}.tl-body{flex:1;min-width:0}.tl-head{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.tl-lines{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:2px 16px;margin:6px 0}.tl-foot{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:6px}
.tl-diff{margin:6px 0;border:1px solid var(--line);border-radius:10px;overflow:hidden}.diff-row{display:grid;grid-template-columns:minmax(120px,1.2fr) 1fr 18px 1fr;gap:8px;padding:6px 10px;font-size:12.5px;border-bottom:1px solid var(--line);align-items:center}
.diff-row:last-child{border-bottom:0}.diff-field{color:var(--tx2)}.diff-from{color:#ff9aa4;text-decoration:line-through;opacity:.85}.diff-to{color:#7be0a6;font-weight:700}.diff-arrow{color:var(--tx3)}
details.tl-group>summary,details.inc-card>summary{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.inc-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:4px 18px;margin:10px 0}.inc-alert{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:4px 0}.inc-summary{margin:6px 0}
/* analytics */
.chart-svg{width:100%;height:290px;display:block}.grid-line{stroke:#1d2a42;stroke-width:1}.axis-text{fill:#7d8fae;font-size:11px}
.bar-g rect{transition:opacity .15s}.bar-g:hover rect{opacity:.8}
.legend{display:flex;flex-wrap:wrap;gap:14px;margin-top:8px;font-size:12.5px;color:var(--tx2)}.legend-item i,.legend-row i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:6px}
.donut-wrap{display:flex;gap:18px;align-items:center;flex-wrap:wrap}.donut-svg{width:170px;height:170px;flex:none}.donut-num{fill:#fff;font-size:26px;font-weight:800}.donut-cap{fill:#8b9bb5;font-size:11px}
.donut-legend{flex:1;min-width:170px}.legend-row{display:grid;grid-template-columns:14px 1fr auto 40px;gap:6px;align-items:center;font-size:13px;margin:5px 0}
.heat-grid{display:grid;grid-template-columns:repeat(12,1fr);gap:5px}.heat-cell{min-height:46px;border-radius:8px;display:flex;flex-direction:column;align-items:center;justify-content:center;font-size:11px}.heat-cell b{font-size:13px}.heat-cell small{color:var(--tx2);font-size:10px}
.stackbar{display:flex;height:12px;border-radius:99px;overflow:hidden;background:#16223a;margin:8px 0}.chart-empty{padding:30px;text-align:center}
.an-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:16px}
#an-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:14px}
/* devices */
.dev-group{margin:14px 0}.dev-group-head{display:flex;gap:10px;align-items:center;margin-bottom:8px}.dev-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(310px,1fr));gap:12px}
.device-item{border:1px solid var(--line2);border-radius:14px;padding:12px;background:linear-gradient(160deg,#0f1828,#0b1220)}.device-item.dev-online{border-color:rgba(61,220,151,.45)}.device-item.dev-silent{opacity:.85}
.dev-top{display:flex;gap:8px;align-items:center}.dev-name{font-weight:800;flex:1}.dev-rename{flex:1}
.dev-dot{width:10px;height:10px;border-radius:50%;background:#55627a}.dev-dot.online{background:var(--good);box-shadow:0 0 0 4px rgba(61,220,151,.18)}.dev-dot.idle{background:var(--warn)}
.dev-kv{margin:8px 0;display:grid;gap:2px}
/* telegram */
.tg-layout{display:grid;grid-template-columns:minmax(260px,340px) 1fr;gap:18px;align-items:start}
.tg-add{border:1px solid var(--line2);border-radius:14px;padding:14px;background:#0c1422}
.bot-list{display:flex;flex-direction:column;gap:12px}
.bot-card{border:1px solid var(--line2);border-radius:16px;padding:14px;background:linear-gradient(160deg,#101a2c,#0b1220)}.bot-card.off{opacity:.72}
.bot-head{display:flex;align-items:center;gap:12px}.bot-avatar{width:42px;height:42px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:18px;background:linear-gradient(135deg,var(--acc),var(--acc2));color:#fff}
.bot-title{flex:1;min-width:0}.bot-info{margin:10px 0;display:grid;gap:3px}.kv.err span{color:var(--bad)}
.bot-actions{display:flex;flex-wrap:wrap;gap:8px}.bot-prefs{margin-top:10px;border-top:1px solid var(--line);padding-top:8px}.bot-prefs>summary{cursor:pointer;color:var(--acc);font-weight:700}
.pref-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:6px;margin:10px 0}.pref{display:flex;gap:6px;align-items:center}
.bot-empty{text-align:center;padding:30px;border:1px dashed var(--line2);border-radius:14px}.bot-empty .big{font-size:36px}
.switch{position:relative;width:46px;height:26px;flex:none;display:inline-block}.switch input{opacity:0;width:0;height:0;position:absolute}
.slider{position:absolute;inset:0;border-radius:99px;background:#2a3850;transition:.2s;cursor:pointer}.slider::before{content:"";position:absolute;width:20px;height:20px;left:3px;top:3px;border-radius:50%;background:#fff;transition:.2s}
.switch input:checked+.slider{background:var(--good)}.switch input:checked+.slider::before{transform:translateX(20px)}
.tg-preview{white-space:pre-wrap;background:#0c1422;border:1px solid var(--line2);border-radius:14px;padding:16px;font-size:14px;line-height:1.6;margin-top:10px}
/* control center */
.state-row{align-items:center;gap:12px}.state-row .row{gap:8px;align-items:center}
.cc-result{border:1px solid var(--line2);border-radius:12px;padding:12px;margin-top:10px;background:#0c1422}.cc-result.ok{border-left:4px solid var(--good)}.cc-result.bad{border-left:4px solid var(--bad)}.cc-result-head{display:flex;gap:10px;align-items:center;justify-content:space-between;margin-bottom:6px}
.feedback-line{margin:8px 0;min-height:20px}
/* live banner */
.live-banner{position:fixed;top:14px;left:50%;transform:translateX(-50%);z-index:95;display:flex;gap:12px;align-items:center;padding:12px 16px;border-radius:14px;background:linear-gradient(135deg,#3a1219,#2a0e14);border:1px solid var(--bad);box-shadow:0 16px 50px rgba(255,107,122,.35);max-width:min(680px,calc(100vw - 24px));animation:lbIn .3s ease}
.lb-ico{font-size:26px}.lb-text{flex:1;min-width:0}.lb-text strong{color:#ffb3bb}
@keyframes lbIn{from{transform:translate(-50%,-20px);opacity:0}to{transform:translate(-50%,0);opacity:1}}
#sound-btn.off{opacity:.6}
tr.row-new{background:rgba(61,220,151,.07)}
.skeleton{height:14px;border-radius:7px;background:linear-gradient(90deg,#14203a,#1d2c4b,#14203a);background-size:200% 100%;animation:sk 1.2s infinite;margin:8px 0}@keyframes sk{to{background-position:-200% 0}}
/* mobile */
@media(max-width:900px){
 .tg-layout{grid-template-columns:1fr}.an-grid{grid-template-columns:1fr}.diff-row{grid-template-columns:1fr 1fr}.diff-arrow{display:none}
 .hbar-row,.hbar-row.big{grid-template-columns:90px 1fr 34px}.heat-grid{grid-template-columns:repeat(6,1fr)}
 .table-wrap table,.table-wrap thead,.table-wrap tbody,.table-wrap tr,.table-wrap td{display:block;width:100%}
 .table-wrap thead{display:none}.table-wrap tr{border:1px solid var(--line);border-radius:12px;margin:10px 0;padding:8px}
 .table-wrap td{border:0!important;padding:4px 6px!important;display:flex;gap:10px;justify-content:space-between}.table-wrap td::before{content:attr(data-label);color:var(--tx3);font-size:12px;min-width:84px}
 .live-banner{top:auto;bottom:70px}
}

#an-timeline.chart,#an-domains,#an-devices,#an-hours,#an-donut,#an-origins{display:block!important;height:auto!important;min-height:0!important;overflow:visible}

.tag-editor{margin:10px 0}.tag-title{font-weight:700;margin-bottom:6px}.tag-list{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:6px}
.tag{display:inline-flex;gap:6px;align-items:center;padding:3px 4px 3px 11px;border-radius:99px;background:#16223a;border:1px solid var(--line2);font-size:12.5px}
.tag-x,.tag-tog{background:transparent!important;border:0;color:var(--tx2)!important;padding:0 6px!important;font-size:12px;border-radius:99px!important;cursor:pointer}.tag-x:hover{color:var(--bad)!important}
.tag-tog{background:rgba(61,220,151,.15)!important;color:var(--good)!important;font-weight:800}
.change-row{display:flex;gap:10px;align-items:center;padding:8px 0;border-bottom:1px solid var(--line);flex-wrap:wrap}.change-row:last-child{border-bottom:0}
.dev-row{display:flex;gap:10px;align-items:center;padding:9px 0;border-bottom:1px solid var(--line)}.dev-row:last-child{border-bottom:0}.dev-right{margin-left:auto;display:flex;gap:8px;align-items:center;flex-wrap:wrap;justify-content:flex-end}
.log-line{font-size:12px;color:var(--tx2);margin-top:6px}

</style>
</head>
<body>
<div id="action-toast" class="toast"></div><button type="button" class="sidebar-toggle" id="sidebar-toggle" aria-label="Open navigation" onclick="toggleSidebar()"><svg viewBox="0 0 24 24" fill="none"><path d="M4 6h16M4 12h16M4 18h16" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg></button><div class="app-shell"><aside class="sidebar" id="sidebar"><div class="sidebar-brand"><img src="/assets/icons/dashboard.svg" alt=""><div><strong>Sentinel</strong><div class="muted" style="font-size:11px">Security Console</div></div></div><div class="nav-label">Monitor</div><button type="button" class="nav-btn active" data-page="overview" data-nav-page="overview" onclick="showPage('overview')"><img src="/assets/icons/overview.svg" alt="">Overview</button><button type="button" class="nav-btn" data-page="analytics" data-nav-page="analytics" onclick="showPage('analytics')"><img src="/assets/icons/features.svg" alt="">Analytics</button><button type="button" class="nav-btn" data-page="devices" data-nav-page="devices" onclick="showPage('devices')"><img src="/assets/icons/project.svg" alt="">Devices</button><div class="nav-label">Security</div><button type="button" class="nav-btn" data-page="security" data-nav-page="security" onclick="showPage('security')"><img src="/assets/icons/security.svg" alt="">Security</button><button type="button" class="nav-btn" data-page="profiles" data-nav-page="profiles" onclick="showPage('profiles')"><img src="/assets/icons/config.svg" alt="">Profiles & Config</button><div class="nav-label">Operations</div><button type="button" class="nav-btn" data-page="notifications" data-nav-page="notifications" onclick="showPage('notifications')"><img src="/assets/icons/security.svg" alt="">Notifications</button><button type="button" class="nav-btn" data-page="operations" data-nav-page="operations" onclick="showPage('operations')"><img src="/assets/icons/process.svg" alt="">Control Center</button><button type="button" class="nav-btn" data-page="data" data-nav-page="data" onclick="showPage('data')"><img src="/assets/icons/storage.svg" alt="">Data & Recovery</button></aside><div class="app-content"><main>
<div class="panel hero">
<div class="hero-copy"><div class="eyebrow">Security Operations Console</div><h1>NextDNS Sentinel</h1><div class="muted">Local monitoring, alerting and profile control</div></div>
<div class="hero-badge"><span id="hero-dot" class="dot"></span><span id="hero-status">Checking monitor</span><button type="button" id="sound-btn" class="neutral mini" style="margin-top:7px" onclick="toggleSound()">🔔 Sound on</button><div id="device-info" class="device-badge" style="margin-top:7px">Detecting device…</div></div>
</div>

<div class="panel">
<div class="row"><strong>Monitor:</strong><span id="runtime" class="muted">Checking...</span></div>
<button type="button" class="start" onclick="controlMonitor('start')">Start Monitoring</button>
<button type="button" class="stop" onclick="controlMonitor('stop')">Stop Monitoring</button>
<div class="status" id="health">Loading health...</div>
</div>

<div class="panel recent-alerts-panel" id="recent-alerts-panel">
<div class="section-head recent-alerts-head"><div><h2><span class="recent-alerts-dot"></span>Recent Alerts</h2><div class="muted">Only new, unseen activity — grouped by account and labelled by who did it: you in the dashboard, someone in the NextDNS app, or a device visiting a site. Mark as seen to clear them.</div></div><div class="row"><span id="recent-alerts-count" class="pill">0 alerts</span><button type="button" class="neutral" onclick="markAllRecentAlertsSeen()">Mark all seen</button></div></div>
<div id="recent-alerts" class="recent-alerts-grid"><div class="skeleton"></div><div class="skeleton" style="width:70%"></div></div>
</div>

<div class="panel" id="ov-insights-panel"><div class="section-head"><div><h2>Insights</h2><div class="muted">Most visited blocked sites and the latest activity of each account</div></div></div><div id="ov-insights"><div class="skeleton"></div></div></div>

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
<div class="section-head"><div><h2>Telegram Alerts</h2><div class="muted">Each bot can receive different kinds of reports, with optional quiet hours.</div></div><button type="button" class="neutral" onclick="previewTelegram()">Preview a report</button></div>
<div class="status" id="telegram-status">Checking...</div>
<div class="tg-layout">
<div class="tg-add"><strong>Add a bot</strong>
<form id="telegram-form">
<label>Bot name<input name="name" placeholder="e.g. My phone"></label>
<label>Bot token<input name="token" type="password" placeholder="123456:ABC..."></label>
<label>Chat ID<input name="chat_id" placeholder="Telegram chat ID"></label>
<button class="start" type="submit">Add / Save Bot</button>
</form>
<div id="telegram-editor" class="editor hidden">
<strong>Edit Telegram Bot</strong>
<form id="telegram-edit-form">
<label>Bot name<input name="name" placeholder="Telegram Bot"></label>
<label>Bot token<input name="token" type="password" placeholder="Leave blank to keep the current token"></label>
<label>Chat ID<input name="chat_id" placeholder="Telegram chat ID"></label>
<div class="row"><button class="start" type="submit">Save changes</button><button class="neutral" type="button" onclick="closeTelegramEditor()">Cancel</button></div>
</form>
<div class="status" id="telegram-edit-message"></div>
</div>
</div>
<div class="bot-list" id="telegram-bot-card"><div class="skeleton"></div><div class="skeleton" style="width:60%"></div></div>
</div>
</div>

<div class="grid" id="stats"></div>

<div class="panel an-toolbar" id="an-toolbar"><div class="section-head"><div><h2>Analytics</h2><div class="muted" id="an-range-label">Last 24 hours · hourly · your local time</div></div><div class="row"><span id="analytics-total" class="pill">0 events</span><select id="analytics-range" onchange="loadRangeAnalytics()"><option value="12">Last 12 hours</option><option value="24" selected>Last 24 hours</option><option value="72">Last 3 days</option><option value="168">Last 7 days</option><option value="720">Last 30 days</option></select></div></div></div>
<div class="grid" id="an-kpis"></div>
<div class="analytics an-grid">
<div class="panel" style="grid-column:1/-1"><div class="section-head"><div><h2>Activity over time</h2><div class="muted">Stacked by what happened — every colour is a different kind of event</div></div></div><div id="an-timeline" class="chart"></div></div>
<div class="panel"><div class="section-head"><div><h2>What happened</h2><div class="muted">Share of each kind of event</div></div></div><div id="an-donut"></div></div>
<div class="panel"><div class="section-head"><div><h2>Who did it</h2><div class="muted">Dashboard (you), NextDNS app, device activity or system</div></div></div><div id="an-origins"></div></div>
<div class="panel"><div class="section-head"><div><h2>Top blocked sites</h2><div class="muted">Only real visits to blocked sites — settings changes are not counted here</div></div></div><div id="an-domains"></div></div>
<div class="panel"><div class="section-head"><div><h2>Denylist changes</h2><div class="muted">Domains that were added to or removed from a denylist</div></div></div><div id="an-changes"></div></div>
<div class="panel" style="grid-column:1/-1"><div class="section-head"><div><h2>Devices</h2><div class="muted">Every device seen on your profiles — updates live</div></div></div><div id="an-devices"></div></div>
<div class="panel" style="grid-column:1/-1"><div class="section-head"><div><h2>Busiest hours</h2><div class="muted">Activity by hour of day</div></div></div><div id="an-hours"></div></div>
</div>
<div class="panel"><div class="section-head"><div><h2>Per-profile analytics</h2><div class="muted">Open an account to see its breakdown, most visited blocked sites and latest events</div></div><span id="analytics-profile-count" class="pill">0 profiles</span></div><div id="analytics-profiles" class="scalable-list"><div class="skeleton"></div></div></div>
<div class="panel"><div class="section-head"><div><h2>Sentinel Health</h2><div class="muted">Storage and runtime self-check</div></div><span id="sentinel-health-pill" class="pill">Checking</span></div><div id="sentinel-health" class="mini-list"><div class="muted">Loading...</div></div></div>

<div class="panel">
<div class="section-head"><div><h2>Security Incidents</h2><div class="muted">Related alerts grouped together — with account, profile, device, domain and timing</div></div><span id="incident-count" class="pill">0</span></div>
<div id="incidents" class="mini-list"><div class="muted">Loading...</div></div>
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
<button type="button" class="neutral" onclick="loadControlCenter()">Refresh Control Center</button>
<button type="button" class="neutral" onclick="exportSettings()">Export Settings</button>
<label class="neutral" style="display:inline-flex;align-items:center;gap:6px;cursor:pointer;padding:9px 13px;margin:3px;border-radius:10px;border:1px solid #2c3d58;background:#1a2638;color:#e9eef8;font-weight:700;font-size:13px;width:auto">Import Settings<input id="settings-import" type="file" accept=".json,application/json" hidden onchange="importSettings(this)"></label>
</div>
<div id="cc-feedback" class="status feedback-line">Every button here confirms what it did, right below.</div>
<div id="control-summary" class="mini-list"><div class="muted">Loading...</div></div>
<div class="grid">
<div class="panel rule-builder"><h3>Alert Rules</h3><div class="muted">Build a rule from simple choices — no JSON needed.</div>
<label>Rule name<input id="rule-name" placeholder="e.g. Mute noisy tablet"></label>
<div class="row3"><label>When<select id="rule-type"><option value="">Any alert</option><option value="denylist_match">Blocked site visited</option><option value="configuration_action">Setting changed (dashboard)</option><option value="config_change">Setting changed (outside)</option><option value="device_inactive">Device went silent</option></select></label>
<label>On profile<select id="rule-profile"><option value="">Any profile</option></select></label>
<label>Device<select id="rule-device"><option value="">Any device</option></select></label></div>
<label>Domain (optional)<input id="rule-domain" placeholder="example.com"></label>
<div class="row3"><label>Then<select id="rule-action" onchange="syncRuleForm()"><option value="suppress">Mute notifications</option><option value="cooldown">Mute for a while after each match</option></select></label>
<label id="rule-cooldown-wrap" class="hidden">Mute for (minutes)<input id="rule-cooldown" type="number" min="1" value="10"></label></div>
<div class="row"><button type="button" class="start" onclick="saveRule()">Save Rule</button><span id="rule-msg" class="muted"></span></div>
<div id="rules-list" class="mini-list"></div></div>
<div class="panel"><h3>Maintenance Mode</h3><div class="muted">Silences notifications while you work on a profile. Alerts are still recorded.</div>
<label>Duration<select id="maintenance-preset"><option value="900">15 minutes</option><option value="3600" selected>1 hour</option><option value="14400">4 hours</option><option value="86400">24 hours</option></select></label>
<label>Reason (optional)<input id="maintenance-reason" placeholder="e.g. testing new blocklist"></label>
<div class="row"><button type="button" class="neutral" onclick="enableMaintenance()">Enable Maintenance</button></div>
<input id="maintenance-seconds" type="hidden" value="3600"><input id="suppression-fingerprint" type="hidden"><input id="suppression-seconds" type="hidden" value="600">
</div>
</div>
<div class="mini-list">
<div class="mini-item"><span><strong>Diagnostics</strong><br><span class="muted">Checks database, encryption and required tables.</span></span><button type="button" class="neutral" onclick="loadDiagnostics()">Run</button></div>
<div class="mini-item"><span><strong>Incident Metrics</strong><br><span class="muted">Shows incident counts and mean time to resolve.</span></span><button type="button" class="neutral" onclick="loadIncidentMetrics()">View</button></div>
<div class="mini-item"><span><strong>Database Cleanup</strong><br><span class="muted">Deletes old operational records and attempts SQLite VACUUM.</span></span><span class="row"><input id="retention-days" type="number" min="1" value="30" style="max-width:90px"><button type="button" class="neutral" onclick="runRetention()">Run</button></span></div>
<div class="mini-item"><span><strong>Latest Config Diff</strong><br><span class="muted">Shows the latest detected configuration difference.</span></span><button type="button" class="neutral" onclick="showConfigDiff()">View</button></div>
<div class="mini-item"><span><strong>Typical activity</strong><br><span class="muted">Shows the hours your profiles are usually busiest, learned from past activity.</span></span><button type="button" class="neutral" onclick="loadRiskBaseline()">View</button></div>
<div class="mini-item"><span><strong>Rate Limits</strong><br><span class="muted">Shows recent NextDNS API rate-limit telemetry.</span></span><button type="button" class="neutral" onclick="loadRateLimits()">View</button></div>
<div class="mini-item state-row" id="auth-row"><span><strong>API Authentication</strong><br><span class="muted" id="auth-session">Checking…</span></span><span class="row"><span id="auth-chip" class="state-chip muted">…</span><input id="api-auth-token" type="password" placeholder="Token" style="max-width:210px"><button type="button" id="auth-btn-on" class="start" onclick="configureApiAuth()">Turn ON</button><button type="button" id="auth-btn-off" class="stop" style="display:none" onclick="disableApiAuth()">Turn OFF</button><button type="button" id="auth-btn-logout" class="neutral" style="display:none" onclick="logoutApiAuth()">Log out</button></span></div>
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
<div class="section-head"><div><h2>Security Alerts & Actions</h2><div class="muted">Everything Sentinel saw — clearly labelled by what happened and who did it</div></div><span id="alerts-count" class="pill">0 shown</span></div>
<div class="row"><input id="alert-search" type="search" placeholder="Search domain, account, reason, status…" autocomplete="off"><select id="alert-type-filter" style="max-width:220px"><option value="">All events</option><option value="site">🚫 Blocked-site visits</option><option value="profile">🔧 Profile settings changes</option><option value="denylist">🛡️ Denylist changes</option><option value="device">📱 Device events</option><option value="other">⚙️ Other</option></select><select id="alert-origin-filter" style="max-width:220px" onchange="filterAlerts()"><option value="">Done by anyone</option><option value="dashboard">🖥 You · Dashboard</option><option value="app">📱 NextDNS app</option><option value="device">🌐 Device activity</option><option value="system">⚙️ System</option></select></div>
<div class="table-wrap"><table>
<thead><tr><th>Time</th><th>Account</th><th>Device</th><th>Domain</th><th>Event</th><th>Done by</th><th>Details</th><th>Notification</th><th>Seen</th></tr></thead>
<tbody id="alerts"></tbody>
</table></div>
</div>
</main>
</div>
</div>
<script>const MON3=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
function pad2(v){return String(v).padStart(2,'0');}
function parseDate(v){if(!v)return null;const d=new Date(v);return Number.isNaN(d.getTime())?null:d;}
function fmtClock(d,withSeconds){let h=d.getHours();const ap=h>=12?'PM':'AM';h=h%12||12;return h+':'+pad2(d.getMinutes())+(withSeconds?':'+pad2(d.getSeconds()):'')+' '+ap;}
function fmtDate(d){return pad2(d.getDate())+' '+MON3[d.getMonth()]+' '+d.getFullYear();}
function formatDateTime(v){const d=parseDate(v);if(!d)return v?String(v):'—';return fmtDate(d)+' · '+fmtClock(d,true);}
function formatTime(v){const d=parseDate(v);return d?fmtClock(d,false):'—';}
function relTime(v){const d=parseDate(v);if(!d)return '—';const s=Math.max(0,Math.round((Date.now()-d.getTime())/1000));if(s<10)return 'just now';if(s<60)return s+'s ago';const m=Math.floor(s/60);if(m<60)return m+' min ago';const h=Math.floor(m/60);if(h<24)return h+' h ago';return Math.floor(h/24)+' d ago';}
function humanSeconds(sec){sec=Number(sec)||0;if(sec%3600===0&&sec>=3600)return (sec/3600)+' hour'+(sec===3600?'':'s');if(sec%60===0)return (sec/60)+' minutes';return sec+' seconds';}
function el(tag,cls,text){const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined&&text!==null)e.textContent=text;return e;}
function formatTimestampCell(td,value){td.textContent=formatDateTime(value);td.title=value||'';}

function showActionToast(message,type='error'){
 let stack=document.getElementById('toast-stack');
 if(!stack){stack=el('div','');stack.id='toast-stack';document.body.append(stack);}
 const kind=(type==='ok'||type==='success')?'ok':((type==='info'||type==='muted')?'info':'error');
 const t=el('div','toast-item '+kind);
 t.append(el('span','toast-ico',kind==='ok'?'✔':(kind==='info'?'ℹ':'✖')),el('span','toast-msg',message));
 const x=el('button','toast-x','×');x.onclick=()=>t.remove();t.append(x);
 stack.append(t);while(stack.children.length>4)stack.firstChild.remove();
 setTimeout(()=>{t.classList.add('out');setTimeout(()=>t.remove(),300);},kind==='error'?6500:3800);
}

const SILENT_PATHS=[/\\/seen(-all)?$/,/^\\/api\\/pulse/];
function announce(method,path,rawBody,res){
 let b={};try{b=(rawBody&&typeof rawBody==='string')?JSON.parse(rawBody):{};}catch(e){b={};}
 const seg=path.split('?')[0];let m;
 const acct=id=>accountLabel(decodeURIComponent(id));
 let msg='';
 if(m=seg.match(/^\\/api\\/safe-mode$/))msg='Safe Mode is now '+(b.enabled?'ON — configuration changes are blocked':'OFF — configuration changes are allowed');
 else if(seg==='/api/maintenance')msg=method==='DELETE'?'Maintenance mode is now OFF — notifications are active again':'Maintenance mode is now ON for '+humanSeconds(b.seconds||3600)+' — notifications are muted';
 else if(seg==='/api/rules')msg=(b.id!==undefined&&b.enabled!==undefined&&Object.keys(b).length<=4&&b.rule)?'Rule "'+(b.name||'')+'" turned '+(b.enabled?'ON':'OFF'):'Rule "'+(b.name||'')+'" saved';
 else if(/^\\/api\\/rules\\/\\d+$/.test(seg))msg='Rule deleted';
 else if(seg==='/api/suppressions')msg='Alert suppression added';
 else if(seg==='/api/retention')msg='Old records cleaned up';
 else if(seg==='/api/denylist/bulk')msg='Bulk denylist change applied';
 else if(m=seg.match(/^\\/api\\/denylist\\/([^/]+)\\/(.+)$/))msg='Removed "'+decodeURIComponent(m[2])+'" from the denylist of '+acct(m[1]);
 else if(m=seg.match(/^\\/api\\/denylist\\/([^/]+)$/))msg=method==='DELETE'?'Denylist cleared for '+acct(m[1]):'Added "'+(b.domain||'')+'" to the denylist of '+acct(m[1]);
 else if(m=seg.match(/^\\/api\\/accounts\\/([^/]+)\\/toggle$/))msg='Monitoring for '+acct(m[1])+' is now '+(b.active?'ON':'OFF');
 else if(m=seg.match(/^\\/api\\/accounts\\/([^/]+)$/))msg=method==='DELETE'?'Profile removed from Sentinel':'Profile details saved';
 else if(seg==='/api/accounts')msg='Profile added';
 else if(m=seg.match(/^\\/api\\/monitor\\/(start|stop)$/))msg=m[1]==='start'?'Monitoring started':'Monitoring stopped';
 else if(m=seg.match(/^\\/api\\/settings\\/telegram\\/bots\\/(\\d+)\\/enable$/))msg='Telegram bot is now '+(b.enabled?'ENABLED':'DISABLED');
 else if(/^\\/api\\/settings\\/telegram\\/bots\\/\\d+\\/test$/.test(seg))msg='Test message sent to Telegram';
 else if(/^\\/api\\/settings\\/telegram\\/bots\\/\\d+\\/check$/.test(seg))msg='Bot connection checked — it is working';
 else if(/^\\/api\\/settings\\/telegram\\/bots\\/\\d+\\/prefs$/.test(seg))msg='Bot preferences saved';
 else if(/^\\/api\\/settings\\/telegram\\/bots\\/\\d+$/.test(seg))msg='Telegram bot deleted';
 else if(seg==='/api/settings/telegram/bots')msg='Telegram bot saved';
 else if(/^\\/api\\/settings\\/telegram/.test(seg))msg='Telegram settings updated';
 else if(/^\\/api\\/config-changes\\/\\d+\\/undo$/.test(seg))msg='Change undone and verified on the live profile';
 else if(m=seg.match(/^\\/api\\/profiles\\/([^/]+)\\/config/))msg='Settings applied to '+acct(m[1]);
 else if(m=seg.match(/^\\/api\\/incidents\\/(\\d+)\\/status$/))msg='Incident #'+m[1]+' set to '+String(b.status||'').toUpperCase();
 else if(/^\\/api\\/devices\\//.test(seg))msg='Device updated';
 else if(seg==='/api/settings/import')msg='Settings imported';
 else if(/^\\/api\\/alert-log/.test(seg)||/save-alert/.test(seg))msg='Alert log setting saved';
 else msg='Done';
 showActionToast(msg,'ok');
 const fb=document.getElementById('cc-feedback');
 if(fb){fb.textContent='✔ '+msg+' · '+fmtClock(new Date(),true);fb.className='status ok feedback-line';}
}

async function api(path,options={}){
 const method=String(options.method||'GET').toUpperCase();
 try{
  const headers={...(options.headers||{})};
  if(!(options.body instanceof FormData))headers['Content-Type']=headers['Content-Type']||'application/json';
  const r=await fetch(path,{...options,headers});
  const d=await r.json().catch(()=>({}));
  if(r.status===401){if(!window.__authReload){window.__authReload=true;clearInterval(window.__sentinelRefreshTimer);showActionToast('Please log in again…','info');setTimeout(()=>location.reload(),500);}return new Promise(()=>{});}
  if(!r.ok)throw new Error(d.error||'HTTP '+r.status);
  if(method!=='GET'){
   if(!options._skipAutoRefresh)scheduleAutoRefresh();
   if(!options._silent && !SILENT_PATHS.some(re=>re.test(path)))announce(method,path,options.body,d);
  }
  return d;
 }catch(e){
  const error=e instanceof TypeError?new Error('Dashboard could not reach the local API. Make sure Sentinel is running and try again.'):e;
  if(!options._quiet)showActionToast(error.message,'error');
  throw error;
 }
}

const CAT={site:{label:'Blocked site',icon:'🚫',color:'#ff6b7a'},profile:{label:'Settings',icon:'🔧',color:'#f5c451'},denylist:{label:'Denylist',icon:'🛡️',color:'#a78bfa'},device:{label:'Device',icon:'📱',color:'#5ad1e6'},other:{label:'Other',icon:'⚙️',color:'#8b9bb5'}};
const ORIGIN={dashboard:{label:'You · Dashboard',icon:'🖥',cls:'o-dash',color:'#4f9dff'},app:{label:'NextDNS app',icon:'📱',cls:'o-app',color:'#3ddc97'},device:{label:'Device activity',icon:'🌐',cls:'o-dev',color:'#ff9f6b'},system:{label:'System',icon:'⚙️',cls:'o-sys',color:'#8b9bb5'}};
function originBadge(key){const o=ORIGIN[key]||ORIGIN.system;return el('span','origin-badge '+o.cls,o.icon+' '+o.label);}
function catBadge(cat){const c=CAT[cat]||CAT.other;const b=el('span','cat-badge',c.icon+' '+c.label);b.style.setProperty('--c',c.color);return b;}
function alertTitle(x){if(x.category==='denylist')return x.status==='denylist_removed'?'Denylist entry removed':'Denylist entry added';return {site:'Blocked site visited',profile:'Profile settings changed',device:'Device went silent',other:'Event'}[x.category]||'Event';}
const TYPE_TO_CAT={denylist_match:'site',config_change:'profile',config_changed:'profile',configuration_action:'profile',configuration_undo:'profile',denylist_added:'denylist',denylist_removed:'denylist',device_inactive:'device',device_new:'device'};
function typeBadge(type){return catBadge(TYPE_TO_CAT[type]||'other');}
let __accountNameMap={};
function accountLabel(id){return __accountNameMap[id]||id||'System';}
function profileLabel(id){const a=(window.__accounts||[]).find(x=>x.profile_id===id);return a?(a.profile_name||''):'';}
function byTimeDesc(a,b){return String(b.event_timestamp||b.created_at||b.time||'').localeCompare(String(a.event_timestamp||a.created_at||a.time||''));}
function notifChip(st,x){
 const map={sent:['Sent','ok'],pending:['Waiting to send','warn'],failed:['Failed — retrying','bad'],suppressed:['Grouped (cooldown)','muted'],stale:['Waiting to send','warn']};
 let [t,c]=map[st]||[st||'—','muted'];let title='';
 if(x&&st==='sent'&&x.notified_at){const ev=parseDate(x.event_timestamp||x.created_at),nt=parseDate(x.notified_at);if(ev&&nt&&(nt-ev)>120000){t='Sent late';c='warn';title='This happened '+relTime(x.event_timestamp||x.created_at)+' but was delivered at '+formatDateTime(x.notified_at)+' (Sentinel or the bot was offline).';}}
 const chip=el('span','state-chip '+c,t);if(title)chip.title=title;return chip;
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
  const ls=item.log_stat||{};const logLine=document.createElement('div');logLine.className='log-line';logLine.textContent=ls.polled_at?('Last check: '+(ls.count||0)+' DNS log entries received'+(ls.newest?' · newest '+relTime(ls.newest):'')):'Waiting for the first log check…';
  card.append(name,status,poll,failures,err,logLine);box.append(card);
 }
}
const TYPE_LABELS={denylist_match:['Blocked site visited','site'],denylist_added:['Denylist added','cfg'],denylist_removed:['Denylist removed','cfg'],config_change:['Profile settings changed','cfg'],config_changed:['Profile settings changed','cfg'],configuration_action:['Settings changed (dashboard)','cfg'],configuration_undo:['Change undone','cfg'],device_inactive:['Device inactive','dev'],device_new:['New device','dev']};



function closeDetailModal(){const m=document.getElementById('detail-modal');if(m)m.remove();}
function openDetailModal(title,headers,rows,note){
 closeDetailModal();
 const back=document.createElement('div');back.id='detail-modal';back.className='modal-back';back.onclick=e=>{if(e.target===back)closeDetailModal();};
 const box=document.createElement('div');box.className='modal-box';
 const head=document.createElement('header');const h=document.createElement('strong');h.textContent=title;const x=document.createElement('button');x.className='neutral';x.textContent='Close';x.onclick=closeDetailModal;head.append(h,x);
 const body=document.createElement('div');body.className='modal-body';
 if(note){const n=document.createElement('div');n.className='muted';n.style.marginBottom='8px';n.textContent=note;body.append(n);}
 if(!rows.length){const e=document.createElement('div');e.className='muted';e.textContent='Nothing to show yet.';body.append(e);}
 else{const t=document.createElement('table');const th=document.createElement('thead');const hr=document.createElement('tr');headers.forEach(k=>{const c=document.createElement('th');c.textContent=k;hr.append(c);});th.append(hr);t.append(th);const tb=document.createElement('tbody');
  for(const r of rows){const tr=document.createElement('tr');r.forEach(v=>{const td=document.createElement('td');if(v instanceof Node)td.append(v);else td.textContent=v==null||v===''?'—':v;tr.append(td);});tb.append(tr);}
  t.append(tb);const w=document.createElement('div');w.className='table-wrap';w.style.maxHeight='none';w.append(t);body.append(w);}
 box.append(head,body);back.append(box);document.body.append(back);
}


const transientStatusIds=new Set(['account-message','profile-edit-message','bulk-result','config-status','telegram-edit-message','alert-log-status']);
function setText(id,text,cls=''){
 const e=document.getElementById(id);if(!e)return;
 e.textContent=text;e.className=cls;
 if(transientStatusIds.has(id)){
  window.__statusTimers=window.__statusTimers||{};
  clearTimeout(window.__statusTimers[id]);
  if(text)window.__statusTimers[id]=setTimeout(()=>{e.textContent='';e.className='';},5000);
 }
}

let autoRefreshTimer=null;

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
   let before={},after={};try{before=JSON.parse(x.before_json||'{}');after=JSON.parse(x.after_json||'{}');const unwrap=o=>(o&&Object.keys(o).length===1&&o.data&&typeof o.data==='object')?o.data:o;before=unwrap(before);after=unwrap(after);}catch(e){}
   const diffs=configChangeDiff(before,after);
   if(!diffs.length){const empty=document.createElement('div');empty.className='muted';empty.textContent='No field-level difference recorded.';body.append(empty);}
   for(const diff of diffs.slice(0,100)){
    body.append(diffRowEl(diff));
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
function buildConfigControl(value,path,label,parent){
 if(value&&typeof value==='object'&&!Array.isArray(value)){
  const details=document.createElement('details');details.open=true;details.style.margin='6px 0';const summary=document.createElement('summary');summary.style.cursor='pointer';summary.textContent=configLabel(label);details.append(summary);
  for(const [key,val] of Object.entries(value))buildConfigControl(val,path.concat(key),key,details);parent.append(details);return;
 }
 if(Array.isArray(value)){buildArrayControl(value,path,label,parent);return;}
 const row=document.createElement('label');row.style.margin='6px 0';row.textContent=configLabel(label);
 if(Array.isArray(value)){const input=document.createElement('textarea');input.rows=Math.min(8,Math.max(2,value.length+1));input.dataset.path=JSON.stringify(path);input.dataset.kind='array-json';input.value=JSON.stringify(value,null,2);input.style.width='100%';row.append(input);}
 else{const input=document.createElement('input');input.dataset.path=JSON.stringify(path);if(typeof value==='boolean'){input.type='checkbox';input.checked=value;input.dataset.kind='boolean';}else if(typeof value==='number'){input.type='number';input.step=Number.isInteger(value)?'1':'any';input.value=String(value);input.dataset.kind='number';}else{input.type='text';input.value=value==null?'':String(value);input.dataset.kind='string';}row.append(input);}
 parent.append(row);
}
function renderConfigForm(value){const box=document.getElementById('config-form');box.replaceChildren();configFormSource=JSON.parse(JSON.stringify(value||{}));if(!value||typeof value!=='object'){box.textContent='No editable configuration was returned.';return;}for(const [key,val] of Object.entries(value))buildConfigControl(val,[key],key,box);}
function setConfigPath(target,path,value){let node=target;for(let i=0;i<path.length-1;i++){const k=path[i];if(node[k]===null||typeof node[k]!=='object')node[k]={};node=node[k];}node[path[path.length-1]]=value;}
function collectConfigForm(){const result=JSON.parse(JSON.stringify(configFormSource||{}));document.querySelectorAll('#config-form [data-path]').forEach(input=>{const path=JSON.parse(input.dataset.path);let value;if(input.dataset.kind==='boolean')value=!!input.checked;else if(input.dataset.kind==='number')value=input.value===''?null:Number(input.value);else if(input.dataset.kind==='array-json'){try{value=JSON.parse(input.value||'[]');}catch(e){throw new Error('Invalid array JSON for '+path.join('.'));}}else value=input.value;setConfigPath(result,path,value);});return result;}
function flattenConfig(o,prefix,out){out=out||{};prefix=prefix||'';if(o&&typeof o==='object'&&!Array.isArray(o)){for(const [k,v] of Object.entries(o))flattenConfig(v,prefix?prefix+' › '+configLabel(k):configLabel(k),out);}else out[prefix||'Value']=humanValue(o);return out;}
function configDiffRows(before,after){const a=flattenConfig(before),b=flattenConfig(after);const rows=[];for(const k of new Set([...Object.keys(a),...Object.keys(b)])){if(a[k]!==b[k])rows.push([k,a[k]===undefined?'—':a[k],b[k]===undefined?'—':b[k]]);}return rows;}
function updateConfigDirty(){
 let n=0;try{n=configDiffRows(configFormSource||{},collectConfigForm()).length;}catch(e){}
 let tag=document.getElementById('config-dirty');
 if(!tag){tag=document.createElement('span');tag.id='config-dirty';tag.className='dirty-tag';const st=document.getElementById('config-status');if(st)st.parentNode.insertBefore(tag,st);}
 tag.textContent=n?('● '+n+' unsaved change'+(n>1?'s':'')):'';tag.style.display=n?'inline-block':'none';
 document.querySelectorAll('#config-form [data-path]').forEach(inp=>{let changed=false;try{const path=JSON.parse(inp.dataset.path);let ref=configFormSource;for(const k of path)ref=ref==null?undefined:ref[k];let cur=inp.dataset.kind==='boolean'?inp.checked:(inp.dataset.kind==='number'?(inp.value===''?null:Number(inp.value)):inp.value);changed=inp.dataset.kind==='array-json'?false:JSON.stringify(ref)!==JSON.stringify(cur);}catch(e){}inp.closest('label')?.classList.toggle('changed',changed);});
}
document.addEventListener('input',e=>{if(e.target.closest&&e.target.closest('#config-form'))updateConfigDirty();});
document.addEventListener('change',e=>{if(e.target.closest&&e.target.closest('#config-form'))updateConfigDirty();});
function confirmConfigDiff(before,after,title){
 return new Promise(resolve=>{
  const rows=configDiffRows(before,after);
  openDetailModal(title||'Review changes before applying',['Setting','Current','New'],rows.map(r=>[r[0],r[1],r[2]]),'These changes will be sent to the selected NextDNS profile only. You can undo them later from Configuration Changes.');
  const box=document.querySelector('#detail-modal .modal-box');const head=box.querySelector('header');const closeBtn=head.querySelector('button');
  const ok=document.createElement('button');ok.className='start';ok.textContent='Apply '+rows.length+' change'+(rows.length===1?'':'s');
  let done=false;const finish=v=>{if(done)return;done=true;closeDetailModal();resolve(v);};
  ok.onclick=()=>finish(true);closeBtn.textContent='Cancel';closeBtn.onclick=()=>finish(false);head.insertBefore(ok,closeBtn);
  document.getElementById('detail-modal').addEventListener('click',e=>{if(e.target.id==='detail-modal')finish(false);});
 });
}

async function loadConfigSection(){const id=document.getElementById('config-profile').value;const section=document.getElementById('config-section').value;if(!id)return;try{const d=await api('/api/profiles/'+encodeURIComponent(id)+'/config/'+encodeURIComponent(section));renderConfigForm(d);renderConfigReadable(d);setText('config-status','Live configuration loaded. Edit the fields below and apply when ready.','ok');updateConfigDirty();}catch(e){setText('config-status','Load failed: '+e.message,'error');}}
async function saveConfigSection(){const id=document.getElementById('config-profile').value;const section=document.getElementById('config-section').value;let data;try{data=collectConfigForm();}catch(e){setText('config-status',e.message,'error');return;}try{const preview=await api('/api/profiles/'+encodeURIComponent(id)+'/config/'+encodeURIComponent(section),{method:'PATCH',body:JSON.stringify(Object.assign({},data,{_preview:true}))});const changed=preview.changed_fields||[];if(!changed.length){setText('config-status','No changes detected. Nothing will be sent to NextDNS.','muted');return;}if(!(await confirmConfigDiff(configFormSource,data)))return;await api('/api/profiles/'+encodeURIComponent(id)+'/config/'+encodeURIComponent(section),{method:'PATCH',body:JSON.stringify(data)});setText('config-status','Change applied successfully and verified against the live profile.','ok');await refresh();await loadConfigChanges();await loadConfigSection();}catch(e){setText('config-status','Change failed: '+e.message,'error');}}

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
  overview:['stats','health','recent-alerts-panel','ov-insights-panel','profile-health','event-timeline','hero-dot','runtime'],
  analytics:['an-toolbar','an-kpis','an-timeline','an-donut','an-domains','an-changes','an-devices','analytics-profiles','sentinel-health'],
  devices:['device-activity','device-editor'],
  security:['incidents','global-search','operations-center','alerts','alert-search','alert-type-filter'],
  profiles:['account-form','accounts','profile-editor','config-changes','config-profile','config-readable','config-form','config-section','deny-profile','deny-domain','denylist'],
  notifications:['telegram-form','telegram-status','telegram-bot-card','telegram-editor'],
  operations:['control-summary','cc-feedback','rules-list','maintenance-preset','control-details','api-auth-token'],
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
  for(const k in __sig)delete __sig[k];
  refresh();
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
  ['initial refresh',()=>{api('/api/pulse').then(p=>{window.__lastPulse=JSON.stringify(p);}).catch(()=>{});return refresh();}]
 ];
 for(const [name,fn] of steps){
  try{fn();}
  catch(error){console.error('Dashboard boot step failed:',name,error);showDashboardError(name+': '+dashboardErrorMessage(error));}
 }
 try{window.addEventListener('resize',detectDevice);}catch(error){console.error(error);}
 if(window.__sentinelRefreshTimer)clearInterval(window.__sentinelRefreshTimer);
 installEngagementTracking();
 window.__sentinelRefreshTimer=setInterval(()=>{pulseTick().catch(error=>console.error('Pulse failed:',error));},3000);
}
window.__lastInput=0;window.__dirtyUntil=0;window.__lastPulse='';
function installEngagementTracking(){
 if(window.__engagementInstalled)return;window.__engagementInstalled=true;
 ['pointerdown','keydown'].forEach(ev=>document.addEventListener(ev,()=>{window.__lastInput=Date.now();},true));
 document.addEventListener('input',e=>{if(e.target&&e.target.closest&&e.target.closest('form,#config-form,.rule-builder,.bot-card-editor'))window.__dirtyUntil=Date.now()+60000;},true);
}
function userEngaged(){
 if(document.getElementById('detail-modal'))return true;
 const a=document.activeElement;
 if(a&&a!==document.body&&/^(INPUT|TEXTAREA)$/.test(a.tagName)&&a.closest('main,.app-content')&&(a.value||'').length>0&&Date.now()<window.__dirtyUntil)return true;
 if(Date.now()<window.__dirtyUntil&&a&&a!==document.body&&/^(INPUT|SELECT|TEXTAREA)$/.test(a.tagName))return true;
 return false;
}

function captureOpenState(){
 const keys=[];document.querySelectorAll('main details[open]').forEach(d=>{const host=d.closest('[id]');const sum=d.querySelector('summary');keys.push(d.dataset.key||((host?host.id:'')+'|'+(sum?sum.textContent.replace(/[0-9]+/g,'#').split(' · ')[0]:'')));});
 const scroll={};document.querySelectorAll('[id]').forEach(el=>{if(el.scrollTop>0&&el.scrollHeight>el.clientHeight)scroll[el.id]=el.scrollTop;});
 return {keys,scroll,x:window.scrollX,y:window.scrollY};
}
function restoreOpenState(state){
 if(!state)return;
 document.querySelectorAll('main details').forEach(d=>{const host=d.closest('[id]');const sum=d.querySelector('summary');const key=d.dataset.key||((host?host.id:'')+'|'+(sum?sum.textContent.replace(/[0-9]+/g,'#').split(' · ')[0]:''));if(state.keys.includes(key))d.open=true;});
 for(const [id,top] of Object.entries(state.scroll)){const el=document.getElementById(id);if(el)el.scrollTop=top;}
 window.scrollTo(state.x,state.y);
}
async function lightRefresh(){
 try{const s=await api('/api/stats');const rt=await api('/api/runtime');setText('runtime',rt.running?'Running':'Stopped',rt.running?'ok':'muted');
  const health=document.getElementById('health');if(health){health.className='status '+(s.last_error?'error':'ok');health.textContent=s.last_error?'Monitor error: '+s.last_error+' · '+formatDateTime(s.last_error_at):'Monitor healthy · Last successful poll: '+formatDateTime(s.last_success_at);}
 }catch(e){}
}

window.addEventListener('error',event=>{
 const message=event?.error?.message||event?.message;
 if(message)showDashboardError(message);
});
window.addEventListener('unhandledrejection',event=>{
 const message=event?.reason?.message||String(event?.reason||'Unknown promise rejection');
 showDashboardError(message);
});


async function runRetention(){const days=Math.max(1,Number(document.getElementById('retention-days').value)||30);if(!confirm('Clean Sentinel data older than '+days+' days?'))return;try{const d=await api('/api/retention',{method:'POST',body:JSON.stringify({days})});setText('control-details','Retention cleanup removed '+d.deleted+' records.','ok');await refresh();await loadControlCenter();}catch(e){setText('control-details',e.message,'error')}}




function syncRuleForm(){const a=document.getElementById('rule-action').value;document.getElementById('rule-cooldown-wrap').classList.toggle('hidden',a!=='cooldown');}
async function fillRuleSelects(){
 const prof=document.getElementById('rule-profile'),dev=document.getElementById('rule-device');if(!prof||!dev||document.activeElement===prof||document.activeElement===dev)return;
 try{const [acc,devs]=await Promise.all([api('/api/accounts'),api('/api/devices')]);
  const pv=prof.value,dv=dev.value;
  prof.replaceChildren(new Option('Any profile',''));acc.forEach(a=>prof.append(new Option(a.name+' ('+a.profile_id+')',a.profile_id)));
  dev.replaceChildren(new Option('Any device',''));devs.forEach(d=>dev.append(new Option((d.device_name||d.device_id)+' · '+d.account_name,d.device_id)));
  prof.value=pv;dev.value=dv;}catch(e){}
}
function describeRule(r){
 const m=r.rule||{};const A={suppress:'Mute notifications',ignore:'Mute notifications'};
 const T={denylist_match:'a blocked site is visited',configuration_action:'a setting is changed from the dashboard',config_change:'a setting is changed outside Sentinel',device_inactive:'a device goes silent'};
 let act=m.cooldown_seconds?('Mute for '+Math.round(m.cooldown_seconds/60)+' min after each match'):(A[m.action]||'Record only');
 const parts=[T[m.alert_type]?('when '+T[m.alert_type]):'on any alert'];
 if(m.profile_id)parts.push('on profile '+accountLabel(m.profile_id));
 if(m.device_id)parts.push('from device '+m.device_id);
 if(m.domain)parts.push('for '+m.domain);
 return act+' — '+parts.join(' ');
}
function renderRulesList(rules){
 const rl=document.getElementById('rules-list');rl.replaceChildren();
 if(!rules.length){const e=document.createElement('div');e.className='muted';e.textContent='No rules yet. Rules decide which alerts are muted.';rl.append(e);return;}
 for(const r of rules){
  const x=document.createElement('div');x.className='mini-item';
  const left=document.createElement('span');const t=document.createElement('strong');t.textContent=r.name;const sm=document.createElement('div');sm.className='muted';sm.textContent=describeRule(r);left.append(t,sm);
  const right=document.createElement('span');right.className='actions';
  const tog=document.createElement('button');tog.type='button';tog.className=r.enabled?'neutral':'start';tog.textContent=r.enabled?'Turn off':'Turn on';
  tog.onclick=async()=>{await api('/api/rules',{method:'POST',body:JSON.stringify({id:r.id,name:r.name,rule:r.rule,enabled:!r.enabled})});await loadControlCenter();};
  const del=document.createElement('button');del.type='button';del.className='stop';del.textContent='Delete';
  del.onclick=async()=>{await api('/api/rules/'+r.id,{method:'DELETE'});await loadControlCenter();};
  right.append(tog,del);x.append(left,right);rl.append(x);
 }
}
async function saveRule(){
 const name=document.getElementById('rule-name').value.trim();const msg=document.getElementById('rule-msg');
 if(!name){msg.textContent='Give the rule a name first.';msg.className='error';return;}
 const rule={};const v=id=>document.getElementById(id).value.trim();
 if(v('rule-type'))rule.alert_type=v('rule-type');if(v('rule-profile'))rule.profile_id=v('rule-profile');if(v('rule-device'))rule.device_id=v('rule-device');if(v('rule-domain'))rule.domain=v('rule-domain').toLowerCase();
 const a=v('rule-action');if(a==='cooldown'){rule.action='suppress';rule.cooldown_seconds=Math.max(60,Number(v('rule-cooldown')||10)*60);}else rule.action=a;
 if(!rule.alert_type&&!rule.profile_id&&!rule.device_id&&!rule.domain&&a==='suppress'&&!confirm('This rule has no conditions and will mute EVERY alert. Continue?'))return;
 try{await api('/api/rules',{method:'POST',body:JSON.stringify({name,rule,enabled:true})});['rule-name','rule-domain'].forEach(i=>document.getElementById(i).value='');msg.textContent='Rule saved.';msg.className='ok';window.__dirtyUntil=0;await loadControlCenter();}
 catch(e){msg.textContent='Could not save: '+e.message;msg.className='error';}
}
async function enableMaintenance(){
 const seconds=Math.max(60,Number(document.getElementById('maintenance-preset').value)||3600);const reason=document.getElementById('maintenance-reason').value.trim();
 await api('/api/maintenance',{method:'POST',body:JSON.stringify({scope:'global',seconds,reason})});loadControlCenter();
}
async function addSuppression(){
 const fingerprint=document.getElementById('suppression-fingerprint').value.trim();const seconds=Math.max(30,Number(document.getElementById('suppression-seconds').value)||600);
 if(!fingerprint)return alert('Fingerprint is required.');
 await api('/api/suppressions',{method:'POST',body:JSON.stringify({fingerprint,seconds,reason:'Dashboard suppression'})});loadControlCenter();
}




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





function renderIncidentSummary(items){
 const box=document.getElementById('incidents');if(!box)return;box.replaceChildren();setText('incident-count',items.length+' incidents','');
 if(!items.length){box.textContent='No correlated incidents yet. New correlated alerts will appear here.';return;}
 for(const x of items){const row=document.createElement('div');row.className='mini-item';row.style.cursor='pointer';row.onclick=()=>loadIncidentDetail(x.id);row.innerHTML='<span></span><strong></strong>';row.firstChild.textContent='#'+x.id+' · '+x.title+' · '+String(x.status||'open').toUpperCase();row.lastChild.textContent=String(x.risk_score||0)+'/100 · '+(x.alert_count||0)+' alert(s) · '+formatDateTime(x.updated_at);box.append(row);}
}

function closeDeviceDetail(){document.getElementById('device-detail-panel')?.classList.add('hidden');}

async function checkTelegramBot(id){try{const d=await api('/api/settings/telegram/bots/'+id+'/check',{method:'POST'});setText('telegram-status','Active · @'+(d.bot_username||'bot')+' · '+(d.chat_title||'chat'),'ok');await refresh();}catch(e){setText('telegram-status','Telegram check failed: '+e.message,'error');await refresh();}}

async function clearProfileDenylistFromEditor(){
 if(!editingProfileId)return;
 if(!confirm('Remove every denylist entry from this profile? This affects only the selected profile.'))return;
 try{const d=await api('/api/denylist/'+encodeURIComponent(editingProfileId),{method:'DELETE'});setText('profile-edit-message','Cleared '+(d.removed||0)+' denylist entries.','ok');await refresh();}catch(e){setText('profile-edit-message','Clear denylist failed: '+e.message,'error');}
}



function configLabel(label){const raw=String(label??'').replace(/([a-z])([A-Z])/g,'$1 $2').replace(/[_-]+/g,' ').trim();return raw?raw.charAt(0).toUpperCase()+raw.slice(1):'Value';}





/* ---------- Recent alerts (only NEW ones; "Mark all seen" clears them) ---------- */
async function markSeen(ids,profileId){
 try{await api('/api/alerts/seen-all',{method:'POST',body:JSON.stringify(ids&&ids.length?{ids}:(profileId?{profile_id:profileId}:{})),_silent:true});}catch(e){return;}
 (window.__recentAlertsCache||[]).forEach(x=>{if(!ids||!ids.length||ids.includes(x.id)){if(!profileId||x.profile_id===profileId)x.seen_at=x.seen_at||new Date().toISOString();}});
 renderRecentAlerts(window.__recentAlertsCache||[]);
 showActionToast(ids&&ids.length===1?'Alert marked as seen.':'Marked as seen — they are removed from Recent Alerts and kept in the alert log.','ok');
 scheduleAutoRefresh();
}
async function markAllRecentAlertsSeen(){const n=(window.__recentAlertsCache||[]).filter(x=>!x.seen_at).length;if(!n){showActionToast('Nothing new to mark.','info');return;}await markSeen([],'');}
async function markRecentAccountSeen(profileId,ids){await markSeen(ids,profileId);}
function alertLines(x){
 const out=[];
 if(x.category==='site'){out.push(['Device',[x.device_name||x.device_id||'Unidentified device',x.device_model?'('+x.device_model+')':''].join(' ')]);if(x.client_ip)out.push(['IP',x.client_ip]);}
 else if(x.category==='device'){out.push(['Device',x.device_name||x.device_id||'—']);}
 else if(x.reason){out.push(['Details',x.reason]);}
 return out;
}
function recentItem(x){
 const row=el('div','recent-item cat-'+x.category);row.style.setProperty('--c',(CAT[x.category]||CAT.other).color);
 row.append(el('div','recent-ico',(CAT[x.category]||CAT.other).icon));
 const main=el('div','recent-main');
 const head=el('div','recent-title');head.append(el('strong','',alertTitle(x)));if(x.domain)head.append(el('span','recent-domain',x.domain));head.append(el('span','pill new-pill','NEW'));
 main.append(head);
 const meta=el('div','recent-meta');
 for(const [k,v] of alertLines(x)){const s=el('span','kv');s.append(el('em','',k+': '),document.createTextNode(v));meta.append(s);}
 main.append(meta);
 const foot=el('div','recent-foot');foot.append(originBadge(x.origin),notifChip(x.notification_status,x));
 const tm=el('span','muted',formatDateTime(x.event_timestamp||x.created_at)+' · '+relTime(x.event_timestamp||x.created_at));foot.append(tm);main.append(foot);
 const ok=el('button','neutral mini','✓ Seen');ok.title='Mark this alert as seen';ok.onclick=()=>markSeen([x.id],'');
 row.append(main,ok);return row;
}
function renderRecentAlerts(alerts){
 const box=document.getElementById('recent-alerts');if(!box)return;
 const unseen=(Array.isArray(alerts)?alerts:[]).filter(x=>!x.seen_at).sort(byTimeDesc);
 setText('recent-alerts-count',unseen.length?unseen.length+' new':'All caught up','');
 const btn=document.querySelector('#recent-alerts-panel .section-head button');if(btn)btn.style.display=unseen.length?'':'none';
 box.replaceChildren();
 if(!unseen.length){const e=el('div','recent-alert-empty');e.append(el('div','big','✓'),el('div','','You are all caught up — no new alerts.'),el('div','muted','Everything you marked as seen stays in Security → Alerts.'));box.append(e);return;}
 const groups=new Map();for(const a of unseen){const k=a.profile_id||'__none__';if(!groups.has(k))groups.set(k,[]);groups.get(k).push(a);}
 for(const [pid,items] of groups){
  const card=el('section','recent-account unseen');
  const head=el('div','recent-account-head');const t=el('div','');
  t.append(el('strong','',items[0].account_name||pid||'Unassigned'));
  t.append(el('div','muted',(items[0].profile_name?items[0].profile_name+' · ':'')+(pid!=='__none__'?pid:'')));
  const right=el('div','recent-actions');
  const cnt=new Map();items.forEach(x=>cnt.set(x.category,(cnt.get(x.category)||0)+1));
  const chips=el('div','chips');cnt.forEach((n,c)=>{const b=catBadge(c);b.append(' · '+n);chips.append(b);});
  const oc=new Map();items.forEach(x=>oc.set(x.origin,(oc.get(x.origin)||0)+1));
  oc.forEach((n,o)=>{const b=originBadge(o);b.append(' · '+n);chips.append(b);});
  const mark=el('button','neutral','Mark all seen');mark.onclick=()=>markSeen(items.map(x=>x.id),pid==='__none__'?'':pid);
  right.append(mark);head.append(t,right);card.append(head,chips);
  const list=el('div','recent-list');items.slice(0,8).forEach(x=>list.append(recentItem(x)));
  if(items.length>8)list.append(el('div','muted','+ '+(items.length-8)+' more — see Security → Alerts'));
  card.append(list);box.append(card);
 }
}

/* ---------- Alerts table (Security page) ---------- */
function renderAlertsTable(alerts){
 const body=document.getElementById('alerts');if(!body)return;body.replaceChildren();
 for(const x of alerts){
  const tr=document.createElement('tr');tr.dataset.alertType=x.alert_type||'';tr.dataset.alertCategory=x.category||'';tr.dataset.origin=x.origin||'';
  if(!x.seen_at)tr.className='row-new';
  const cell=(label,content)=>{const td=document.createElement('td');td.dataset.label=label;if(content instanceof Node)td.append(content);else td.textContent=content??'—';tr.append(td);return td;};
  const when=el('div','');const wd=parseDate(x.event_timestamp||x.created_at);when.append(el('strong','',wd?fmtClock(wd,true):'—'),el('div','muted small',(wd?fmtDate(wd)+' · ':'')+relTime(x.event_timestamp||x.created_at)));when.style.whiteSpace='nowrap';cell('Time',when);
  const acc=el('div','');acc.append(el('strong','',x.account_name||'—'),el('div','muted small',(x.profile_name||'')+(x.profile_id?' · '+x.profile_id:'')));cell('Account',acc);
  cell('Device',x.device_name||x.device_id||'—');
  cell('Domain',x.domain||'—');
  cell('Event',catBadge(x.category));
  cell('Done by',originBadge(x.origin));
  cell('Details',x.reason||'—');
  cell('Notification',notifChip(x.notification_status,x));
  const td=document.createElement('td');td.dataset.label='Seen';
  if(x.seen_at){td.append(el('span','muted','✓ Seen'));}else{const b=el('button','neutral mini','Mark seen');b.onclick=()=>markSeen([x.id],'');td.append(b);}
  tr.append(td);body.append(tr);
 }
 filterAlerts();
}
function filterAlerts(){
 const q=(document.getElementById('alert-search')?.value||'').toLowerCase().trim();
 const cat=(document.getElementById('alert-type-filter')?.value||'').toLowerCase();
 const org=(document.getElementById('alert-origin-filter')?.value||'').toLowerCase();
 let shown=0;
 document.querySelectorAll('#alerts tr').forEach(row=>{
  const ok=(!q||row.textContent.toLowerCase().includes(q))&&(!cat||row.dataset.alertCategory===cat)&&(!org||row.dataset.origin===org);
  row.style.display=ok?'':'none';if(ok)shown++;
 });
 setText('alerts-count',shown+' shown','');
}

/* ---------- Overview stat cards ---------- */
function renderStats(s){
 const stats=document.getElementById('stats');stats.replaceChildren();
 const per=s.per_account||[];const alerts=window.__recentAlertsCache||[];
 const newCount=alerts.filter(x=>!x.seen_at).length;
 const cards=[
  {k:'profiles',label:'Monitored Profiles',value:s.accounts,color:'#4f9dff',sub:per.map(a=>a.name)},
  {k:'active',label:'Active Profiles',value:s.active_accounts,color:'#3ddc97',sub:per.map(a=>a.name+(a.active?' ✓':' ✕'))},
  {k:'alerts',label:'Alerts Total',value:s.alerts,color:'#ff6b7a',sub:[newCount+' new',alerts.filter(x=>x.category==='site').length+' blocked-site visits'],spark:true},
  {k:'denylist',label:'Denylist Entries',value:s.denylist_entries,color:'#a78bfa',sub:per.map(a=>a.name+' · '+a.denylist)},
  {k:'poll',label:'Poll Interval',value:s.poll_interval_seconds+'s',color:'#5ad1e6',sub:['Checks NextDNS every '+s.poll_interval_seconds+' seconds']}
 ];
 for(const c of cards){
  const card=el('div','card stat-card');card.style.setProperty('--c',c.color);card.tabIndex=0;
  card.append(el('div','muted',c.label),el('div','value',String(c.value)));
  const sub=el('div','stat-sub');(c.sub||[]).slice(0,5).forEach(t=>sub.append(el('span','stat-chip',t)));card.append(sub);
  if(c.spark){const sp=el('div','spark');sp.id='spark-alerts';card.append(sp);}
  card.onclick=()=>showStatDetail(c.k);card.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();showStatDetail(c.k);}};
  stats.append(card);
 }
}
function sparkSvg(values,color){
 const w=160,h=34,max=Math.max(1,...values);const step=values.length>1?w/(values.length-1):w;
 const pts=values.map((v,i)=>[i*step,h-3-(v/max)*(h-8)]);
 const line=pts.map((p,i)=>(i?'L':'M')+p[0].toFixed(1)+' '+p[1].toFixed(1)).join(' ');
 return '<svg viewBox="0 0 '+w+' '+h+'" preserveAspectRatio="none"><path d="'+line+' L'+w+' '+h+' L0 '+h+' Z" fill="'+color+'" opacity=".16"/><path d="'+line+'" fill="none" stroke="'+color+'" stroke-width="2" stroke-linecap="round"/></svg>';
}
async function showStatDetail(kind){
 try{
  if(kind==='alerts'){const a=await api('/api/alerts');openDetailModal('All alerts ('+a.length+')',['Time','Account','Profile','Event','Done by','Device','Domain','Details','Notification'],a.map(x=>[formatDateTime(x.event_timestamp||x.created_at),x.account_name,x.profile_name,catBadge(x.category),originBadge(x.origin),x.device_name||x.device_id||'',x.domain,x.reason,notifChip(x.notification_status)]));}
  else if(kind==='profiles'||kind==='active'){const [acc,hl]=await Promise.all([api('/api/accounts'),api('/api/health')]);const hm={};(hl||[]).forEach(h=>hm[h.profile_id]=h);const list=kind==='active'?acc.filter(a=>a.active):acc;openDetailModal((kind==='active'?'Active profiles':'Monitored profiles')+' ('+list.length+')',['Account','NextDNS profile','ID','Monitoring','Health','Last success','Failures','Last error'],list.map(a=>{const h=hm[a.profile_id]||{};return [a.name,a.profile_name,a.profile_id,a.active?'Enabled':'Disabled',h.status,formatDateTime(h.last_success_at),h.consecutive_failures||0,h.last_error];}));}
  else if(kind==='denylist'){
   const acc=await api('/api/accounts');const rows=[];let total=0;
   for(const a of acc){let d=[];try{d=await api('/api/denylist/'+encodeURIComponent(a.profile_id),{_quiet:true});}catch(e){rows.push([a.name,a.profile_name,'Could not load: '+e.message]);continue;}
    const list=Array.isArray(d)?d:(Array.isArray(d?.entries)?d.entries:[]);total+=list.length;
    if(!list.length)rows.push([a.name,a.profile_name,'(empty)']);list.forEach(e=>rows.push([a.name,a.profile_name,typeof e==='string'?e:(e.domain||e.id||JSON.stringify(e))]));}
   openDetailModal('Denylist entries per account ('+total+' total)',['Account','NextDNS profile','Domain'],rows);
  }
  else if(kind==='poll'){const hl=await api('/api/health');openDetailModal('Polling status',['Account','Status','Last poll','Last success','Failures','Last error'],(hl||[]).map(h=>[h.name||h.profile_id,h.status,formatDateTime(h.last_poll_at||h.last_success_at),formatDateTime(h.last_success_at),h.consecutive_failures||0,h.last_error]));}
 }catch(e){showActionToast('Could not load details: '+e.message,'error');}
}
function renderOverviewInsights(data){
 const box=document.getElementById('ov-insights');if(!box)return;box.replaceChildren();
 const left=el('div','ov-col');left.append(el('h3','','Top blocked sites · 24 h'));
 const td=(data.top_domains||[]).filter(d=>d.visits>0).slice(0,5);
 if(!td.length)left.append(el('div','muted','No blocked-site visits in the last 24 hours.'));
 const max=Math.max(1,...td.map(d=>d.visits));
 td.forEach((d,i)=>{const r=el('div','hbar-row');r.append(el('span','hbar-label',d.domain));const bar=el('span','hbar');const f=el('span','hbar-fill');f.style.width=(d.visits/max*100)+'%';f.style.background=PALETTE[i%PALETTE.length];bar.append(f);r.append(bar,el('strong','',String(d.visits)));left.append(r);});
 const right=el('div','ov-col');right.append(el('h3','','Latest activity per account'));
 const profs=data.profiles||[];if(!profs.length)right.append(el('div','muted','No activity recorded yet.'));
 profs.slice(0,6).forEach(p=>{const ev=p.recent_events&&p.recent_events[0];const r=el('div','act-row');const t=el('div','');t.append(el('strong','',p.account_name),el('div','muted small',p.profile_name||p.profile_id));
  const m=el('div','act-meta');m.append(el('span','pill',p.total_alerts+' events'));if(p.blocked_count)m.append(el('span','pill bad',p.blocked_count+' blocked'));if(ev)m.append(el('span','muted small',(ev.domain||ev.alert_type||'event')+' · '+relTime(ev.ts)));
  r.append(t,m);right.append(r);});
 box.append(left,right);
}

/* ---------- Event timeline (detailed, with origin and before → after) ---------- */
function timelineEvent(ev){
 const row=el('div','tl-item cat-'+(ev.category||'other'));row.style.setProperty('--c',(CAT[ev.category]||CAT.other).color);
 if(ev.alert_id&&!ev.seen)row.classList.add('unseen');
 const dot=el('div','tl-dot',(CAT[ev.category]||CAT.other).icon);
 const body=el('div','tl-body');
 const head=el('div','tl-head');head.append(el('strong','',ev.title||'Event'));if(ev.alert_id&&!ev.seen)head.append(el('span','pill new-pill','NEW'));if(ev.undone)head.append(el('span','pill','undone'));
 body.append(head);
 const who=el('div','tl-who muted');who.textContent=[ev.account_name&&('Account: '+ev.account_name),ev.profile_name&&('Profile: '+ev.profile_name),ev.profile_id&&('ID: '+ev.profile_id)].filter(Boolean).join(' · ')||'Sentinel';body.append(who);
 if((ev.lines||[]).length){const g=el('div','tl-lines');ev.lines.forEach(([k,v])=>{const s=el('div','kv');s.append(el('em','',k+': '),document.createTextNode(v));g.append(s);});body.append(g);}
 if((ev.diff||[]).length){const t=el('div','tl-diff');ev.diff.forEach(d=>{const r=el('div','diff-row');r.append(el('span','diff-field',d.field),el('span','diff-from',d.from),el('span','diff-arrow','→'),el('span','diff-to',d.to));t.append(r);});body.append(t);}
 const foot=el('div','tl-foot');foot.append(originBadge(ev.origin),el('span','muted',formatDateTime(ev.time)+' · '+relTime(ev.time)));body.append(foot);
 row.append(dot,body);return row;
}
function renderTimeline(events){
 const box=document.getElementById('event-timeline');if(!box)return;
 const sig=JSON.stringify((events||[]).map(e=>[e.alert_id,e.change_id,e.audit_id,e.seen,e.undone]));if(box.dataset.sig===sig)return;box.dataset.sig=sig;
 box.replaceChildren();setText('timeline-count',(events||[]).length+' events','');
 if(!events||!events.length){box.append(el('div','muted','No timeline events yet.'));return;}
 const groups=new Map();for(const ev of events){const k=ev.profile_id||'system';if(!groups.has(k))groups.set(k,[]);groups.get(k).push(ev);}
 window.__openTimeline=window.__openTimeline||new Set();
 for(const [pid,group] of groups){
  const card=document.createElement('details');card.className='account tl-group';card.dataset.key='tl:'+pid;if(window.__openTimeline.has(pid))card.open=true;
  const unseen=group.filter(e=>e.alert_id&&!e.seen).length;
  const sum=document.createElement('summary');
  const title=pid==='system'?'System':(group[0].account_name||pid);
  sum.append(el('strong','',title));if(pid!=='system'&&group[0].profile_name)sum.append(el('span','muted',' · '+group[0].profile_name));
  sum.append(el('span','pill',group.length+' events'));if(unseen)sum.append(el('span','pill new-pill','NEW '+unseen));
  card.append(sum);
  const list=el('div','tl-list');const render=(n)=>{list.replaceChildren();group.slice(0,n).forEach(ev=>list.append(timelineEvent(ev)));if(group.length>n){const m=el('button','neutral','Show '+Math.min(25,group.length-n)+' more');m.onclick=()=>render(n+25);list.append(m);}};render(25);
  card.append(list);
  sum.addEventListener('click',()=>{card.dataset.userToggle='1';});
  card.addEventListener('toggle',async()=>{if(card.open)window.__openTimeline.add(pid);else window.__openTimeline.delete(pid);
   const byUser=card.dataset.userToggle==='1';delete card.dataset.userToggle;
   if(!card.open||!byUser)return;const ids=group.filter(e=>e.alert_id&&!e.seen).map(e=>e.alert_id);if(!ids.length)return;
   group.forEach(e=>{if(ids.includes(e.alert_id))e.seen=true;});
   try{await api('/api/alerts/seen-all',{method:'POST',body:JSON.stringify({ids}),_silent:true});}catch(e){return;}
   card.querySelectorAll('.tl-item.unseen').forEach(n=>n.classList.remove('unseen'));card.querySelectorAll('.new-pill').forEach(n=>n.remove());
   (window.__recentAlertsCache||[]).forEach(x=>{if(ids.includes(x.id))x.seen_at=x.seen_at||new Date().toISOString();});renderRecentAlerts(window.__recentAlertsCache||[]);});
  box.append(card);
 }
}

/* ---------- Security incidents (detailed) ---------- */
const INC_COLORS={open:'bad',investigating:'warn',resolved:'ok',ignored:'muted'};
async function loadIncidents(){
 const items=await api('/api/incidents?limit=30');const box=document.getElementById('incidents');if(!box)return;
 const openKeys=new Set([...box.querySelectorAll('details[open]')].map(d=>d.dataset.key));
 box.replaceChildren();setText('incident-count',items.length+' incidents','');
 if(!items.length){box.append(el('div','muted','No correlated incidents yet. They appear when several related alerts happen close together.'));return;}
 for(const x of items){
  const d=document.createElement('details');d.className='account inc-card';d.dataset.key='inc:'+x.id;if(openKeys.has(d.dataset.key))d.open=true;
  const sum=document.createElement('summary');sum.append(el('strong','','#'+x.id+' · '+(x.title||'Incident')),el('span','state-chip '+(INC_COLORS[x.status]||'muted'),String(x.status||'').toUpperCase()));
  d.append(sum);
  const grid=el('div','inc-grid');
  const kv=(k,v)=>{const r=el('div','kv');r.append(el('em','',k),el('span','',v||'—'));grid.append(r);};
  kv('Account',x.account_name);kv('NextDNS profile',(x.profile_name||'—')+(x.profile_id?' · '+x.profile_id:''));
  kv('Domain',x.domain);kv('Device',x.device_name);kv('Alerts in incident',String(x.alert_count||0));
  kv('Started',formatDateTime(x.created_at));kv('Last activity',formatDateTime(x.updated_at));
  if(x.resolved_at)kv('Resolved',formatDateTime(x.resolved_at));
  d.append(grid);if(x.summary)d.append(el('div','muted inc-summary',x.summary));
  const ctl=el('div','row');const sel=document.createElement('select');for(const s of ['open','investigating','resolved','ignored']){const o=document.createElement('option');o.value=s;o.textContent=s[0].toUpperCase()+s.slice(1);o.selected=s===x.status;sel.append(o);}
  const apply=el('button','neutral','Update status');apply.onclick=async()=>{await api('/api/incidents/'+x.id+'/status',{method:'POST',body:JSON.stringify({status:sel.value})});loadIncidents();};
  ctl.append(el('span','muted','Status'),sel,apply);d.append(ctl);
  const alertsBox=el('div','inc-alerts');alertsBox.textContent='Open to load the alerts in this incident…';d.append(alertsBox);
  d.addEventListener('toggle',async()=>{if(!d.open||d.dataset.loaded)return;d.dataset.loaded='1';
   try{const full=await api('/api/incidents/'+x.id);alertsBox.replaceChildren();(full.alerts||[]).forEach(a=>{const r=el('div','inc-alert');r.append(catBadge(alert_cat(a)),el('strong','',a.domain||'—'),el('span','muted',(a.device_name||a.device_id||'')+' · '+formatDateTime(a.event_timestamp||a.created_at)));alertsBox.append(r);});if(!(full.alerts||[]).length)alertsBox.textContent='No alerts attached.';}catch(e){alertsBox.textContent=e.message;}});
  box.append(d);
 }
}
async function loadIncidentDetail(id){const d=document.querySelector('[data-key="inc:'+id+'"]');if(d){d.open=true;d.scrollIntoView({behavior:'smooth',block:'center'});}}
async function loadDomains(){}

/* ---------- Live in-dashboard alerts ---------- */
let soundOn=(localStorage.getItem('sentinel_sound')||'on')==='on';
function beep(){if(!soundOn)return;try{const C=window.AudioContext||window.webkitAudioContext;const ctx=new C();const o=ctx.createOscillator(),g=ctx.createGain();o.type='sine';o.frequency.value=880;g.gain.setValueAtTime(.0001,ctx.currentTime);g.gain.exponentialRampToValueAtTime(.25,ctx.currentTime+.02);g.gain.exponentialRampToValueAtTime(.0001,ctx.currentTime+.55);o.connect(g);g.connect(ctx.destination);o.start();o.stop(ctx.currentTime+.6);setTimeout(()=>ctx.close(),800);}catch(e){}}
function toggleSound(){soundOn=!soundOn;localStorage.setItem('sentinel_sound',soundOn?'on':'off');paintSoundBtn();showActionToast('Alert sound is '+(soundOn?'ON':'OFF'),'info');if(soundOn)beep();}
function paintSoundBtn(){const b=document.getElementById('sound-btn');if(b){b.textContent=soundOn?'🔔 Sound on':'🔕 Sound off';b.classList.toggle('off',!soundOn);}}
function showLiveBanner(items){
 let b=document.getElementById('live-banner');if(!b){b=el('div','');b.id='live-banner';document.body.append(b);}
 const x=items[items.length-1];b.replaceChildren();
 const ico=el('div','lb-ico','🚫');const t=el('div','lb-text');
 t.append(el('strong','',items.length>1?items.length+' new blocked-site visits':'Blocked site visited: '+(x.domain||'unknown')));
 t.append(el('div','',(x.account_name||'')+(x.device_name?' · '+x.device_name:'')+' · '+fmtClock(parseDate(x.event_timestamp||x.created_at)||new Date(),true)));
 const view=el('button','neutral','View');view.onclick=()=>{b.remove();navigateToTarget('overview','recent-alerts-panel');};
 const close=el('button','neutral','Dismiss');close.onclick=()=>b.remove();
 b.append(ico,t,view,close);b.className='live-banner show';clearTimeout(window.__bannerTimer);window.__bannerTimer=setTimeout(()=>b.remove(),15000);
 document.title='(🚫 '+items.length+') NextDNS Sentinel';setTimeout(()=>{document.title='NextDNS Sentinel';},8000);
}
function notifyNewDenylistAlerts(alerts){
 const newest=Math.max(lastAlertId,...alerts.map(x=>Number(x.id||0)));
 const fresh=alerts.filter(x=>Number(x.id||0)>lastAlertId&&x.alert_type==='denylist_match'&&!x.seen_at);
 if(lastAlertId&&fresh.length){
  showLiveBanner(fresh);beep();
  const x=fresh[fresh.length-1];
  if('Notification' in window&&Notification.permission==='granted'&&'serviceWorker' in navigator){
   navigator.serviceWorker.ready.then(reg=>{if(reg&&typeof reg.showNotification==='function')return reg.showNotification('Blocked site visited',{body:(x.domain||'')+' — '+(x.account_name||''),tag:'sentinel-'+x.id});}).catch(()=>{});
  }
 }else if(!notificationPermissionRequested&&'Notification' in window&&Notification.permission==='default'){notificationPermissionRequested=true;try{Notification.requestPermission().catch(()=>{});}catch(e){}}
 if(newest>lastAlertId){try{localStorage.setItem('sentinel_last_alert_id',String(newest));}catch(e){}}
 lastAlertId=Math.max(lastAlertId,newest);
}

const PALETTE=['#4f9dff','#3ddc97','#f5c451','#ff6b7a','#a78bfa','#5ad1e6','#ff9f6b','#e879f9','#84cc16','#38bdf8'];
const SVGNS='http://www.w3.org/2000/svg';
function svg(tag,attrs,text){const e=document.createElementNS(SVGNS,tag);for(const k in (attrs||{}))e.setAttribute(k,attrs[k]);if(text!==undefined)e.textContent=text;return e;}
function chartEmpty(box,msg){box.replaceChildren(el('div','chart-empty muted',msg||'No data in this period yet.'));}
function hourLabel(d){let h=d.getHours();const ap=h>=12?'PM':'AM';return (h%12||12)+' '+ap;}
function dayLabel(d){return MON3[d.getMonth()]+' '+d.getDate();}

function bucketize(timeline,hours){
 const cats=['site','profile','denylist','device','other'];
 if(hours<=48)return timeline.map(b=>({d:new Date(b.time),label:hourLabel(new Date(b.time)),tip:fmtDate(new Date(b.time))+' · '+hourLabel(new Date(b.time)),v:b}));
 const days=new Map();
 timeline.forEach(b=>{const d=new Date(b.time);const key=d.getFullYear()+'-'+d.getMonth()+'-'+d.getDate();if(!days.has(key))days.set(key,{d:new Date(d.getFullYear(),d.getMonth(),d.getDate()),v:{site:0,profile:0,denylist:0,device:0,other:0}});const t=days.get(key);cats.forEach(c=>t.v[c]+=b[c]||0);});
 return [...days.values()].map(x=>({d:x.d,label:dayLabel(x.d),tip:fmtDate(x.d),v:x.v}));
}
function drawStacked(box,timeline,hours){
 const cats=['site','profile','denylist','device','other'];const data=bucketize(timeline,hours);
 const total=data.reduce((s,b)=>s+cats.reduce((a,c)=>a+(b.v[c]||0),0),0);
 if(!total)return chartEmpty(box,'No events in this period.');
 const W=860,H=290,L=44,R=12,T=14,B=44;const max=Math.max(1,...data.map(b=>cats.reduce((a,c)=>a+(b.v[c]||0),0)));
 const nice=Math.max(1,Math.ceil(max/4)*4);const s=svg('svg',{viewBox:`0 0 ${W} ${H}`,class:'chart-svg',preserveAspectRatio:'none'});
 for(let i=0;i<=4;i++){const y=T+(H-T-B)*(1-i/4);s.append(svg('line',{x1:L,x2:W-R,y1:y,y2:y,class:'grid-line'}),svg('text',{x:L-8,y:y+4,class:'axis-text','text-anchor':'end'},String(Math.round(nice*i/4))));}
 const bw=(W-L-R)/data.length;const every=Math.ceil(data.length/12);
 data.forEach((b,i)=>{let y=H-B;const x=L+i*bw+bw*.14;const w=bw*.72;const g=svg('g',{class:'bar-g'});
  const sum=cats.reduce((a,c)=>a+(b.v[c]||0),0);
  cats.forEach(c=>{const v=b.v[c]||0;if(!v)return;const h=(H-T-B)*v/nice;y-=h;const r=svg('rect',{x,y,width:w,height:Math.max(1,h),rx:3,fill:CAT[c].color});r.append(svg('title',{},b.tip+' — '+CAT[c].label+': '+v));g.append(r);});
  if(!sum){g.append(svg('rect',{x,y:H-B-1.5,width:w,height:1.5,fill:'#26344d'}));}
  s.append(g);if(i%every===0)s.append(svg('text',{x:x+w/2,y:H-B+18,class:'axis-text','text-anchor':'middle'},b.label));});
 box.replaceChildren(s);
 const leg=el('div','legend');cats.forEach(c=>{const l=el('span','legend-item');const sw=el('i','');sw.style.background=CAT[c].color;l.append(sw,document.createTextNode(CAT[c].label));leg.append(l);});box.append(leg);
}
function drawDonut(box,items,centerLabel){
 const total=items.reduce((a,i)=>a+i.value,0);if(!total)return chartEmpty(box);
 const R=62,C=2*Math.PI*R;const s=svg('svg',{viewBox:'0 0 180 180',class:'donut-svg'});s.append(svg('circle',{cx:90,cy:90,r:R,fill:'none',stroke:'#17223a','stroke-width':22}));
 let off=0;items.filter(i=>i.value>0).forEach(i=>{const len=C*i.value/total;const c=svg('circle',{cx:90,cy:90,r:R,fill:'none',stroke:i.color,'stroke-width':22,'stroke-dasharray':`${Math.max(0,len-1.5)} ${C-len+1.5}`,'stroke-dashoffset':-off,transform:'rotate(-90 90 90)'});c.append(svg('title',{},i.label+': '+i.value));s.append(c);off+=len;});
 s.append(svg('text',{x:90,y:92,class:'donut-num','text-anchor':'middle'},String(total)),svg('text',{x:90,y:110,class:'donut-cap','text-anchor':'middle'},centerLabel||'events'));
 const wrap=el('div','donut-wrap');wrap.append(s);const leg=el('div','donut-legend');
 items.forEach(i=>{const r=el('div','legend-row');const sw=el('i','');sw.style.background=i.color;r.append(sw,el('span','',i.label),el('strong','',String(i.value)),el('span','muted',Math.round(i.value/total*100)+'%'));leg.append(r);});
 wrap.append(leg);box.replaceChildren(wrap);
}
function drawHBars(box,rows,emptyMsg){
 if(!rows.length)return chartEmpty(box,emptyMsg);const max=Math.max(1,...rows.map(r=>r.value));box.replaceChildren();
 rows.forEach((r,i)=>{const row=el('div','hbar-row big');row.append(el('span','hbar-label',r.label));const bar=el('span','hbar');const f=el('span','hbar-fill');f.style.width=Math.max(4,r.value/max*100)+'%';f.style.background='linear-gradient(90deg,'+PALETTE[i%PALETTE.length]+','+PALETTE[(i+3)%PALETTE.length]+')';bar.append(f);row.append(bar,el('strong','',String(r.value)));if(r.sub)row.title=r.sub;box.append(row);});
}
function drawHeat(box,timeline){
 const hours=new Array(24).fill(0);timeline.forEach(b=>{hours[new Date(b.time).getHours()]+=b.count||0;});
 const max=Math.max(...hours);if(!max)return chartEmpty(box);box.replaceChildren();
 const grid=el('div','heat-grid');
 hours.forEach((v,h)=>{const c=el('div','heat-cell');const a=v?(.18+.82*v/max):.05;c.style.background='rgba(79,157,255,'+a.toFixed(2)+')';if(v/max>.66)c.style.background='rgba(255,107,122,'+a.toFixed(2)+')';else if(v/max>.33)c.style.background='rgba(245,196,81,'+a.toFixed(2)+')';c.title=hourLabel(new Date(2000,0,1,h))+': '+v+' events';c.append(el('b','',v?String(v):'·'),el('small','',hourLabel(new Date(2000,0,1,h))));grid.append(c);});
 box.append(grid,el('div','muted small','Darker/redder = busier. Hours are in your local time.'));
}
async function loadRangeAnalytics(){
 const sel=document.getElementById('analytics-range');const hours=Number(sel?.value||24);
 const data=await api('/api/analytics?hours='+hours,{_quiet:true});window.__analyticsCache=data;renderAnalytics(data);
}
function renderAnalytics(data){
 if(!data)return;const hours=data.hours||24;const cats=data.categories||{};
 const kp=document.getElementById('an-kpis');
 if(kp){kp.replaceChildren();const spark=(data.timeline||[]).map(b=>b.count);
  [['Total events',data.total_24h||0,'#4f9dff'],['Blocked-site visits',cats.site||0,CAT.site.color],['Settings changes',cats.profile||0,CAT.profile.color],['Denylist changes',cats.denylist||0,CAT.denylist.color],['Device events',cats.device||0,CAT.device.color]].forEach(([l,v,c],i)=>{const card=el('div','card stat-card');card.style.setProperty('--c',c);card.append(el('div','muted',l),el('div','value',String(v)));if(i===0){const sp=el('div','spark');sp.innerHTML=sparkSvg(spark,c);card.append(sp);}kp.append(card);});}
 setText('analytics-total',(data.total_24h||0)+' events','');
 const sub=document.getElementById('an-range-label');if(sub)sub.textContent='Last '+(hours>=48?Math.round(hours/24)+' days':hours+' hours')+' · '+(hours<=48?'hourly':'daily')+' · your local time';
 const t=document.getElementById('an-timeline');if(t)drawStacked(t,data.timeline||[],hours);
 const d=document.getElementById('an-donut');if(d)drawDonut(d,Object.keys(CAT).map(k=>({label:CAT[k].label,value:cats[k]||0,color:CAT[k].color})),'events');
 const dm=document.getElementById('an-domains');if(dm)drawHBars(dm,(data.top_domains||[]).map(x=>({label:x.domain,value:x.count,sub:x.visits+' visits · last '+formatDateTime(x.last)})),'No blocked or denylisted domains in this period.');
 const o=document.getElementById('an-origins');if(o){const oc=data.origins||{};drawDonut(o,Object.keys(ORIGIN).map(k=>({label:ORIGIN[k].label,value:oc[k]||0,color:ORIGIN[k].color})),'events');}
 const hm=document.getElementById('an-hours');if(hm)drawHeat(hm,data.timeline||[]);
 const dv=document.getElementById('an-devices');if(dv)drawHBars(dv,(data.top_devices||[]).map(x=>({label:x.device+' · '+x.account_name,value:x.count})),'No blocked-site visits from devices in this period.');
 const pb=document.getElementById('analytics-profiles');if(pb){
  pb.replaceChildren();setText('analytics-profile-count',(data.profiles||[]).length+' profiles','');
  if(!(data.profiles||[]).length)pb.append(el('div','muted','No profile activity in this period.'));
  (data.profiles||[]).forEach(p=>{
   const d=document.createElement('details');d.className='account prof-card';d.dataset.key='prof:'+p.profile_id;
   const sum=document.createElement('summary');sum.append(el('strong','',p.account_name),el('span','muted',' · '+(p.profile_name||p.profile_id)),el('span','pill',p.total_alerts+' events'));if(p.blocked_count)sum.append(el('span','pill bad',p.blocked_count+' blocked'));d.append(sum);
   const total=Math.max(1,p.total_alerts);const bar=el('div','stackbar');Object.keys(CAT).forEach(c=>{const v=p.categories[c]||0;if(!v)return;const s=el('span','');s.style.width=(v/total*100)+'%';s.style.background=CAT[c].color;s.title=CAT[c].label+': '+v;bar.append(s);});d.append(bar);
   const chips=el('div','chips');Object.keys(CAT).forEach(c=>{const v=p.categories[c]||0;if(v){const b=catBadge(c);b.append(' · '+v);chips.append(b);}});d.append(chips);
   if((p.top_domains||[]).length){d.append(el('div','muted small','Most visited blocked sites'));const rows=el('div','');drawHBars(rows,p.top_domains.slice(0,5).map(x=>({label:x.domain,value:x.count})));d.append(rows);}
   const ev=el('div','prof-events');(p.recent_events||[]).slice(0,6).forEach(e=>{const r=el('div','inc-alert');r.append(catBadge(alert_cat(e)),el('strong','',e.domain||(e.alert_type||'').replace(/_/g,' ')),el('span','muted',(e.device_name||'')+' '+formatDateTime(e.ts)));ev.append(r);});d.append(ev);
   pb.append(d);});
 }
 renderAnalyticsExtras(data);
 const sp=document.getElementById('spark-alerts');if(sp&&(hours===24))sp.innerHTML=sparkSvg((data.timeline||[]).map(b=>b.count),'#ff6b7a');
}
function alert_cat(e){if(e.status==='denylist_added'||e.status==='denylist_removed')return 'denylist';return TYPE_TO_CAT[e.alert_type]||'other';}

/* ---------- Devices ---------- */
function deviceStatus(x){const last=x.last_seen_at?new Date(x.last_seen_at).getTime():0;const age=last?(Date.now()-last)/1000:Infinity;
 if(age<=180)return {k:'online',label:'Active',cls:'ok'};if(age<=3600)return {k:'idle',label:'Idle',cls:'warn'};return {k:'silent',label:'Silent',cls:'muted'};}
function renderDevices(items){
 const box=document.getElementById('device-activity');box.replaceChildren();setText('device-count',(items||[]).length+' devices','');
 if(!items||!items.length){box.append(el('div','muted','No DNS activity has been observed yet. Devices appear here after their first DNS query.'));return;}
 const alerts=window.__recentAlertsCache||[];
 const groups=new Map();items.forEach(x=>{const k=x.profile_id;if(!groups.has(k))groups.set(k,[]);groups.get(k).push(x);});
 for(const [pid,list] of groups){
  const sec=el('section','dev-group');const head=el('div','dev-group-head');
  head.append(el('strong','',list[0].account_name||accountLabel(pid)),el('span','muted',profileLabel(pid)?' · '+profileLabel(pid):''),el('span','pill',list.length+' device'+(list.length>1?'s':'')));sec.append(head);
  const grid=el('div','dev-grid');
  list.sort((a,b)=>String(b.last_seen_at||'').localeCompare(String(a.last_seen_at||''))).forEach(x=>{
   const st=deviceStatus(x);const mine=alerts.filter(a=>a.profile_id===x.profile_id&&a.device_id===x.device_id);
   const card=el('div','device-item dev-'+st.k);
   const top=el('div','dev-top');const dot=el('span','dev-dot '+st.k);const name=el('span','dev-name',x.device_name||x.device_id||'Unidentified device');name.title='Click the pencil to rename';
   const pen=el('button','neutral mini','✎');pen.title='Rename';
   pen.onclick=()=>{const inp=document.createElement('input');inp.value=x.device_name||'';inp.className='dev-rename';name.replaceWith(inp);inp.focus();pen.textContent='✓';
    const save=async()=>{const v=inp.value.trim();if(!v){showActionToast('Name cannot be empty.','error');return;}try{await api('/api/devices/'+encodeURIComponent(x.profile_id)+'/'+encodeURIComponent(x.device_id),{method:'PATCH',body:JSON.stringify({device_name:v})});}catch(e){return;}};
    pen.onclick=save;inp.onkeydown=e=>{if(e.key==='Enter')save();if(e.key==='Escape')refresh();};};
   top.append(dot,name,el('span','state-chip '+st.cls,st.label),pen);card.append(top);
   const kvs=[['Model',x.device_model||'—'],['IP address',x.client_ip||'—'],['Last seen',x.last_seen_at?relTime(x.last_seen_at)+' · '+formatDateTime(x.last_seen_at):'—'],['Last domain',x.last_domain||'—'],['Last result',x.last_status||'—'],['Blocked-site visits',String(x.blocked_count!=null?x.blocked_count:mine.filter(a=>a.category==='site').length)],['Other events',String(x.alert_count!=null?Math.max(0,x.alert_count-(x.blocked_count||0)):mine.filter(a=>a.category!=='site').length)]];
   const g=el('div','dev-kv');kvs.forEach(([k,v])=>{const r=el('div','kv');r.append(el('em','',k),el('span','',v));g.append(r);});card.append(g);
   const act=el('div','row');const det=el('button','neutral','Details');det.onclick=()=>loadDeviceDetail(x.profile_id,x.device_id);const ed=el('button','neutral','Edit all fields');ed.onclick=()=>editDevice(x);act.append(det,ed);card.append(act);
   grid.append(card);});
  sec.append(grid);box.append(sec);
 }
}

/* ---------- Telegram bots ---------- */
const TG_TYPES=[['site','🚫 Blocked-site visits'],['profile','🔧 Profile settings changes'],['denylist','🛡️ Denylist changes'],['device','📱 Device events'],['system','⚙️ System reports']];
function botCard(bot){
 const wrap=el('div','bot-card'+(bot.enabled?'':' off'));
 const head=el('div','bot-head');const av=el('div','bot-avatar',(bot.name||'B').trim().charAt(0).toUpperCase());
 const t=el('div','bot-title');t.append(el('strong','',bot.name||'Telegram Bot'),el('div','muted small',(bot.bot_username?'@'+bot.bot_username:'unknown bot')+' → '+(bot.chat_title||bot.chat_id||'chat')));
 const state=bot.last_error?{c:'bad',t:'Error'}:(bot.enabled?{c:'ok',t:'Working'}:{c:'muted',t:'Disabled'});
 const sw=el('label','switch');const cb=document.createElement('input');cb.type='checkbox';cb.checked=!!bot.enabled;cb.onchange=()=>toggleTelegramBot(bot.id,cb.checked);sw.append(cb,el('span','slider'));sw.title=bot.enabled?'Turn this bot OFF':'Turn this bot ON';
 head.append(av,t,el('span','state-chip '+state.c,state.t),sw);wrap.append(head);
 const info=el('div','bot-info');
 const k1=el('div','kv');k1.append(el('em','','Last notification'),el('span','',bot.last_notification_at?formatDateTime(bot.last_notification_at)+' · '+relTime(bot.last_notification_at):'Nothing sent yet'));info.append(k1);
 if(bot.last_error){const e=el('div','kv err');e.append(el('em','','Last error'),el('span','',bot.last_error));info.append(e);}
 const types=(bot.alert_types||'').split(',').filter(Boolean);
 const k2=el('div','kv');k2.append(el('em','','Receives'),el('span','',types.length?types.map(x=>(TG_TYPES.find(t=>t[0]===x)||[0,x])[1]).join(' · '):'Everything'));info.append(k2);
 if(bot.quiet_start&&bot.quiet_end){const k3=el('div','kv');k3.append(el('em','','Quiet hours'),el('span','',bot.quiet_start+' – '+bot.quiet_end+' (delivered silently)'));info.append(k3);}
 wrap.append(info);
 const act=el('div','bot-actions');
 const b=(txt,cls,fn)=>{const x=el('button',cls,txt);x.onclick=fn;act.append(x);};
 b('Send test','neutral',()=>testTelegramBot(bot.id));b('Preview report','neutral',()=>previewTelegram());b('Edit','neutral',()=>editTelegramBot(bot.id));b('Delete','stop',()=>deleteTelegramBot(bot.id));
 wrap.append(act);
 const d=document.createElement('details');d.className='bot-prefs';d.dataset.key='botprefs:'+bot.id;
 d.append(el('summary','','⚙ What this bot receives · quiet hours'));
 const body=el('div','bot-card-editor');
 const grid=el('div','pref-grid');TG_TYPES.forEach(([k,label])=>{const l=el('label','pref');const c=document.createElement('input');c.type='checkbox';c.value=k;c.checked=!types.length||types.includes(k);l.append(c,document.createTextNode(' '+label));grid.append(l);});
 const qh=el('div','row');const qs=document.createElement('input');qs.type='time';qs.value=bot.quiet_start||'';const qe=document.createElement('input');qe.type='time';qe.value=bot.quiet_end||'';
 qh.append(el('span','muted','Quiet hours (silent delivery) from'),qs,el('span','muted','to'),qe);
 const save=el('button','start','Save preferences');save.onclick=async()=>{const chosen=[...grid.querySelectorAll('input:checked')].map(i=>i.value);const all=chosen.length===TG_TYPES.length;if(!chosen.length){showActionToast('Pick at least one report type, or turn the bot off.','error');return;}
  await api('/api/settings/telegram/bots/'+bot.id+'/prefs',{method:'POST',body:JSON.stringify({alert_types:all?[]:chosen,quiet_start:qs.value,quiet_end:qe.value})});window.__dirtyUntil=0;};
 body.append(grid,qh,el('div','muted small','Quiet hours still deliver the report, but without a notification sound. Clear both times to disable.'),save);d.append(body);wrap.append(d);
 return wrap;
}
async function renderBots(){
 const botCardBox=document.getElementById('telegram-bot-card');if(!botCardBox)return;
 const bots=await api('/api/settings/telegram/bots');window.__bots=bots;botCardBox.replaceChildren();
 const working=bots.filter(b=>b.enabled&&!b.last_error).length;
 setText('telegram-status',bots.length?(working+' of '+bots.length+' bot'+(bots.length>1?'s':'')+' working'+(bots.length-working?' · '+(bots.length-working)+' off or with errors':'')):'No bots yet — add one to receive reports.',working?'ok':'muted');
 if(!bots.length){const e=el('div','bot-empty');e.append(el('div','big','🤖'),el('strong','','No Telegram bots yet'),el('div','muted','Add a bot on the left to receive reports on Telegram.'));botCardBox.append(e);return;}
 bots.forEach(b=>botCardBox.append(botCard(b)));
}
async function previewTelegram(kind){
 try{const k=kind||'denylist_match';const d=await api('/api/settings/telegram/preview?kind='+k,{_quiet:true});
  openDetailModal('Telegram report preview',[],[],'This is exactly how a report looks on Telegram (sample data).');
  const body=document.querySelector('#detail-modal .modal-body');body.replaceChildren(el('div','muted small','Sample data — nothing was sent.'));
  const tabs=el('div','row');[['denylist_match','🚫 Blocked site'],['denylist_added','➕ Denylist'],['config_changed','🔧 Settings'],['device_inactive','📴 Device']].forEach(([v,l])=>{const b=el('button',v===k?'start':'neutral',l);b.onclick=()=>previewTelegram(v);tabs.append(b);});
  const pre=el('pre','tg-preview');pre.textContent=d.text;body.append(tabs,pre);
 }catch(e){}
}
async function toggleTelegramBot(id,enabled){try{await api('/api/settings/telegram/bots/'+id+'/enable',{method:'POST',body:JSON.stringify({enabled})});await refresh();}catch(e){await refresh();}}
async function testTelegramBot(id){try{await api('/api/settings/telegram/bots/'+id+'/test',{method:'POST'});await refresh();}catch(e){}}

/* ---------- Control Center ---------- */
function ccResult(title,lines,ok){
 const box=document.getElementById('control-details');if(!box)return;box.replaceChildren();
 const card=el('div','cc-result '+(ok===false?'bad':'ok'));const h=el('div','cc-result-head');h.append(el('strong','',title),el('span','muted small',fmtClock(new Date(),true)));
 const x=el('button','neutral mini','Clear');x.onclick=()=>box.replaceChildren();h.append(x);card.append(h);
 (lines||[]).forEach(l=>card.append(el('div','kv',l)));box.append(card);
 showActionToast(title,ok===false?'error':'ok');
}
async function loadDiagnostics(){const d=await api('/api/diagnostics',{_silent:true});ccResult('Diagnostics',Object.entries(d).map(([k,v])=>k+': '+(v?'OK ✔':'FAIL ✖')),Object.values(d).every(Boolean));}
async function loadRateLimits(){const d=await api('/api/control-center',{_silent:true});const r=d.rate_limits||[];ccResult('Rate limits',r.length?r.map(x=>x.endpoint+' · retry after '+x.retry_after+'s · '+formatDateTime(x.created_at)):['No rate-limit events recorded. NextDNS has not throttled Sentinel.'],true);}
async function loadIncidentMetrics(){const d=await api('/api/incident-metrics',{_silent:true});ccResult('Incident metrics',['Total incidents: '+d.total_incidents,'Open: '+d.open_incidents,'Resolved: '+d.resolved_incidents,'Mean time to resolve: '+(d.mean_time_to_resolve_seconds?Math.round(d.mean_time_to_resolve_seconds/60)+' min':'—')],true);}
async function loadRiskBaseline(){const base=await api('/api/baseline',{_silent:true});const rows=(base||[]).slice().sort((a,b)=>Number(b.baseline||0)-Number(a.baseline||0)).slice(0,8);ccResult('Typical activity by hour',rows.length?rows.map(x=>hourLabel(new Date(2000,0,1,Number(x.bucket_hour)))+' — '+Number(x.baseline||0).toFixed(1)+' events on average'):['Not enough history yet — Sentinel learns this over a few days.'],true);}
async function toggleSafeMode(){
 const d=await api('/api/control-center',{_silent:true});const enabled=!d.safe_mode;
 await api('/api/safe-mode',{method:'POST',body:JSON.stringify({enabled})});await loadControlCenter();
}
async function endMaintenance(){await api('/api/maintenance',{method:'DELETE'});await loadControlCenter();}
function stateRow(label,sub,on,onText,offText,btn){
 const r=el('div','mini-item state-row');const left=el('span','');left.append(el('strong','',label));if(sub)left.append(el('div','muted small',sub));
 const right=el('span','row');const chip=el('span','state-chip '+(on===null?'muted':(on?'ok':'muted')),on===null?offText:(on?onText:offText));right.append(chip);if(btn)right.append(btn);r.append(left,right);return r;
}
async function loadControlCenter(){
 try{
  const d=await api('/api/control-center',{_quiet:true});const box=document.getElementById('control-summary');box.replaceChildren();
  const sb=el('button',d.safe_mode?'neutral':'start',d.safe_mode?'Turn OFF':'Turn ON');sb.onclick=toggleSafeMode;
  box.append(stateRow('Safe Mode','When ON, nothing can change your NextDNS settings from this dashboard.',!!d.safe_mode,'ON','OFF',sb));
  let mb=null;if(d.maintenance){mb=el('button','neutral','End now');mb.onclick=endMaintenance;}
  const mEnd=d.maintenance&&d.maintenance.ends_at?' · ends '+formatTime(d.maintenance.ends_at):'';
  box.append(stateRow('Maintenance mode',d.maintenance?(d.maintenance.reason||'Notifications are muted')+mEnd:'Notifications are active',!!d.maintenance,'ON','OFF',mb));
  box.append(stateRow('Alert rules',(d.rules||[]).length?(d.rules.filter(r=>r.enabled).length+' of '+d.rules.length+' enabled'):'No rules yet',(d.rules||[]).length>0,String(d.rules.length)+' rule(s)','None',null));
  box.append(stateRow('Database','Local SQLite storage',!!d.diagnostics?.database,'OK','Problem',null));
  box.append(stateRow('Schema','Required tables',!!d.diagnostics?.schema,'OK','Problem',null));
  box.append(stateRow('API protection',d.api_auth?'Token required for the dashboard API':'No token — local access only',!!d.api_auth,'ON','OFF',null));
  renderRulesList(d.rules||[]);fillRuleSelects();loadAuthStatus();
 }catch(e){setText('control-summary',e.message,'error');}
}

/* ---------- Advanced profile config: Clear really clears ---------- */
function clearConfigForm(){
 configFormSource=null;
 const f=document.getElementById('config-form');if(f)f.replaceChildren();
 const r=document.getElementById('config-readable');if(r)r.replaceChildren(el('div','muted','Select a profile and load its live configuration.'));
 const tag=document.getElementById('config-dirty');if(tag){tag.textContent='';tag.style.display='none';}
 window.__dirtyUntil=0;setText('config-status','Cleared. Nothing is loaded.','muted');showActionToast('Configuration view cleared.','info');
}

/* ---------- Keyboard shortcuts ---------- */
document.addEventListener('keydown',e=>{
 if(/^(INPUT|TEXTAREA|SELECT)$/.test((e.target||{}).tagName||'')||e.metaKey||e.ctrlKey||e.altKey)return;
 if(e.key==='/'){const s=document.getElementById('alert-search');if(s){e.preventDefault();navigateToTarget('security','alert-search');setTimeout(()=>s.focus(),300);}return;}
 const map={o:'overview',a:'analytics',d:'devices',s:'security',p:'profiles',n:'notifications',c:'operations'};
 if(window.__gKey&&map[e.key]){showPage(map[e.key]);window.__gKey=false;return;}
 window.__gKey=(e.key==='g');clearTimeout(window.__gTimer);window.__gTimer=setTimeout(()=>{window.__gKey=false;},1200);
});


/* ---------- change-gated, page-scoped refresh (no pill, no needless re-rendering) ---------- */
const __sig={};
function changed(key,data){const s=JSON.stringify(data);if(__sig[key]===s)return false;__sig[key]=s;return true;}
function activePage(){return localStorage.getItem('sentinel_active_page')||'overview';}
async function refresh(){
 const page=activePage();
 try{
  const [acc,rt,s,alerts]=await Promise.all([api('/api/accounts'),api('/api/runtime'),api('/api/stats'),api('/api/alerts')]);
  window.__accounts=acc;__accountNameMap={};acc.forEach(a=>{__accountNameMap[a.profile_id]=a.name;});
  window.__stats=s;window.__recentAlertsCache=alerts;
  setText('runtime',rt.running?'Running':'Stopped',rt.running?'ok':'muted');
  const health=document.getElementById('health');health.className='status '+(s.last_error?'error':'ok');health.textContent=s.last_error?'Monitor error: '+s.last_error+' · '+formatDateTime(s.last_error_at):'Monitor healthy · Last successful poll: '+formatDateTime(s.last_success_at);
  const heroDot=document.getElementById('hero-dot');heroDot.className='dot '+(s.last_error?'':'ok');setText('hero-status',s.last_error?'Attention required':'Monitoring healthy',s.last_error?'error':'ok');
  notifyNewDenylistAlerts(alerts);
  const unseenIds=alerts.filter(x=>!x.seen_at).map(x=>x.id);
  if(page==='overview'){
   if(changed('stats',[s.accounts,s.active_accounts,s.alerts,s.denylist_entries,s.poll_interval_seconds,s.per_account,unseenIds.length]))renderStats(s);
   if(changed('recent',unseenIds))renderRecentAlerts(alerts);
   const analytics=await api('/api/analytics?hours=24',{_quiet:true});if(changed('insights',[analytics.top_domains,analytics.profiles&&analytics.profiles.map(p=>[p.profile_id,p.total_alerts,p.blocked_count])]))renderOverviewInsights(analytics);
   renderProfileHealth(await api('/api/health'));
   renderTimeline(await api('/api/timeline'));
  }
  if(page==='security'){
   if(changed('alerts',alerts.map(x=>[x.id,x.seen_at,x.notification_status,x.notified_at])))renderAlertsTable(alerts);
   await loadIncidents();
  }
  if(page==='devices'){const d=await api('/api/devices');if(changed('devices',d)&&!document.querySelector('.dev-rename'))renderDevices(d);}
  if(page==='profiles'){
   if(changed('accounts',acc)){renderAccountsTable(acc);renderGroupedDenylist(acc);}
   syncProfileSelects(acc);
   let dl='';try{dl=JSON.parse(window.__lastPulse||'{}').denylist||'';}catch(e){}
   if(changed('deny',[dl,document.getElementById('deny-profile')?.value]))await showSelectedDenylist();
   await loadConfigChanges();
  }
  if(page==='notifications')await renderBots();
  if(page==='operations')await loadControlCenter();
  if(page==='analytics'){await loadRangeAnalytics();await loadSentinelHealth();}
 }catch(e){setText('health','Dashboard error: '+e.message,'error');showActionToast('Refresh failed: '+e.message,'error');}
}
function renderAccountsTable(accounts){
 const box=document.getElementById('accounts');box.replaceChildren();
 if(!accounts.length){box.textContent='No profiles configured. Add one above.';return;}
 const wrap=el('div','table-wrap');const table=document.createElement('table');table.innerHTML='<thead><tr><th>Account</th><th>NextDNS Profile</th><th>Profile ID</th><th>Status</th><th>Actions</th></tr></thead><tbody></tbody>';
 const body=table.querySelector('tbody');
 for(const a of accounts){
  const tr=document.createElement('tr');
  [a.name,a.profile_name,a.profile_id].forEach(v=>{const td=document.createElement('td');td.textContent=v||'—';tr.append(td);});
  const st=document.createElement('td');st.append(el('span','state-chip '+(a.active?'ok':'muted'),a.active?'Monitoring ON':'Monitoring OFF'));tr.append(st);
  const actions=document.createElement('td');
  const b=el('button',a.active?'stop':'start',a.active?'Disable':'Enable');b.onclick=()=>toggleAccount(a.profile_id,!a.active);
  const v=el('button','neutral','Denylist');v.onclick=()=>showDenylist(a.profile_id);
  const edit=el('button','neutral','Edit');edit.onclick=()=>editProfile(a.profile_id);
  const del=el('button','stop','Delete');del.onclick=()=>deleteAccount(a.profile_id);
  actions.append(b,v,edit,del);tr.append(actions);body.append(tr);
 }
 wrap.append(table);box.append(wrap);
}
function syncProfileSelects(accounts){
 const sig=JSON.stringify(accounts.map(a=>[a.profile_id,a.name,a.profile_name]));
 for(const id of ['config-profile','deny-profile']){
  const sel=document.getElementById(id);if(!sel)continue;if(sel.dataset.sig===sig&&sel.options.length)continue;
  const old=sel.value;sel.replaceChildren();
  for(const a of accounts){const o=document.createElement('option');o.value=a.profile_id;o.textContent=a.name+' · '+a.profile_name+' ('+a.profile_id+')';sel.append(o);}
  if(old&&[...sel.options].some(o=>o.value===old))sel.value=old;sel.dataset.sig=sig;
 }
}
async function softRefresh(){
 try{const alerts=await api('/api/alerts',{_quiet:true});window.__recentAlertsCache=alerts;notifyNewDenylistAlerts(alerts);
  if(activePage()==='overview'&&changed('recent',alerts.filter(x=>!x.seen_at).map(x=>x.id)))renderRecentAlerts(alerts);}catch(e){}
}
async function fullRefresh(){const open=captureOpenState();await refresh();restoreOpenState(open);}
function showPendingPill(){const p=document.getElementById('pending-pill');if(p)p.remove();}
async function forceRefresh(){for(const k in __sig)delete __sig[k];try{window.__lastPulse=JSON.stringify(await api('/api/pulse'));}catch(e){}await fullRefresh();}
async function pulseTick(){
 if(document.hidden)return;
 const pulse=JSON.stringify(await api('/api/pulse',{_quiet:true}));
 const page=activePage();
 if(pulse!==window.__lastPulse){
  if(userEngaged()){await softRefresh();return;}   // never rebuild a form the user is typing in
  window.__lastPulse=pulse;await fullRefresh();return;
 }
 await lightRefresh();
 const now=Date.now();
 if((page==='devices'||page==='analytics')&&now-(window.__liveTick||0)>8000){window.__liveTick=now;if(!userEngaged())await fullRefresh();}
}
function scheduleAutoRefresh(){clearTimeout(autoRefreshTimer);autoRefreshTimer=setTimeout(()=>{if(!userEngaged())fullRefresh().catch(()=>{});else softRefresh();},250);}

/* ---------- readable values instead of JSON ---------- */
function humanValue(v){
 if(v===undefined||v===null||v==='')return '—';
 if(typeof v==='boolean')return v?'On':'Off';
 if(typeof v==='number')return String(v);
 if(typeof v==='string'){try{const p=JSON.parse(v);if(p&&typeof p==='object')return humanValue(p);}catch(e){}return v;}
 if(Array.isArray(v)){if(!v.length)return 'None';return v.map(x=>(x&&typeof x==='object')?(x.id||x.name||x.domain||humanValue(x)):String(x)).join(', ');}
 if(typeof v==='object'){const parts=Object.entries(v).map(([k,x])=>configLabel(k)+': '+humanValue(x));return parts.length?parts.join(' · '):'—';}
 return String(v);
}
function prettyJson(v){return humanValue(v);}
function pathLabel(p){return String(p||'').split('.').map(configLabel).join(' › ');}
async function showConfigDiff(){
 try{const accounts=await api('/api/accounts');if(!accounts.length){ccResult('Latest config diff',['No profiles configured.'],false);return;}
  const d=await api('/api/config-diff/'+encodeURIComponent(accounts[0].profile_id),{_silent:true});
  ccResult('Latest config diff · '+(accounts[0].name||accounts[0].profile_id),d.changed?d.diff.map(x=>pathLabel(x.field)+': '+humanValue(x.before)+' → '+humanValue(x.after)):['No recent configuration change for this profile.'],true);
 }catch(e){ccResult('Latest config diff',[e.message],false);}
}
function diffRowEl(diff){
 const r=el('div','diff-row');r.append(el('span','diff-field',pathLabel(diff.field)),el('span','diff-from',diff.type==='added'?'—':humanValue(diff.before)),el('span','diff-arrow','→'),el('span','diff-to',diff.type==='removed'?'—':humanValue(diff.after)));return r;
}

/* ---------- array settings as tag lists (no JSON text boxes) ---------- */
function buildArrayControl(value,path,label,parent){
 const box=el('div','tag-editor');box.append(el('div','tag-title',configLabel(label)));
 const hidden=document.createElement('textarea');hidden.style.display='none';hidden.dataset.path=JSON.stringify(path);hidden.dataset.kind='array-json';
 let items=JSON.parse(JSON.stringify(value));
 const isObj=items.some(x=>x&&typeof x==='object');
 const list=el('div','tag-list');
 const sync=()=>{hidden.value=JSON.stringify(items);hidden.dispatchEvent(new Event('input',{bubbles:true}));};
 const idOf=x=>(x&&typeof x==='object')?String(x.id||x.name||x.domain||humanValue(x)):String(x);
 const paint=()=>{list.replaceChildren();if(!items.length)list.append(el('span','muted','Nothing added'));items.forEach((x,i)=>{const t=el('span','tag');t.append(el('span','',idOf(x)));if(x&&typeof x==='object'&&'active' in x){const sw=el('button','tag-tog',x.active?'on':'off');sw.type='button';sw.title='Toggle active';sw.onclick=()=>{x.active=!x.active;paint();sync();};t.append(sw);}const rm=el('button','tag-x','×');rm.type='button';rm.title='Remove';rm.onclick=()=>{items.splice(i,1);paint();sync();};t.append(rm);list.append(t);});};
 const add=el('div','row');const inp=document.createElement('input');inp.type='text';inp.placeholder='Add item and press Enter';inp.style.maxWidth='260px';
 const addBtn=el('button','neutral mini','Add');addBtn.type='button';
 const doAdd=()=>{const v=inp.value.trim();if(!v)return;if(items.some(x=>idOf(x)===v)){showActionToast('"'+v+'" is already in the list.','info');return;}items.push(isObj?{id:v,active:true}:v);inp.value='';paint();sync();};
 addBtn.onclick=doAdd;inp.onkeydown=e=>{if(e.key==='Enter'){e.preventDefault();doAdd();}};
 add.append(inp,addBtn);box.append(list,add,hidden);hidden.value=JSON.stringify(items);parent.append(box);
}

/* ---------- API authentication: clear state, real logout, turn OFF ---------- */
async function loadAuthStatus(){
 const row=document.getElementById('auth-row');if(!row)return;
 let st={enabled:false,authenticated:true};try{st=await api('/api/auth/status',{_quiet:true});}catch(e){}
 const chip=document.getElementById('auth-chip');chip.className='state-chip '+(st.enabled?'ok':'muted');chip.textContent=st.enabled?'Protection ON':'Protection OFF';
 const sess=document.getElementById('auth-session');sess.textContent=st.enabled?(st.authenticated?'You are logged in.':'You are logged out.'):'Anyone on this computer can open the dashboard.';
 document.getElementById('auth-btn-on').style.display=st.enabled?'none':'';
 document.getElementById('auth-btn-off').style.display=st.enabled?'':'none';
 document.getElementById('auth-btn-logout').style.display=st.enabled?'':'none';
 document.getElementById('api-auth-token').placeholder=st.enabled?'Current token (to turn OFF)':'New token, 16+ chars';
}
async function configureApiAuth(){
 const t=document.getElementById('api-auth-token');const token=t.value.trim();
 if(token.length<16){showActionToast('Use a token with at least 16 characters.','error');return;}
 await api('/api/auth/configure',{method:'POST',body:JSON.stringify({token}),_silent:true});t.value='';
 showActionToast('API protection is now ON. Keep your token safe — you need it to log in or turn protection off.','ok');await loadAuthStatus();await loadControlCenter();
}
async function disableApiAuth(){
 const t=document.getElementById('api-auth-token');const token=t.value.trim();
 if(!token){showActionToast('Type your current token in the box, then press Turn OFF.','error');t.focus();return;}
 await api('/api/auth/disable',{method:'POST',body:JSON.stringify({token}),_silent:true});t.value='';
 showActionToast('API protection is now OFF.','ok');await loadAuthStatus();await loadControlCenter();
}
async function logoutApiAuth(){
 await api('/api/auth/logout',{method:'POST',_silent:true});
 showActionToast('Logged out. Reloading…','info');setTimeout(()=>location.reload(),600);
}

/* ---------- analytics: separate panels, live device list ---------- */
function renderAnalyticsExtras(data){
 const dm=document.getElementById('an-domains');
 if(dm)drawHBars(dm,(data.top_domains||[]).map(x=>({label:x.domain,value:x.visits,sub:'Last visit '+formatDateTime(x.last_visit)})),'No blocked-site visits in this period.');
 const ch=document.getElementById('an-changes');
 if(ch){ch.replaceChildren();const rows=data.denylist_changes||[];if(!rows.length)ch.append(el('div','chart-empty muted','No denylist changes in this period.'));
  rows.forEach(r=>{const row=el('div','change-row');row.append(el('strong','',r.domain));const chips=el('span','chips');if(r.added){const a=el('span','state-chip ok','+ added ×'+r.added);chips.append(a);}if(r.removed){const b=el('span','state-chip bad','− removed ×'+r.removed);chips.append(b);}row.append(chips,el('span','muted small',relTime(r.last)));ch.append(row);});}
 const dv=document.getElementById('an-devices');
 if(dv){dv.replaceChildren();const list=data.devices||[];if(!list.length)dv.append(el('div','chart-empty muted','No devices have been seen yet.'));
  list.forEach(d=>{const st=deviceStatus({last_seen_at:d.last_seen_at});const row=el('div','dev-row');const dot=el('span','dev-dot '+st.k);const main=el('div','');main.append(el('strong','',d.device||'Unidentified'),el('div','muted small',d.account_name+(d.model?' · '+d.model:'')+(d.ip?' · '+d.ip:'')));
   const right=el('div','dev-right');right.append(el('span','state-chip '+st.cls,st.label),el('span','muted small',d.last_seen_at?relTime(d.last_seen_at):'never'),el('span','pill'+(d.visits?' bad':''),d.visits+' blocked visits'));row.append(dot,main,right);dv.append(row);});}
 const kp=document.getElementById('an-kpis');
 if(kp){const cards=kp.querySelectorAll('.stat-card');const last=cards[cards.length-1];if(last){const list=data.devices||[];const active=list.filter(d=>deviceStatus({last_seen_at:d.last_seen_at}).k==='online').length;last.querySelector('.muted').textContent='Active devices now';last.querySelector('.value').textContent=active+' / '+list.length;}}
}
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
            if request.path not in {"/api/auth/status","/api/auth/login","/api/auth/configure","/api/auth/logout","/api/auth/disable"} and not session.get("sentinel_authenticated"):
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

    @app.post("/api/auth/disable")
    def api_auth_disable() -> Any:
        expected=store.setting("api_auth_hash","")
        if not expected:
            return jsonify({"enabled":False,"authenticated":True})
        token=str(request_json().get("token","")).strip()
        if hashlib.sha256(token.encode()).hexdigest()!=expected:
            return jsonify({"error":"Invalid API token. Protection stays ON."}),401
        store.set_setting("api_auth_hash","")
        session.pop("sentinel_authenticated",None)
        features.audit("api_auth_disable","security","api",details={"enabled":False})
        return jsonify({"enabled":False,"authenticated":True})

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
        data = store.stats()
        data["per_account"] = [{"profile_id": a["profile_id"], "name": a["name"], "profile_name": a.get("profile_name", ""),
                                "active": bool(a.get("active")), "denylist": len(store.denylist_entries(a["profile_id"]))}
                               for a in store.accounts()]
        return jsonify(data)

    @app.get("/api/health")
    def api_health() -> Any:
        items = store.monitor_health()
        for item in items:
            try:
                item["log_stat"] = json.loads(store.setting(f"logstat:{item.get('profile_id','')}", "") or "{}")
            except (TypeError, ValueError):
                item["log_stat"] = {}
        return jsonify(items)

    @app.get("/api/pulse")
    def api_pulse() -> Any:
        queries={
            "alerts":"SELECT COALESCE(MAX(id),0)||'-'||COUNT(*)||'-'||COALESCE(MAX(seen_at),'')||'-'||COALESCE(MAX(notified_at),'')||'-'||COALESCE(SUM(CASE WHEN seen_at!='' THEN 1 ELSE 0 END),0) FROM alerts",
            "changes":"SELECT COALESCE(MAX(id),0)||'-'||COUNT(*)||'-'||COALESCE(MAX(undone_at),'') FROM config_changes",
            "audit":"SELECT COALESCE(MAX(id),0) FROM audit_log",
            "accounts":"SELECT COUNT(*)||'-'||COALESCE(SUM(active),0)||'-'||COALESCE(MAX(rowid),0) FROM accounts",
            "devices":"SELECT COUNT(*) FROM device_state",
            "bots":"SELECT COUNT(*)||'-'||COALESCE(MAX(updated_at),'') FROM telegram_bots",
            "rules":"SELECT COUNT(*)||'-'||COALESCE(MAX(id),0) FROM alert_rules",
            "maintenance":"SELECT COUNT(*)||'-'||COALESCE(MAX(id),0) FROM maintenance_windows",
            "suppressions":"SELECT COUNT(*)||'-'||COALESCE(MAX(id),0) FROM alert_suppressions",
            "settings":"SELECT COUNT(*)||'-'||COALESCE(MAX(updated_at),'') FROM sentinel_settings",
            "denylist":"SELECT COUNT(*) FROM denylist",
        }
        out={}
        with sqlite3.connect(DB_PATH) as db:
            for key,query in queries.items():
                try: out[key]=str(db.execute(query).fetchone()[0])
                except Exception: out[key]="?"
        return jsonify(out)

    def mark_dashboard_change(account: dict[str, Any]) -> None:
        """Dashboard changes are recorded by the dashboard itself; refresh the stored snapshot so the
        monitor never mistakes them for changes made in the NextDNS app."""
        pid = account["profile_id"]
        store.set_setting(f"dash_mark:{pid}", utc_now())
        try:
            store.save_config_snapshot(pid, config_snapshot(NextDNSClient(account["api_key"]).profile(pid)))
        except Exception:
            logging.debug("Could not refresh the profile snapshot after a dashboard change.", exc_info=True)
        store.set_setting(f"dash_mark:{pid}", utc_now())

    def _account_lookup() -> dict[str, dict[str, Any]]:
        return {a["profile_id"]: a for a in store.accounts()}

    def _decorate_alert(row: dict[str, Any], accounts: dict[str, dict[str, Any]]) -> dict[str, Any]:
        row = dict(row)
        acc = accounts.get(row.get("profile_id", ""), {})
        key, label = origin_of(row.get("source", ""))
        row["origin"] = key; row["origin_label"] = label
        row["category"] = alert_category(row.get("alert_type", ""), row.get("status", ""))
        row["profile_name"] = acc.get("profile_name", "")
        row["account_name"] = acc.get("name") or row.get("account_name", "")
        for volatile in ("severity", "risk_score", "risk_factors", "anomaly_score", "domain_risk", "correlation_id"):
            row.pop(volatile, None)  # estimated values are not shown anywhere
        return row

    @app.get("/api/alerts")
    def api_alerts() -> Any:
        accounts = _account_lookup()
        return jsonify([_decorate_alert(r, accounts) for r in features.alerts(300)])

    def _flat(value: Any, prefix: str = "", out: dict[str, str] | None = None) -> dict[str, str]:
        out = {} if out is None else out
        if isinstance(value, dict):
            for k, v in value.items():
                _flat(v, f"{prefix} › {k}" if prefix else str(k), out)
        else:
            out[prefix or "value"] = json.dumps(value, ensure_ascii=False, default=str)
        return out

    def _diff_pairs(before: Any, after: Any) -> list[dict[str, str]]:
        b = _flat(unwrap_profile_data(before)); a = _flat(unwrap_profile_data(after))
        return [{"field": k, "from": b.get(k, "—"), "to": a.get(k, "—")} for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]

    AUDIT_TITLES = {
        "incident_status": "Incident status changed", "safe_mode": "Safe Mode", "maintenance_start": "Maintenance mode enabled",
        "rule_save": "Alert rule saved", "rule_delete": "Alert rule deleted", "monitor_start": "Monitoring started",
        "monitor_stop": "Monitoring stopped", "profile_monitor_toggle": "Profile monitoring toggled", "profile_delete": "Profile removed from Sentinel",
        "local_profile_update": "Profile details edited", "device_update": "Device edited", "telegram_bot_save": "Telegram bot saved",
        "telegram_bot_enable": "Telegram bot enabled", "telegram_bot_disable": "Telegram bot disabled", "telegram_bot_delete": "Telegram bot deleted",
        "denylist_add": "Denylist entry added", "denylist_remove": "Denylist entry removed", "denylist_clear": "Denylist cleared",
        "bulk_denylist": "Bulk denylist change", "profile_config_patch": "Profile settings applied", "configuration_undo": "Configuration change undone",
        "settings_import": "Settings imported", "database_retention": "Old records cleaned up", "alert_suppression": "Alert suppression added",
    }

    @app.get("/api/timeline")
    def api_timeline() -> Any:
        accounts = _account_lookup()
        def who(pid: str) -> dict[str, str]:
            a = accounts.get(pid, {})
            return {"profile_id": pid, "account_name": a.get("name", ""), "profile_name": a.get("profile_name", "")}
        events = []
        for alert in features.alerts(120):
            row = _decorate_alert(alert, accounts)
            cat = row["category"]
            lines = []
            if row.get("domain"):
                lines.append(("Domain", row["domain"]))
            if row.get("device_name") or row.get("device_id"):
                lines.append(("Device", row.get("device_name") or row.get("device_id")))
            if row.get("client_ip"):
                lines.append(("IP address", row["client_ip"]))
            if row.get("reason"):
                lines.append(("Details", row["reason"]))
            titles = {"site": "Blocked site visited", "denylist": "Denylist changed", "profile": "Profile settings changed", "device": "Device event", "other": "Event"}
            events.append({"time": row.get("event_timestamp") or row.get("created_at") or "", "title": titles.get(cat, "Event") + (f" · {row['domain']}" if row.get("domain") else ""),
                           "lines": lines, "kind": "warn", "category": cat, "alert_type": row.get("alert_type", ""), "status": row.get("status", ""),
                           "origin": row["origin"], "origin_label": row["origin_label"], **who(row.get("profile_id", "")),
                           "alert_id": row.get("id"), "seen": bool(row.get("seen_at"))})
        for change in store.config_changes(100):
            try:
                diff = _diff_pairs(json.loads(change.get("before_json") or "{}"), json.loads(change.get("after_json") or "{}"))
            except (TypeError, ValueError):
                diff = []
            key, label = origin_of(change.get("source", ""))
            events.append({"time": change.get("changed_at") or "", "title": "Settings change · " + str(change.get("change_type") or "profile"),
                           "lines": [], "diff": diff[:30], "kind": "config", "category": "profile", "origin": key, "origin_label": label,
                           "undone": bool(change.get("undone_at")), **who(change.get("profile_id", "")), "change_id": change.get("id")})
        for audit in features.audit_entries(120):
            action = str(audit.get("action") or "")
            try:
                details = json.loads(audit.get("details") or "{}")
            except (TypeError, ValueError):
                details = {}
            lines = []
            if action == "incident_status":
                lines.append(("Incident", "#" + str(audit.get("target_id"))))
                if details.get("domain"):
                    lines.append(("Domain", details["domain"]))
                lines.append(("Status", f"{details.get('from', '—')} → {details.get('status', details.get('to', '—'))}"))
            elif action == "safe_mode":
                lines.append(("State", "ON" if details.get("enabled") else "OFF"))
            else:
                for k, v in list(details.items())[:6]:
                    lines.append((str(k).replace("_", " ").title(), json.dumps(v, ensure_ascii=False, default=str) if isinstance(v, (dict, list)) else str(v)))
                if audit.get("target_id") and not lines:
                    lines.append(("Target", str(audit["target_id"])))
            events.append({"time": audit.get("created_at") or "", "title": AUDIT_TITLES.get(action, action.replace("_", " ").title() or "Sentinel action"),
                           "lines": lines, "kind": "audit", "category": "other", "origin": "dashboard", "origin_label": origin_of("sentinel_dashboard")[1],
                           **who(audit.get("profile_id", "")), "audit_id": audit.get("id")})
        events.sort(key=lambda item: str(item.get("time") or ""), reverse=True)
        return jsonify(events[:250])

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
            before=config_snapshot(json.loads(change["before_json"])); after=config_snapshot(json.loads(change["after_json"]))
            client=NextDNSClient(account["api_key"])
            current=config_snapshot(client.profile(change["profile_id"]))
            if current!=after:
                return jsonify({"error":"Undo refused: the profile changed again after this audit event."}),409
            rollback={k:before[k] for k in set(before)|set(after) if before.get(k)!=after.get(k) and k in {"security","privacy","parentalControl","settings","denylist","allowlist","name"}}
            if not rollback:
                return jsonify({"error":"Nothing to undo."}),409
            client._patch(f"/profiles/{change['profile_id']}",rollback)
            verified=config_snapshot(client.profile(change["profile_id"]))
            if verified!=before:
                return jsonify({"error":"Undo was sent but the live profile did not match the previous configuration."}),502
            store.mark_change_undone(change_id)
            store.save_config_snapshot(change["profile_id"],before); mark_dashboard_change(account)
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
        accounts = _account_lookup()
        devices = {(d["profile_id"], d["device_id"]): d for d in store.device_states()}
        out = []
        for inc in features.incidents(request.args.get("status", ""), int(request.args.get("limit", "100"))):
            acc = accounts.get(inc.get("profile_id", ""), {})
            dev = devices.get((inc.get("profile_id", ""), inc.get("device_id", "")), {})
            inc = dict(inc)
            inc["account_name"] = acc.get("name", ""); inc["profile_name"] = acc.get("profile_name", "")
            inc["device_name"] = dev.get("device_name", "") or inc.get("device_id", "")
            for volatile in ("severity", "risk_score"):
                inc.pop(volatile, None)
            out.append(inc)
        return jsonify(out)

    @app.get("/api/incidents/<int:incident_id>")
    def api_incident(incident_id:int) -> Any:
        item=features.incident(incident_id)
        return jsonify(item) if item else (jsonify({"error":"Incident not found."}),404)

    @app.post("/api/incidents/<int:incident_id>/status")
    def api_incident_status(incident_id:int) -> Any:
        data=request_json(); status=str(data.get("status","")).lower()
        before=features.incident(incident_id) or {}
        if not features.set_incident_status(incident_id,status):
            return jsonify({"error":"Invalid incident status or incident not found."}),400
        features.audit("incident_status","incident",str(incident_id),profile_id=str(before.get("profile_id","")),details={"from":before.get("status",""),"status":status,"domain":before.get("domain",""),"title":before.get("title","")})
        acc=_account_lookup().get(str(before.get("profile_id","")),{})
        sentinel.notify_report("Incident status updated",[f"Incident: #{incident_id}"]+([f"Domain: {before.get('domain')}"] if before.get("domain") else [])+[f"Account: {acc.get('name','—')}",f"NextDNS profile: {acc.get('profile_name') or '—'}",f"Status: {str(before.get('status','')).upper()} → {status.upper()}"])
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

    @app.post("/api/denylist/<profile_id>")
    def api_denylist_add(profile_id: str) -> Any:
        data=request_json(); domain=normalize_domain(str(data.get("domain","")))
        account=next((a for a in store.accounts() if a["profile_id"]==profile_id),None)
        if not account: return jsonify({"error":"Account not found."}),404
        try:
            client=NextDNSClient(account["api_key"]); client.add_denylist(profile_id,domain)
            current=client.denylist(profile_id); store.replace_denylist(profile_id,current); mark_dashboard_change(account)
            key=hashlib.sha256(f"action:denylist_add:{profile_id}:{domain}:{utc_now()}".encode()).hexdigest()
            store.add_alert(profile_id,account["name"],domain,domain,f"Denylist entry added by Sentinel dashboard","denylist_added","",utc_now(),key,"configuration_action",source="sentinel_dashboard")
            alert_id=sentinel.enrich_alert(key,account,domain,"Denylist entry added by Sentinel dashboard","denylist_added",domain,"",utc_now(),"","","","",False)
            delivered=sentinel.notify(account,domain,"Denylist entry added by Sentinel dashboard","denylist_added",domain,event_time=utc_now(),alert_id=alert_id)
            if delivered: store.mark_alert_notified(key)
            else: store.mark_notification_failed(key)
            features.audit("denylist_add","profile",profile_id,profile_id,{"domain":domain})
            return jsonify({"saved":True,"domain":domain,"entries":current})
        except Exception as exc: return jsonify({"error":str(exc)}),400

    @app.delete("/api/denylist/<profile_id>")
    def api_denylist_clear(profile_id: str) -> Any:
        account=next((a for a in store.accounts() if a["profile_id"]==profile_id),None)
        if not account: return jsonify({"error":"Account not found."}),404
        try:
            client=NextDNSClient(account["api_key"]); current=client.denylist(profile_id)
            for domain in current:
                client.remove_denylist(profile_id,domain)
            store.replace_denylist(profile_id,[]); mark_dashboard_change(account)
            key=hashlib.sha256(f"action:denylist_clear:{profile_id}:{utc_now()}".encode()).hexdigest()
            store.add_alert(profile_id,account["name"],"","",f"All denylist entries removed from Sentinel dashboard","denylist_removed","",utc_now(),key,"configuration_action",source="sentinel_dashboard")
            features.audit("denylist_clear","profile",profile_id,profile_id,{"removed":len(current)})
            return jsonify({"cleared":True,"removed":len(current),"entries":[]})
        except Exception as exc: return jsonify({"error":str(exc)}),400


    @app.delete("/api/denylist/<profile_id>/<path:domain>")
    def api_denylist_remove(profile_id: str, domain: str) -> Any:
        account=next((a for a in store.accounts() if a["profile_id"]==profile_id),None)
        if not account: return jsonify({"error":"Account not found."}),404
        try:
            client=NextDNSClient(account["api_key"]); client.remove_denylist(profile_id,domain)
            current=client.denylist(profile_id); store.replace_denylist(profile_id,current); mark_dashboard_change(account)
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
                current=client.denylist(account["profile_id"]); store.replace_denylist(account["profile_id"],current); mark_dashboard_change(account)
                results.append({"profile_id":account["profile_id"],"profile_name":account["profile_name"],"status":"success","reason":"API operation completed."})
            except Exception as exc:
                results.append({"profile_id":account["profile_id"],"profile_name":account["profile_name"],"status":"failed","reason":str(exc)})
        successes=sum(r["status"]=="success" for r in results); failures=sum(r["status"]=="failed" for r in results); skipped=sum(r["status"]=="skipped" for r in results)
        operation_id=features.record_bulk("denylist_"+action,domain,results)
        features.audit("bulk_denylist","all_profiles",domain,details={"action":action,"operation_id":operation_id,"successes":successes,"failures":failures,"skipped":skipped})
        if True:
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
            store.save_config_snapshot(profile_id,after); mark_dashboard_change(account)
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
            existing=next((b for b in store.telegram_bots() if b.get("chat_id")==chat_id),None)
            store.save_telegram_bot(int(existing["id"]) if existing else None,str(data.get("name") or identity["bot"].get("first_name") or "Telegram Bot"),token,chat_id,True,identity)
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
                        "token_configured":bool(b["token"]),"alert_types":b.get("alert_types",""),
                        "quiet_start":b.get("quiet_start",""),"quiet_end":b.get("quiet_end","")} for b in store.telegram_bots()])

    @app.post("/api/settings/telegram/bots/<int:bot_id>/prefs")
    def api_telegram_bot_prefs(bot_id:int) -> Any:
        d=request_json()
        if not store.set_telegram_bot_prefs(bot_id,",".join(d.get("alert_types") or []) if isinstance(d.get("alert_types"),list) else str(d.get("alert_types") or ""),str(d.get("quiet_start") or ""),str(d.get("quiet_end") or "")):
            return jsonify({"error":"Telegram bot not found."}),404
        features.audit("telegram_bot_save","telegram_bot",str(bot_id),details={"preferences":"updated"})
        return jsonify({"saved":True})

    @app.get("/api/settings/telegram/preview")
    def api_telegram_preview() -> Any:
        kind=str(request.args.get("kind","denylist_match"))
        sample_acc={"name":"Mo Phone","profile_name":"My First Profile","profile_id":"abc123"}
        samples={
            "denylist_match":dict(domain="example-blocked.com",reason="Custom denylist match",status="blocked",matched="example-blocked.com",client_ip="192.0.2.10",device_name="Pixel 8",device_model="Google Pixel",protocol="DNS-over-HTTPS",encrypted=True,ctx={"alert_type":"denylist_match","source":"nextdns_logs"},repeats=2),
            "denylist_added":dict(domain="example-blocked.com",reason="Denylist entry added",status="denylist_added",ctx={"alert_type":"configuration_action","source":"sentinel_dashboard"}),
            "config_changed":dict(domain="",reason="",status="config_changed",ctx={"alert_type":"config_change","source":"nextdns_profile"}),
            "device_inactive":dict(domain="",reason="No recent DNS activity",status="device_inactive",device_name="Pixel 8",ctx={"alert_type":"device_inactive","source":""}),
        }
        sm=samples.get(kind,samples["denylist_match"])
        text,category=sentinel.build_report(sample_acc,sm.get("domain",""),sm.get("reason",""),sm.get("status",""),sm.get("matched",""),sm.get("client_ip",""),utc_now(),"",sm.get("device_name",""),sm.get("device_model",""),sm.get("protocol",""),bool(sm.get("encrypted")),sm["ctx"],int(sm.get("repeats",0)),utc_now())
        plain=re.sub(r"<[^>]+>","",text).replace("&amp;","&").replace("&lt;","<").replace("&gt;",">")
        return jsonify({"kind":kind,"category":category,"text":plain})

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
            if "alert_types" in data or "quiet_start" in data:
                store.set_telegram_bot_prefs(saved_id,",".join(data.get("alert_types") or []) if isinstance(data.get("alert_types"),list) else str(data.get("alert_types") or ""),str(data.get("quiet_start") or ""),str(data.get("quiet_end") or ""))
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

    @app.post("/api/settings/telegram/bots/<int:bot_id>/check")
    def api_telegram_bot_check(bot_id:int) -> Any:
        bot=next((b for b in store.telegram_bots() if int(b["id"])==bot_id),None)
        if not bot: return jsonify({"error":"Telegram bot not found."}),404
        try:
            identity=validate_telegram_credentials(bot["token"],bot["chat_id"])
            store.mark_telegram_bot_result(bot_id,True,"")
            return jsonify({"active":True,"bot_username":str(identity["bot"].get("username") or ""), "bot_name":str(identity["bot"].get("first_name") or ""), "chat_title":str(identity["chat"].get("title") or identity["chat"].get("first_name") or identity["chat"].get("username") or ""), "checked_at":utc_now()})
        except Exception as exc:
            store.mark_telegram_bot_result(bot_id,False,str(exc))
            return jsonify({"active":False,"error":str(exc),"checked_at":utc_now()}),502


    @app.delete("/api/settings/telegram/bots/<int:bot_id>")
    def api_telegram_bot_delete(bot_id:int) -> Any:
        if not store.delete_telegram_bot(bot_id): return jsonify({"error":"Telegram bot not found."}),404
        # Old single-bot credentials must not come back and keep delivering after the bot is removed.
        for key in ("telegram_token","telegram_chat_id"):
            store.delete_secret(key)
        store.set_setting("telegram_legacy_migrated","1")
        sentinel.telegram_token = ""; sentinel.telegram_chat_id = ""
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

    @app.delete("/api/maintenance")
    def api_maintenance_end()->Any:
        ended=features.end_maintenance()
        features.audit("maintenance_end","maintenance","")
        return jsonify({"ended":ended})

    @app.post("/api/alerts/seen-all")
    def api_alerts_seen_all()->Any:
        data=request_json(); ids=[int(x) for x in (data.get("ids") or []) if str(x).isdigit()]
        profile_id=str(data.get("profile_id") or ""); now=utc_now(); count=0
        with sqlite3.connect(DB_PATH) as db:
            if ids:
                for i in ids:
                    cur=db.execute("UPDATE alerts SET seen_at=? WHERE id=? AND seen_at=''",(now,i)); count+=cur.rowcount
                    db.execute("UPDATE notification_state SET state='seen',seen_at=? WHERE alert_id=? AND state!='seen'",(now,i))
            else:
                where=" AND profile_id=?" if profile_id else ""
                args=(now,profile_id) if profile_id else (now,)
                rows=[r[0] for r in db.execute("SELECT id FROM alerts WHERE seen_at=''"+where,args[1:]).fetchall()]
                cur=db.execute("UPDATE alerts SET seen_at=? WHERE seen_at=''"+where,args); count=cur.rowcount
                for i in rows: db.execute("UPDATE notification_state SET state='seen',seen_at=? WHERE alert_id=? AND state!='seen'",(now,i))
        return jsonify({"seen":count})

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
    if telegram_token and telegram_chat_id and not store.telegram_bots() and store.setting("telegram_legacy_migrated","0") != "1":
        try:
            store.save_telegram_bot(None, "Telegram Bot", telegram_token, telegram_chat_id, True, {})
        except Exception:
            logging.warning("Could not migrate the legacy Telegram bot.", exc_info=True)
    store.set_setting("telegram_legacy_migrated", "1")
    sentinel = Sentinel(store, features, "", "")

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