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
        db = sqlite3.connect(self.path)
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
        bucket=dt.astimezone(timezone.utc).strftime('%H')
        with self._connect() as db:
            row=db.execute("SELECT count FROM anomaly_baseline WHERE profile_id=? AND bucket_hour=?",(profile_id,bucket)).fetchone()
            count=int(row['count'])+1 if row else 1
            db.execute(
                "INSERT INTO anomaly_baseline(profile_id,bucket_hour,count,updated_at) VALUES(?,?,?,?) "
                "ON CONFLICT(profile_id,bucket_hour) DO UPDATE SET count=excluded.count,updated_at=excluded.updated_at",
                (profile_id,bucket,count,now_iso()),
            )

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

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            self._migrate_alert_columns(db)
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
                    undone_at TEXT NOT NULL DEFAULT ''
                )
            """)


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
            db.execute("DELETE FROM accounts WHERE profile_id=?", (profile_id,))
            db.execute("DELETE FROM denylist WHERE profile_id=?", (profile_id,))
            db.execute("DELETE FROM monitor_state WHERE profile_id=?", (profile_id,))

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

    def add_config_change(self, profile_id: str, before: dict[str,Any], after: dict[str,Any], change_type: str) -> int:
        with sqlite3.connect(self.path) as db:
            cur=db.execute("INSERT INTO config_changes(profile_id,change_type,before_json,after_json,changed_at) VALUES(?,?,?,?,?)",(profile_id,change_type,json.dumps(before,sort_keys=True),json.dumps(after,sort_keys=True),utc_now()))
            return int(cur.lastrowid)

    def config_changes(self, limit:int=50) -> list[dict[str,Any]]:
        with sqlite3.connect(self.path) as db:
            db.row_factory=sqlite3.Row
            return [dict(r) for r in db.execute("SELECT id,profile_id,change_type,before_json,after_json,changed_at,undone_at FROM config_changes ORDER BY id DESC LIMIT ?",(limit,))]

    def mark_change_undone(self, change_id:int) -> None:
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE config_changes SET undone_at=? WHERE id=?",(utc_now(),change_id))

    def mark_alert_seen(self, alert_id: int) -> bool:
        with sqlite3.connect(self.path) as db:
            cur=db.execute("UPDATE alerts SET seen_at=? WHERE id=? AND seen_at=''",(utc_now(),alert_id))
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
            """,(profile_id,device_id,device_name,device_model,client_ip,last_seen_at,last_status,last_domain,utc_now()))

    def mark_device_inactive_alerted(self, profile_id: str, device_id: str) -> bool:
        with sqlite3.connect(self.path) as db:
            cur=db.execute("UPDATE device_state SET inactive_alerted_at=? WHERE profile_id=? AND device_id=? AND inactive_alerted_at=''",(utc_now(),profile_id,device_id))
            return cur.rowcount>0

    def device_states(self) -> list[dict[str, Any]]:
        with sqlite3.connect(self.path) as db:
            db.row_factory=sqlite3.Row
            return [dict(r) for r in db.execute("SELECT profile_id,device_id,device_name,device_model,client_ip,last_seen_at,last_status,last_domain,updated_at,inactive_alerted_at FROM device_state ORDER BY device_name,device_id")]

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
                SELECT event_timestamp,domain,status
                FROM alerts
                WHERE event_timestamp >= ?
                ORDER BY event_timestamp ASC
                """,
                (start_iso,),
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
        top_domains = sorted(domains.items(), key=lambda item: (-item[1], item[0]))[:8]
        return {
            "timeline": [{"time": key, "count": value} for key, value in buckets.items()],
            "statuses": status_counts,
            "top_domains": [{"domain": key, "count": value} for key, value in top_domains],
            "total_24h": len(rows),
        }

    def monitor_health(self) -> list[dict[str, Any]]:
        with sqlite3.connect(self.path) as db:
            db.row_factory = sqlite3.Row
            return [
                dict(r)
                for r in db.execute(
                    """
                    SELECT a.profile_id,a.name,a.active,
                           s.last_poll_ms,s.last_success_at,s.last_error,s.last_error_at
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
            with self._connect() as db: db.execute("SELECT 1"); checks["database"]=True
        except Exception: checks["database"]=False
        checks["encryption"]=bool(SECRET_KEY)
        checks["schema"]=all(self._table_exists(t) for t in ("alerts","incidents","audit_log","sentinel_health","alert_rules"))
        return checks

    def _table_exists(self, name):
        with self._connect() as db:
            return bool(db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(name,)).fetchone())

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


def validate_telegram_credentials(token: str, chat_id: str) -> None:
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
    features: FeatureStore | None = None
    telegram_token: str = ""
    telegram_chat_id: str = ""
    stop_event: threading.Event | None = None
    threads: list[threading.Thread] | None = None

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
        severity = str(context.get("severity") or "medium").upper()
        risk_score = context.get("risk_score", "—")
        incident_id = context.get("incident_id", "—")
        domain_risk = str(context.get("domain_risk") or "low").upper()
        title = "NextDNS Sentinel Security Alert"
        lines = [
            f"🚨 {title}",
            "",
            f"Severity: {severity} · Risk: {risk_score}/100",
            f"Type: {status or 'security_event'}",
            f"Profile: {account['name']}",
            f"Domain: {domain or 'n/a'}",
            f"Matched: {matched or 'n/a'}",
            f"Domain Risk: {domain_risk}",
            f"Reason: {reason or 'Security event'}",
            f"Event Time: {event_time or 'n/a'}",
            f"Detected At: {utc_now()}",
        ]
        if incident_id not in ("", "—", None):
            lines.append(f"Incident: #{incident_id}")
        if device_name or device_id:
            lines.append(f"Device: {device_name or device_id}")
        if device_model:
            lines.append(f"Model: {device_model}")
        if client_ip:
            lines.append(f"Client IP: {client_ip}")
        if protocol:
            lines.append(f"Protocol: {protocol}")
        if encrypted:
            lines.append("Encrypted: yes")
        if not self.telegram_token or not self.telegram_chat_id:
            return False
        return send_telegram(self.telegram_token, self.telegram_chat_id, "\n".join(lines))

    def notify_report(self, title: str, lines: list[str], alert_id: int | None = None) -> bool:
        if alert_id and self.features:
            context = self.features.alert_context(alert_id)
            severity = str(context.get("severity") or "medium").upper()
            risk = context.get("risk_score", "—")
            lines = [f"Severity: {severity} · Risk: {risk}/100", *lines]
        message = "🛡️ NextDNS Sentinel\n\n" + title + "\n" + "\n".join(lines)
        ok = send_telegram(self.telegram_token, self.telegram_chat_id, message) if self.telegram_token and self.telegram_chat_id else False
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

    def monitor_account(self, account: dict[str, Any]) -> None:
        client = NextDNSClient(account["api_key"])
        profile_id = account["profile_id"]
        logging.info("Monitoring %s (%s)", account["name"], profile_id)
        denylist: set[str] = set()
        iteration = 0

        while self.stop_event is None or not self.stop_event.is_set():
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
                            change_id=self.store.add_config_change(profile_id,previous,live_snapshot,change_type)
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
                        self.store.update_device_state(profile_id,device_id,device_name,device_model,client_ip,event_time,status,domain)
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

                for alert in self.store.unnotified_alerts(profile_id):
                    if self.store.was_recently_notified(
                        profile_id, alert["domain"], ALERT_COOLDOWN
                    ):
                        self.store.mark_alert_suppressed(alert["event_key"])
                        logging.info(
                            "Suppressing delayed notification because %s was "
                            "already notified during the cooldown.",
                            alert["domain"],
                        )
                        continue

                    alert_id=int(alert.get("id") or 0) or None
                    delivered = self.notify(
                        account,
                        alert["domain"],
                        alert["reason"],
                        alert["status"],
                        alert["matched_domain"],
                        alert["client_ip"],
                        alert["event_timestamp"],
                        alert.get("device_id",""), alert.get("device_name",""),
                        alert.get("device_model",""), alert.get("protocol",""),
                        bool(alert.get("encrypted")), alert_id,
                    )
                    if delivered:
                        self.store.mark_alert_notified(alert["event_key"])
                        if self.features and alert_id: self.features.delivery(alert_id,"telegram","sent")
                    else:
                        self.store.mark_notification_failed(alert["event_key"])
                        if self.features and alert_id: self.features.delivery(alert_id,"telegram","failed")

                self.store.set_poll_state(profile_id, checkpoint_ms)
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

    def start(self) -> int:
        if self.is_running():
            return 0

        accounts = [a for a in self.store.accounts() if a["active"]]
        if not accounts:
            raise RuntimeError(
                "No active accounts configured. Add a NextDNS profile from the dashboard."
            )

        self.stop_event = threading.Event()
        if self.features:
            self.features.heartbeat("starting", {"profiles": len(accounts)})
        self.threads = [
            threading.Thread(
                target=self.monitor_account,
                args=(account,),
                name=f"sentinel-{account['profile_id']}",
                daemon=True,
            )
            for account in accounts
        ]

        for thread in self.threads:
            thread.start()

        logging.info(
            "%s is monitoring %d account(s).",
            APP_NAME,
            len(self.threads),
        )
        return len(self.threads)

    def is_running(self) -> bool:
        return bool(self.threads and any(thread.is_alive() for thread in self.threads))

    def stop(self) -> None:
        if self.stop_event:
            self.stop_event.set()
        for thread in self.threads or []:
            thread.join(timeout=CHECK_INTERVAL + 5)
        self.threads = None
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


DASHBOARD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NextDNS Sentinel</title>
<style>:root{color-scheme:dark}*{box-sizing:border-box}body{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:radial-gradient(circle at 15% 0%,#14243a 0,#080b12 36%);color:#e8edf7;margin:0;padding:24px;line-height:1.45}main{max-width:1250px;margin:auto}h1{margin:0;font-size:32px;letter-spacing:-.6px}h2{margin:0 0 12px;font-size:18px}h3{margin:0 0 10px}.muted{color:#8c98aa}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:18px 0}.card,.panel{background:linear-gradient(145deg,rgba(16,22,33,.97),rgba(11,16,25,.97));border:1px solid #263248;border-radius:16px;padding:17px;margin-bottom:14px;box-shadow:0 12px 35px rgba(0,0,0,.16)}.value{font-size:29px;font-weight:750;margin-top:3px}.card .muted{text-transform:capitalize;font-size:12px;letter-spacing:.4px}.status{margin:10px 0;padding:11px 13px;border-radius:10px;background:#101621;border:1px solid #263248}.ok{color:#9af0bb}.error{color:#ffb4b4}.neutral-text{color:#b8c4d8}button{border:1px solid transparent;border-radius:9px;padding:9px 13px;font-weight:700;cursor:pointer;margin:3px;transition:transform .15s,filter .15s}button:hover{filter:brightness(1.08);transform:translateY(-1px)}.start{background:#35c76f;color:#07140b}.stop{background:#ef6b73;color:#21080a}.neutral{background:#29364a;color:#e8edf7}input,select{width:100%;box-sizing:border-box;background:#0b1019;color:#e8edf7;border:1px solid #303b4e;border-radius:9px;padding:10px;margin:5px 0 10px}label{display:block;font-size:13px;color:#aeb8c8}form{max-width:560px}table{width:100%;border-collapse:collapse;background:#101621;border-radius:14px;overflow:hidden}th,td{text-align:left;padding:10px;border-bottom:1px solid #202a3a;font-size:13px}th{color:#9eabc0;font-size:12px;text-transform:uppercase;letter-spacing:.5px}tbody tr:hover{background:#141d2a}code{color:#9ed0ff}.hidden{display:none}.account{padding:12px 0;border-bottom:1px solid #202a3a}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;margin:10px 0}.meta div{background:#0b1019;border:1px solid #202a3a;border-radius:8px;padding:9px}.meta strong{display:block;font-size:12px;color:#8c98aa;margin-bottom:3px}.hero{display:flex;justify-content:space-between;gap:18px;align-items:center;padding:22px 24px;margin-bottom:14px}.hero-copy{min-width:0}.eyebrow{font-size:11px;text-transform:uppercase;letter-spacing:1.6px;color:#7f91aa;font-weight:800}.hero-badge{border:1px solid #2d405c;background:#0c1420;border-radius:12px;padding:10px 13px;white-space:nowrap}.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px;background:#65758d}.dot.ok{background:#35c76f}.analytics{display:grid;grid-template-columns:minmax(0,2fr) minmax(260px,1fr);gap:14px}.chart{height:230px;display:flex;align-items:flex-end;gap:6px;padding:18px 8px 28px;border-top:1px solid #202a3a}.bar-wrap{height:100%;flex:1;display:flex;align-items:flex-end;justify-content:center;position:relative;min-width:4px}.bar{width:100%;max-width:22px;min-height:3px;border-radius:6px 6px 2px 2px;background:linear-gradient(180deg,#55d98a,#2e9e68);transition:height .3s}.bar-label{position:absolute;bottom:-24px;font-size:10px;color:#75839a;white-space:nowrap}.bar-value{position:absolute;top:-18px;font-size:10px;color:#aebbd0}.mini-list{display:grid;gap:8px}.mini-item{display:flex;justify-content:space-between;gap:10px;padding:9px 10px;background:#0b1019;border:1px solid #202a3a;border-radius:9px}.progress{height:5px;background:#202a3a;border-radius:99px;overflow:hidden;margin-top:5px}.progress>span{display:block;height:100%;background:#55d98a}.section-head{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:10px}.pill{font-size:11px;padding:4px 8px;border-radius:99px;background:#172235;color:#aebbd0}@media(max-width:800px){body{padding:12px}.analytics{grid-template-columns:1fr}.hero{align-items:flex-start;flex-direction:column}.hero-badge{width:100%}}.device-badge{font-size:11px;padding:5px 9px;border:1px solid #2d405c;border-radius:99px;background:#101a28;color:#b8c4d8}.health-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:10px}.health-card{padding:12px;background:#0b1019;border:1px solid #202a3a;border-radius:10px}.health-card .name{font-weight:750}.health-card .line{display:flex;justify-content:space-between;gap:8px;font-size:12px;margin-top:5px}.timeline{display:grid;gap:8px}.timeline-item{display:grid;grid-template-columns:8px 1fr auto;gap:10px;align-items:center;padding:9px 10px;background:#0b1019;border:1px solid #202a3a;border-radius:9px}.timeline-dot{width:8px;height:8px;border-radius:50%;background:#55d98a}.timeline-dot.warn{background:#efc95f}.timeline-dot.error{background:#ef6b73}.table-wrap{overflow-x:auto;border-radius:14px}.device-state{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px}.device-item{padding:10px;background:#0b1019;border:1px solid #202a3a;border-radius:10px}.device-item .name{font-weight:750}.device-item .line{font-size:12px;display:flex;justify-content:space-between;margin-top:5px}body.device-android{padding:12px}body.device-android main{max-width:100%}body.device-android h1{font-size:26px}body.device-android .card{padding:14px}body.device-android button{min-height:42px}body.device-android input,body.device-android select{min-height:44px}body.device-windows{padding:28px}@media(max-width:560px){.grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.value{font-size:23px}.card{padding:13px}.chart{gap:2px;height:200px}.bar{max-width:12px}.bar-label{font-size:8px;transform:rotate(-35deg);transform-origin:top left}.section-head{align-items:flex-start;flex-direction:column}.hero-badge{white-space:normal}.timeline-item{grid-template-columns:8px minmax(0,1fr);}.timeline-item>strong{grid-column:2}}.app-shell{display:flex;min-height:calc(100vh - 48px);max-width:1500px;margin:auto}.sidebar{width:245px;flex:0 0 245px;background:rgba(9,14,22,.96);border:1px solid #263248;border-radius:18px;padding:14px;position:sticky;top:24px;height:calc(100vh - 48px);overflow:auto;z-index:50}.sidebar-brand{display:flex;align-items:center;gap:10px;padding:10px 8px 16px;border-bottom:1px solid #202a3a;margin-bottom:12px}.sidebar-brand img{width:30px;height:30px}.nav-label{font-size:10px;text-transform:uppercase;letter-spacing:1.3px;color:#66758c;font-weight:800;padding:10px}.nav-btn{width:100%;display:flex;align-items:center;gap:10px;text-align:left;background:transparent;color:#aebbd0;border:1px solid transparent;padding:10px 11px;margin:2px 0}.nav-btn:hover{background:#111b29;border-color:#24334a;transform:none}.nav-btn.active{background:#162238;border-color:#2d405c;color:#e8edf7}.nav-btn img{width:18px;height:18px}.app-content{min-width:0;flex:1;padding-left:16px}.page-view{display:none}.page-view.active{display:block}.sidebar-toggle{display:none}@media(max-width:900px){.app-shell{display:block}.sidebar{position:fixed;left:12px;top:12px;bottom:12px;height:auto;width:270px;transform:translateX(-120%);transition:transform .2s;box-shadow:0 20px 60px rgba(0,0,0,.5)}.sidebar.open{transform:translateX(0)}.sidebar-toggle{display:flex;position:fixed;left:18px;top:18px;width:44px;height:44px;z-index:60;align-items:center;justify-content:center;background:#162238;color:#e8edf7;border:1px solid #30415a;border-radius:11px}.sidebar-toggle svg{width:22px;height:22px}.app-content{padding-left:0}.hero{padding-top:72px}}</style>
</head>
<body>
<button class="sidebar-toggle" id="sidebar-toggle" aria-label="Open navigation" onclick="toggleSidebar()"><svg viewBox="0 0 24 24" fill="none"><path d="M4 6h16M4 12h16M4 18h16" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg></button><div class="app-shell"><aside class="sidebar" id="sidebar"><div class="sidebar-brand"><img src="/assets/icons/dashboard.svg" alt=""><div><strong>Sentinel</strong><div class="muted" style="font-size:11px">Security Console</div></div></div><div class="nav-label">Monitor</div><button class="nav-btn active" data-page="overview" onclick="showPage('overview')"><img src="/assets/icons/overview.svg" alt="">Overview</button><button class="nav-btn" data-page="analytics" onclick="showPage('analytics')"><img src="/assets/icons/features.svg" alt="">Analytics</button><button class="nav-btn" data-page="devices" onclick="showPage('devices')"><img src="/assets/icons/project.svg" alt="">Devices</button><div class="nav-label">Security</div><button class="nav-btn" data-page="security" onclick="showPage('security')"><img src="/assets/icons/security.svg" alt="">Security</button><button class="nav-btn" data-page="profiles" onclick="showPage('profiles')"><img src="/assets/icons/config.svg" alt="">Profiles & Config</button><div class="nav-label">Operations</div><button class="nav-btn" data-page="notifications" onclick="showPage('notifications')"><img src="/assets/icons/security.svg" alt="">Notifications</button><button class="nav-btn" data-page="operations" onclick="showPage('operations')"><img src="/assets/icons/process.svg" alt="">Control Center</button><button class="nav-btn" data-page="data" onclick="showPage('data')"><img src="/assets/icons/storage.svg" alt="">Data & Recovery</button></aside><div class="app-content"><main>
<div class="panel hero">
<div class="hero-copy"><div class="eyebrow">Security Operations Console</div><h1>NextDNS Sentinel</h1><div class="muted">Local monitoring, alerting and profile control</div></div>
<div class="hero-badge"><span id="hero-dot" class="dot"></span><span id="hero-status">Checking monitor</span><div id="device-info" class="device-badge" style="margin-top:7px">Detecting device…</div></div>
</div>

<div class="panel">
<div class="row"><strong>Monitor:</strong><span id="runtime" class="muted">Checking...</span></div>
<button class="start" onclick="controlMonitor('start')">Start Monitoring</button>
<button class="stop" onclick="controlMonitor('stop')">Stop Monitoring</button>
<div class="status" id="health">Loading health...</div>
</div>

<div class="panel">
<div class="section-head"><div><h2>Profile Health</h2><div class="muted">Live monitoring status for every configured profile</div></div><span id="health-count" class="pill">0 profiles</span></div>
<div id="profile-health" class="health-grid"><div class="muted">Loading...</div></div>
</div>

<div class="panel"><div class="section-head"><div><h2>Device Activity</h2><div class="muted">Last observed DNS activity; inactivity does not prove DNS was disabled.</div></div><span id="device-count" class="pill">0 devices</span></div><div id="device-activity" class="device-state"><div class="muted">Loading...</div></div></div>
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
<h2>Advanced Profile API Control</h2>
<div class="muted">Scoped controls for profile configuration exposed directly through the NextDNS API. Send only the fields you intend to change.</div>
<div class="row"><select id="config-profile"></select><select id="config-section"><option value="profile">Profile</option><option value="security">Security</option><option value="privacy">Privacy</option><option value="parentalControl">Parental Control</option><option value="settings">Settings</option></select></div>
<textarea id="config-json" rows="10" style="width:100%;background:#0b1019;color:#e8edf7;border:1px solid #303b4e;border-radius:9px;padding:10px;font-family:monospace"></textarea>
<button class="neutral" onclick="loadConfigSection()">Load Live Config</button><button class="start" onclick="saveConfigSection()">Apply API Change</button>
<div class="status" id="config-status">Select a profile and load its live configuration.</div>
</div>
<div class="panel">
<h2>Telegram Alerts</h2>
<form id="telegram-form">
<label>Bot token<input name="token" type="password" placeholder="123456:ABC..."></label>
<label>Chat ID<input name="chat_id" placeholder="Telegram chat ID"></label>
<button class="start" type="submit">Save Telegram</button>
<button class="neutral" type="button" onclick="testTelegram()">Send Test</button>
<button class="stop" type="button" onclick="disableTelegram()">Disable</button>
<button class="neutral" type="button" onclick="editTelegram()">Edit Bot</button>
</form>
<div class="status" id="telegram-status">Checking...</div>
<div id="telegram-editor" class="editor hidden">
<strong>Edit Telegram Bot</strong>
<form id="telegram-edit-form">
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
<div class="section-head"><div><h2>Alert Activity</h2><div class="muted">Last 24 hours · hourly event volume</div></div><span id="analytics-total" class="pill">0 alerts</span></div>
<div id="alert-chart" class="chart"></div>
</div>
<div class="panel">
<div class="section-head"><div><h2>Top Domains</h2><div class="muted">Most frequent recent alerts</div></div></div>
<div id="top-domains" class="mini-list"><div class="muted">Loading...</div></div>
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
<div class="row"><input id="global-search" placeholder="Search domain, reason, profile, action…"><button class="neutral" onclick="runGlobalSearch()">Search</button></div>
<div id="search-results" class="mini-list"><div class="muted">Enter a query to search.</div></div>
</div>

<div class="panel">
<div class="section-head"><div><h2>Audit & Delivery Center</h2><div class="muted">Dashboard actions and Telegram delivery history</div></div></div>
<div class="row"><button class="neutral" onclick="loadAudit()">Audit Log</button><button class="neutral" onclick="loadDelivery()">Telegram Delivery</button><button class="neutral" onclick="loadBulkHistory()">Bulk Operations</button><button class="neutral" onclick="exportJson()">Export JSON</button><button class="neutral" onclick="exportCsv()">Export CSV</button></div>
<div id="operations-center" class="mini-list"><div class="muted">Choose a history view.</div></div>
</div>

<div class="panel">
<h2>Denylist Control</h2><div class="muted">Add or remove a domain through the NextDNS API. Bulk operations report each profile separately.</div>
<div class="row"><input id="deny-domain" placeholder="example.com"><button class="start" onclick="bulkDeny('add')">Add to all profiles</button><button class="stop" onclick="bulkDeny('remove')">Remove from all profiles</button></div>
<div class="status" id="bulk-result">Ready.</div>
</div>
<div class="panel">
<h2>Local Denylist Cache</h2>
<p class="muted">This list is synchronized automatically from each monitored NextDNS profile.</p>
<div id="denylist">Select a profile to view its cached entries.</div>
</div>

<div class="panel">
<div class="section-head"><div><h2>Export & Backup</h2><div class="muted">Export investigation data or create a full SQLite backup</div></div></div>
<div class="row"><button class="neutral" onclick="exportJson()">Export JSON</button><button class="neutral" onclick="exportCsv()">Export CSV</button><button class="neutral" onclick="downloadBackup()">Download SQLite Backup</button></div>
<form id="restore-form" style="margin-top:8px"><label>Restore SQLite backup</label><input id="restore-file" type="file" accept=".db,.sqlite,.sqlite3"><button class="stop" type="submit">Restore Backup</button></form>
<div class="status" id="restore-status">Restoring replaces the current local database. Keep a backup first.</div>
</div>

<div class="panel">
<div class="section-head"><div><h2>Sentinel Control Center</h2><div class="muted">Operational controls, alert policy, diagnostics and safe maintenance</div></div><span id="live-pill" class="pill">Live</span></div>
<div class="row">
<select id="analytics-range" onchange="loadRangeAnalytics()"><option value="1">1 hour</option><option value="6">6 hours</option><option value="24" selected>24 hours</option><option value="168">7 days</option><option value="720">30 days</option></select>
<button class="neutral" onclick="loadControlCenter()">Refresh Control Center</button>
<button class="neutral" onclick="exportSettings()">Export Settings</button>
<label class="neutral" style="display:inline-flex;align-items:center;gap:6px;cursor:pointer">Import Settings<input id="settings-import" type="file" accept=".json,application/json" hidden onchange="importSettings(this)"></label>
</div>
<div id="control-summary" class="mini-list"><div class="muted">Loading...</div></div>
<div class="grid">
<div class="panel"><h3>Alert Rules</h3><div class="row"><input id="rule-name" placeholder="Rule name"><input id="rule-json" placeholder='{"action":"suppress","domain":"example.com"}'><button class="start" onclick="saveRule()">Save Rule</button></div><div id="rules-list" class="mini-list"></div></div>
<div class="panel"><h3>Maintenance / Suppression</h3><div class="row"><input id="maintenance-seconds" type="number" min="60" value="3600"><input id="maintenance-reason" placeholder="Reason"><button class="neutral" onclick="enableMaintenance()">Enable Maintenance</button></div><div class="row"><input id="suppression-fingerprint" placeholder="Fingerprint"><input id="suppression-seconds" type="number" min="30" value="600"><button class="neutral" onclick="addSuppression()">Suppress</button></div></div>
</div>
<div class="row"><button class="neutral" onclick="toggleSafeMode()">Toggle Safe Mode</button><button class="neutral" onclick="loadDiagnostics()">Diagnostics</button><button class="neutral" onclick="loadIncidentMetrics()">Incident Metrics</button><input id="retention-days" type="number" min="1" value="30" style="max-width:120px"><button class="neutral" onclick="runRetention()">Cleanup Database</button><button class="neutral" onclick="showConfigDiff()">Latest Config Diff</button><button class="neutral" onclick="loadRiskBaseline()">Risk / Baseline</button><button class="neutral" onclick="loadRateLimits()">Rate Limits</button><input id="api-auth-token" type="password" placeholder="API token (16+ chars)"><button class="neutral" onclick="configureApiAuth()">Enable/Login API Auth</button><button class="neutral" onclick="logoutApiAuth()">Logout</button></div>
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
<div class="section-head"><div><h2>Recent Alerts</h2><div class="muted">Search and inspect the latest security events</div></div><span id="alerts-count" class="pill">0 shown</span></div>
<input id="alert-search" type="search" placeholder="Search domain, account, reason, status…" autocomplete="off">
<div class="table-wrap"><table>
<thead><tr><th>Event Time</th><th>Account</th><th>Device</th><th>Domain</th><th>Severity</th><th>Risk</th><th>Status</th><th>Reason</th><th>Notification</th><th>Seen</th></tr></thead>
<tbody id="alerts"></tbody>
</table></div>
</div>
</main>
<script>
function formatDateTime(value){
 if(!value)return '—';
 const d=new Date(value);
 if(Number.isNaN(d.getTime()))return String(value);
 return new Intl.DateTimeFormat(undefined,{dateStyle:'medium',timeStyle:'medium'}).format(d);
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
async function loadDeviceDetail(profileId,deviceId){
 try{
  const d=await api('/api/devices/'+encodeURIComponent(profileId)+'/'+encodeURIComponent(deviceId));
  const box=document.getElementById('operations-center');box.replaceChildren();
  const title=document.createElement('div');title.className='mini-item';title.innerHTML='<strong></strong><span></span>';
  title.firstChild.textContent=(d.device?.device_name||deviceId)+' investigation';
  title.lastChild.textContent='Profile '+profileId;
  box.append(title);
  for(const a of d.alerts||[]){const row=document.createElement('div');row.className='mini-item';row.innerHTML='<span></span><strong></strong>';row.firstChild.textContent=(a.severity||'medium').toUpperCase()+' · '+(a.domain||a.alert_type);row.lastChild.textContent=formatDateTime(a.event_timestamp||a.created_at);row.title=a.reason||'';box.append(row);}
  box.scrollIntoView({behavior:'smooth',block:'nearest'});
 }catch(e){setText('operations-center',e.message,'error');}
}
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
document.getElementById('restore-form').addEventListener('submit',async e=>{
 if(!confirm('Restore the selected SQLite backup? Sentinel will create a rollback copy first.')){e.preventDefault();return;}
 e.preventDefault();const file=document.getElementById('restore-file').files[0];if(!file){setText('restore-status','Select a backup file first.','error');return;}
 if(!confirm('Restore this SQLite backup? Current local data will be replaced.'))return;
 const form=new FormData();form.append('backup',file);
 try{await api('/api/restore',{method:'POST',body:form,headers:{}});setText('restore-status','Backup restored successfully.','ok');refresh();}catch(err){setText('restore-status',err.message,'error');}
});


function renderAnalytics(data){
 const chart=document.getElementById('alert-chart');chart.replaceChildren();
 const points=data.timeline||[];const max=Math.max(1,...points.map(x=>x.count));
 for(const point of points){
  const wrap=document.createElement('div');wrap.className='bar-wrap';wrap.title=formatDateTime(point.time)+': '+point.count+' alert(s)';
  const value=document.createElement('span');value.className='bar-value';value.textContent=point.count?point.count:'';value.style.display=point.count?'block':'none';
  const bar=document.createElement('div');bar.className='bar';bar.style.height=(point.count?Math.max(4,(point.count/max)*100):2)+'%';
  const label=document.createElement('span');label.className='bar-label';label.textContent=new Date(point.time).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
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
  const c=document.createElement('div');c.className='device-item';
  c.style.cursor='pointer';c.title='Open device investigation details';
  c.onclick=()=>loadDeviceDetail(x.profile_id,x.device_id);
  const n=document.createElement('div');n.className='name';n.textContent=x.device_name||x.device_id||'Unidentified device';
  const last=x.last_seen_at?new Date(x.last_seen_at).getTime():0;const active=last&&now-last<=180000;
  const l=document.createElement('div');l.className='line';l.innerHTML='<span>Activity</span><strong></strong>';l.lastChild.textContent=active?'Active recently':'No recent DNS activity';l.lastChild.className=active?'ok':'error';
  const t=document.createElement('div');t.className='line';t.innerHTML='<span>Last seen</span><span></span>';t.lastChild.textContent=formatDateTime(x.last_seen_at);
  const m=document.createElement('div');m.className='line';m.innerHTML='<span>Model</span><span></span>';m.lastChild.textContent=x.device_model||'—';
  c.append(n,l,t,m);box.append(c);
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
  const value=document.createElement('strong');value.className=item.last_error?'error':(item.active?'ok':'muted');value.textContent=item.last_error?'Error':(item.active?'Healthy':'Idle');
  status.append(label,value);
  const poll=document.createElement('div');poll.className='line';poll.innerHTML='<span>Last success</span><span></span>';poll.lastChild.textContent=formatDateTime(item.last_success_at);
  const err=document.createElement('div');err.className='line';err.innerHTML='<span>Last error</span><span></span>';err.lastChild.textContent=item.last_error?formatDateTime(item.last_error_at):'None';
  card.append(name,status,poll,err);box.append(card);
 }
}
function renderTimeline(health,alerts){
 const box=document.getElementById('event-timeline');box.replaceChildren();
 const events=[];
 for(const item of health||[]){
  if(item.last_success_at)events.push({time:item.last_success_at,title:(item.name||item.profile_id)+' poll succeeded',detail:'Monitoring checkpoint',kind:'ok'});
  if(item.last_error_at&&item.last_error)events.push({time:item.last_error_at,title:(item.name||item.profile_id)+' monitor error',detail:item.last_error,kind:'error'});
 }
 for(const alert of (alerts||[]).slice(0,8)){
  if(alert.event_timestamp)events.push({time:alert.event_timestamp,title:alert.domain||'Alert',detail:(alert.reason||'Security event')+' · '+(alert.status||'unknown'),kind:'warn'});
 }
 events.sort((a,b)=>new Date(b.time)-new Date(a.time));
 setText('timeline-count',events.length+' events','');
 if(!events.length){box.textContent='No timeline events available yet.';return;}
 for(const event of events.slice(0,12)){
  const row=document.createElement('div');row.className='timeline-item';
  const dot=document.createElement('span');dot.className='timeline-dot '+event.kind;
  const middle=document.createElement('div');const title=document.createElement('strong');title.textContent=event.title;const detail=document.createElement('div');detail.className='muted';detail.textContent=event.detail;middle.append(title,detail);
  const time=document.createElement('span');time.className='muted';time.textContent=formatDateTime(event.time);time.title=event.time;
  row.append(dot,middle,time);box.append(row);
 }
}
function filterAlerts(){
 const q=(document.getElementById('alert-search').value||'').toLowerCase().trim();
 let shown=0;
 document.querySelectorAll('#alerts tr').forEach(row=>{
  const match=!q||row.textContent.toLowerCase().includes(q);
  row.style.display=match?'':'none';if(match)shown++;
 });
 setText('alerts-count',shown+' shown','');
}
function setText(id,text,cls=''){const e=document.getElementById(id);e.textContent=text;e.className=cls;}
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
    return d;
  }catch(e){
    if(e instanceof TypeError)throw new Error('Dashboard could not reach the local API. Make sure Sentinel is running and try again.');
    throw e;
  }
}
async function controlMonitor(action){try{const d=await api('/api/monitor/'+action,{method:'POST'});setText('runtime',d.running?'Running':'Stopped',d.running?'ok':'muted');refresh();}catch(e){setText('runtime',e.message,'error');}}
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
document.getElementById('account-form').addEventListener('submit',e=>{e.preventDefault();discoverProfiles();});
document.getElementById('telegram-form').addEventListener('submit',async e=>{
 e.preventDefault();const d=Object.fromEntries(new FormData(e.target).entries());
 try{await api('/api/settings/telegram',{method:'POST',body:JSON.stringify(d)});setText('telegram-status','Telegram configured and encrypted locally.','ok');e.target.reset();refresh();}
 catch(err){setText('telegram-status',err.message,'error');}
});
async function testTelegram(){try{await api('/api/settings/telegram/test',{method:'POST'});setText('telegram-status','Test notification sent.','ok');}catch(e){setText('telegram-status',e.message,'error');}}
async function disableTelegram(){try{await api('/api/settings/telegram',{method:'DELETE'});closeTelegramEditor();setText('telegram-status','Telegram disabled.','muted');}catch(e){setText('telegram-status',e.message,'error');}}
async function editTelegram(){
 try{
  const d=await api('/api/settings/telegram');
  const form=document.getElementById('telegram-edit-form');
  form.elements.chat_id.value=d.chat_id||'';
  form.elements.token.value='';
  document.getElementById('telegram-editor').classList.remove('hidden');
  setText('telegram-edit-message',d.configured?'Current Telegram bot settings loaded.':'Telegram is not configured.','muted');
  document.getElementById('telegram-editor').scrollIntoView({behavior:'smooth',block:'nearest'});
 }catch(e){setText('telegram-status',e.message,'error');}
}
function closeTelegramEditor(){
 document.getElementById('telegram-editor').classList.add('hidden');
 document.getElementById('telegram-edit-form').reset();
 setText('telegram-edit-message','','');
}
document.getElementById('telegram-edit-form').addEventListener('submit',async e=>{
 e.preventDefault();
 const d=Object.fromEntries(new FormData(e.target).entries());
 try{
  await api('/api/settings/telegram',{method:'POST',body:JSON.stringify(d)});
  closeTelegramEditor();
  setText('telegram-status','Telegram bot updated and encrypted locally.','ok');
  refresh();
 }catch(err){setText('telegram-edit-message',err.message,'error');}
});

let editingProfileId='';

async function editProfile(id){
  editingProfileId=id;
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
  }catch(e){setText('profile-edit-message',e.message,'error');}
}
function closeProfileEditor(){
  editingProfileId='';
  document.getElementById('profile-editor').classList.add('hidden');
  document.getElementById('profile-edit-form').reset();
  setText('profile-edit-message','','');
}
document.getElementById('profile-edit-form').addEventListener('submit',async e=>{
  e.preventDefault();
  if(!editingProfileId)return;
  const data=Object.fromEntries(new FormData(e.target).entries());
  try{
    await api('/api/accounts/'+encodeURIComponent(editingProfileId),{method:'PATCH',body:JSON.stringify(data)});
    closeProfileEditor();
    refresh();
  }catch(err){setText('profile-edit-message',err.message,'error');}
});

async function deleteAccount(id){if(!confirm('Delete this profile and its local state?'))return;try{await api('/api/accounts/'+encodeURIComponent(id),{method:'DELETE'});refresh();}catch(e){alert(e.message);}}
async function toggleAccount(id,active){try{await api('/api/accounts/'+encodeURIComponent(id)+'/toggle',{method:'POST',body:JSON.stringify({active})});refresh();}catch(e){alert(e.message);}}
async function showDenylist(id){
 try{const list=await api('/api/denylist/'+encodeURIComponent(id));const box=document.getElementById('denylist');box.replaceChildren();
 const h=document.createElement('div');h.textContent=list.length+' cached entries';box.append(h);
 for(const d of list.slice(0,200)){const x=document.createElement('div');x.textContent=d;box.append(x);}
 }catch(e){setText('denylist',e.message,'error');}
}
async function bulkDeny(action){
 if(!confirm((action==='add'?'Add':'Remove')+' this domain across all active profiles?'))return;
 const domain=document.getElementById('deny-domain').value.trim();if(!domain){setText('bulk-result','Enter a domain.','error');return;}
 try{const d=await api('/api/denylist/bulk',{method:'POST',body:JSON.stringify({domain,action})});setText('bulk-result',action.toUpperCase()+': '+d.successes+' succeeded, '+d.failures+' failed, '+d.skipped+' skipped.','ok');refresh();}catch(e){setText('bulk-result',e.message,'error');}
}
async function loadConfigChanges(){
 try{
  const items=await api('/api/config-changes');const box=document.getElementById('config-changes');box.replaceChildren();
  if(!items.length){box.textContent='No configuration changes detected.';return;}
  for(const x of items.slice(0,20)){
   const row=document.createElement('div');row.className='account';
   const title=document.createElement('div');title.textContent=x.profile_id+' · '+x.change_type+' · '+formatDateTime(x.changed_at);
   const b=document.createElement('button');b.className='neutral';b.textContent=x.undone_at?'Undone':'Undo';b.disabled=!!x.undone_at;b.onclick=async()=>{try{await api('/api/config-changes/'+x.id+'/undo',{method:'POST'});refresh()}catch(e){alert(e.message)}};row.append(title,b);box.append(row);
  }
 }catch(e){}
}
async function loadConfigSection(){
 const id=document.getElementById('config-profile').value;const section=document.getElementById('config-section').value;if(!id)return;
 try{const d=await api('/api/profiles/'+encodeURIComponent(id)+'/config/'+encodeURIComponent(section));document.getElementById('config-json').value=JSON.stringify(d,null,2);setText('config-status','Live configuration loaded.','ok');}catch(e){setText('config-status',e.message,'error');}
}
async function saveConfigSection(){
 const id=document.getElementById('config-profile').value;const section=document.getElementById('config-section').value;let data;
 try{data=JSON.parse(document.getElementById('config-json').value)}catch(e){setText('config-status','Invalid JSON.','error');return;}
 if(!confirm('Apply this configuration through the NextDNS API?'))return;
 try{await api('/api/profiles/'+encodeURIComponent(id)+'/config/'+encodeURIComponent(section),{method:'PATCH',body:JSON.stringify(data)});setText('config-status','Change applied successfully.','ok');loadConfigChanges();}catch(e){setText('config-status',e.message,'error');}
}
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
document.getElementById('save-alert-logs').addEventListener('change',e=>setAlertLogSaving(e.target.checked));

async function refresh(){
 try{
  const rt=await api('/api/runtime');setText('runtime',rt.running?'Running':'Stopped',rt.running?'ok':'muted');
  setText('telegram-status',rt.telegram_configured?'Telegram configured.':'Telegram not configured.',rt.telegram_configured?'ok':'muted');
  const s=await api('/api/stats');const stats=document.getElementById('stats');stats.replaceChildren();
  const cards=[
    ['Monitored Profiles',s.accounts],['Active Profiles',s.active_accounts],['Alerts Total',s.alerts],['Denylist Entries',s.denylist_entries],['Poll Interval',s.poll_interval_seconds+'s']
  ];
  for(const [label,value] of cards){const card=document.createElement('div');card.className='card';const l=document.createElement('div');l.className='muted';l.textContent=label;const val=document.createElement('div');val.className='value';val.textContent=value;card.append(l,val);stats.append(card);}
  const analytics=await api('/api/analytics');renderAnalytics(analytics);renderIntelligence(analytics);loadIncidents();loadDomains();loadSentinelHealth();
  const health=document.getElementById('health');health.className='status '+(s.last_error?'error':'ok');health.textContent=s.last_error?'Monitor error: '+s.last_error+' · '+formatDateTime(s.last_error_at):'Monitor healthy · Last successful poll: '+formatDateTime(s.last_success_at);
  const heroDot=document.getElementById('hero-dot');heroDot.className='dot '+(s.last_error?'':'ok');setText('hero-status',s.last_error?'Attention required':'Monitoring healthy',s.last_error?'error':'ok');
  const healthData=await api('/api/health');renderProfileHealth(healthData);
  const devices=await api('/api/devices');renderDevices(devices);
  const accounts=await api('/api/accounts');const box=document.getElementById('accounts');box.replaceChildren();
  if(!accounts.length){box.textContent='No profiles configured. Add one above.';}
  for(const a of accounts){const row=document.createElement('div');row.className='account';
   const title=document.createElement('div');title.textContent=a.name+' · '+a.profile_id+' · '+(a.active?'Active':'Inactive');row.append(title);
   const b=document.createElement('button');b.className=a.active?'stop':'start';b.textContent=a.active?'Disable':'Enable';b.onclick=()=>toggleAccount(a.profile_id,!a.active);row.append(b);
   const v=document.createElement('button');v.className='neutral';v.textContent='View Denylist';v.onclick=()=>showDenylist(a.profile_id);row.append(v);
   const edit=document.createElement('button');edit.className='neutral';edit.textContent='Edit';edit.onclick=()=>editProfile(a.profile_id);row.append(edit);
   const del=document.createElement('button');del.className='stop';del.textContent='Delete';del.onclick=()=>deleteAccount(a.profile_id);row.append(del);box.append(row);
  }
  const cfgSelect=document.getElementById('config-profile');cfgSelect.replaceChildren();for(const a of accounts){const o=document.createElement('option');o.value=a.profile_id;o.textContent=a.name+' ('+a.profile_id+')';cfgSelect.append(o);}
  const alerts=await api('/api/alerts');const body=document.getElementById('alerts');body.replaceChildren();
  renderTimeline(healthData,alerts);
  for(const x of alerts){
   const tr=document.createElement('tr');if(!x.seen_at)tr.style.background='rgba(53,199,111,.10)';
   const vals=[x.event_timestamp,x.account_name,x.device_name||x.device_id||'Unidentified',x.domain,x.severity||'—',(x.risk_score??'—')+'/100',x.status,x.reason,x.notification_status];
   vals.forEach((v,i)=>{const td=document.createElement('td');if(i===0)formatTimestampCell(td,v);else td.textContent=v??'';tr.append(td);});
   const td=document.createElement('td');const b=document.createElement('button');b.className='neutral';b.textContent=x.seen_at?'Seen':'NEW';b.onclick=async()=>{await api('/api/alerts/'+x.id+'/seen',{method:'POST'});refresh()};td.append(b);tr.append(td);body.append(tr);
  }
  filterAlerts();
 }catch(e){setText('health','Dashboard error: '+e.message,'error');}
}
setupDashboardPages();showPage('overview');detectDevice();window.addEventListener('resize',detectDevice);document.getElementById('alert-search').addEventListener('input',filterAlerts);loadAlertLogSettings();loadConfigChanges();loadControlCenter();refresh();setInterval(()=>{refresh();loadConfigChanges();loadControlCenter()},5000);
function setupDashboardPages(){
 const map={
  overview:['stats','health','profile-health','event-timeline','hero-dot','runtime'],
  analytics:['alert-chart','risk-overview','sentinel-health'],
  devices:['device-activity'],
  security:['incidents','domain-intelligence','global-search','operations-center','alerts','alert-search'],
  profiles:['account-form','config-changes','config-section','denylist','deny-domain'],
  notifications:['telegram-form'],
  operations:['control-summary','rule-name','maintenance-seconds','control-details'],
  data:['restore-file','save-alert-logs']
 };
 document.querySelectorAll('.panel').forEach(p=>{p.dataset.page='';for(const [page,ids] of Object.entries(map)){if(ids.some(id=>p.querySelector('#'+id))){p.dataset.page=page;break}}});
 const stats=document.getElementById('stats');if(stats)stats.dataset.page='overview';
}
function showPage(page){
 setupDashboardPages();
 document.querySelectorAll('.panel[data-page]').forEach(p=>{p.style.display=p.dataset.page===page?'block':'none'});document.querySelectorAll('.panel[data-page=""]').forEach(p=>p.style.display='none');
 const stats=document.getElementById('stats');if(stats)stats.style.display=page==='overview'?'grid':'none';
 document.querySelectorAll('.nav-btn').forEach(b=>b.classList.toggle('active',b.dataset.page===page));
 if(page==='analytics'){loadRangeAnalytics();loadRiskBaseline();}
 if(page==='operations')loadControlCenter();
 if(page==='security'){loadIncidents();loadDomains();}
 if(page==='devices')refresh();
 if(page==='profiles')loadConfigChanges();

 if(page==='data')loadAlertLogSettings();
 if(window.innerWidth<=900)toggleSidebar(false);
}
function toggleSidebar(force){
 const s=document.getElementById('sidebar');if(!s)return;
 const open=typeof force==='boolean'?force:!s.classList.contains('open');s.classList.toggle('open',open);
}
async function loadRiskBaseline(){try{const [risk,base]=await Promise.all([api('/api/risk-history?days=30'),api('/api/baseline')]);const riskText=risk.slice(-10).map(x=>x.day+': avg '+Number(x.avg_risk||0).toFixed(1)+' · max '+x.max_risk+' · '+x.alerts+' alerts').join(' | ');const baseText=base.slice(0,12).map(x=>x.bucket_hour+':00 '+Number(x.baseline||0).toFixed(1)+' avg').join(' · ');setText('control-details','Risk history: '+(riskText||'No data')+' || Baseline: '+(baseText||'No data'),'muted')}catch(e){setText('control-details',e.message,'error')}}
async function runRetention(){const days=Math.max(1,Number(document.getElementById('retention-days').value)||30);if(!confirm('Clean Sentinel data older than '+days+' days?'))return;try{const d=await api('/api/retention',{method:'POST',body:JSON.stringify({days})});setText('control-details','Retention cleanup removed '+d.deleted+' records.','ok');}catch(e){setText('control-details',e.message,'error')}}
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
  for(const r of d.rules||[]){const x=document.createElement('div');x.className='mini-item';x.innerHTML='<span></span><button class="stop">Delete</button>';x.firstChild.textContent=r.name+' · '+(r.enabled?'Enabled':'Disabled');x.lastChild.onclick=async()=>{await api('/api/rules/'+r.id,{method:'DELETE'});loadControlCenter()};rl.append(x);}
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
</script>
</body>
</html>"""

def request_json() -> dict[str, Any]:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def create_app(store: Store, sentinel: Sentinel, features: FeatureStore) -> Flask:
    app = Flask(__name__)
    app.secret_key = SECRET_KEY
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")

    # Keep dashboard navigation icons self-contained so the single-file app does
    # not depend on a separate static-assets directory.
    dashboard_icons = {
        "dashboard.svg": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>',
        "overview.svg": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.7"/></svg>',
        "features.svg": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 19V9M10 19V5M16 19v-7M22 19V3"/><path d="M2 19h21"/></svg>',
        "project.svg": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="4" y="3" width="16" height="18" rx="2"/><path d="M9 7h6M8 17h8M8 13h3"/></svg>',
        "security.svg": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 3 20 6v5c0 5-3.2 8.3-8 10-4.8-1.7-8-5-8-10V6l8-3Z"/><path d="m8.5 12 2.2 2.2 4.8-5"/></svg>',
        "config.svg": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 6h16M4 12h16M4 18h16"/><circle cx="9" cy="6" r="2"/><circle cx="15" cy="12" r="2"/><circle cx="11" cy="18" r="2"/></svg>',
        "process.svg": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="4" width="7" height="5" rx="1"/><rect x="14" y="15" width="7" height="5" rx="1"/><path d="M10 6.5h3a3 3 0 0 1 3 3V15M16 12l3 3-3 3"/></svg>',
        "storage.svg": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v7c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 12v7c0 1.7 3.6 3 8 3s8-1.3 8-3v-7"/></svg>',
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

    @app.get("/api/config-changes")
    def api_config_changes() -> Any:
        return jsonify(store.config_changes())

    @app.post("/api/config-changes/<int:change_id>/undo")
    def api_config_undo(change_id:int) -> Any:
        changes=store.config_changes(200)
        change=next((x for x in changes if x["id"]==change_id),None)
        if not change: return jsonify({"error":"Change not found."}),404
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
            store.mark_change_undone(change_id)
            store.save_config_snapshot(change["profile_id"],before)
            features.audit("configuration_undo","profile",change["profile_id"],change["profile_id"],{"change_id":change_id,"fields":sorted(rollback)})
            key=hashlib.sha256(f"config_undo:{change['profile_id']}:{change_id}:{utc_now()}".encode()).hexdigest()
            store.add_alert(change["profile_id"],account["name"],"","",f"Configuration change #{change_id} was undone","configuration_undo","",utc_now(),key,"configuration_action",source="sentinel_dashboard")
            alert_id=sentinel.enrich_alert(key,account,"",f"Configuration change #{change_id} was undone","configuration_undo","","",utc_now(),"","","","",False)
            delivered=sentinel.notify(account,"",f"Configuration change #{change_id} was undone","configuration_undo","",event_time=utc_now(),alert_id=alert_id)
            if delivered: store.mark_alert_notified(key)
            else: store.mark_notification_failed(key)
            return jsonify({"undone":True,"alert_id":alert_id})
        except Exception as exc: return jsonify({"error":str(exc)}),400

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

    @app.get("/api/settings/telegram")
    def api_telegram_settings() -> Any:
        return jsonify({
            "configured": bool(
                sentinel.telegram_token and sentinel.telegram_chat_id
            )
        })

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
        allowed={"profile","security","privacy","parentalControl","settings"}
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
        try:
            client=NextDNSClient(account["api_key"])
            before=config_snapshot(client.profile(profile_id))
            path=f"/profiles/{profile_id}" if section=="profile" else f"/profiles/{profile_id}/{section}"
            result=client._patch(path,data)
            live=client.profile(profile_id); after=config_snapshot(live)
            if before!=after:
                change_type=config_change_summary(before,after)
                change_id=store.add_config_change(profile_id,before,after,change_type)
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
        was_running = sentinel.is_running()
        try:
            client = NextDNSClient(api_key)
            profile_response = client._get(f"/profiles/{profile_id}")
            profile = profile_response.get("data", profile_response)
            if not isinstance(profile, dict):
                raise NextDNSError("NextDNS returned an unexpected profile response.")
            current_profile_name = str(profile.get("name") or profile_id)
            if profile_name != current_profile_name:
                client.update_profile_name(profile_id, profile_name)
            client.denylist(profile_id)
            if was_running:
                sentinel.stop()
            store.upsert_account({
                "profile_id": profile_id,
                "name": display_name,
                "profile_name": profile_name,
                "api_key": api_key,
                "active": bool(account["active"]),
                "added_at": account["added_at"],
            })
            if was_running:
                sentinel.start()
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
            if was_running and not sentinel.is_running():
                try:
                    sentinel.start()
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
            client.denylist(profile_id)
            store.upsert_account({
                "profile_id": profile_id,
                "name": resolved_display,
                "profile_name": resolved_name,
                "api_key": api_key,
                "active": True,
                "added_at": utc_now(),
            })
            if not sentinel.is_running():
                sentinel.start()
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
            # Restarting is the safest way to drop the account's monitor thread.
            sentinel.stop()
        store.set_account_active(profile_id, active)
        features.audit("profile_monitor_toggle","profile",profile_id,profile_id,{"active":active})
        sentinel.notify_report("Profile monitoring changed",[
            f"Profile: {profile_id}",
            f"Monitoring: {'enabled' if active else 'disabled'}",
        ])
        if active:
            try:
                sentinel.start()
            except RuntimeError as exc:
                return jsonify({"error": str(exc)}), 400
        return jsonify({"active": active, "running": sentinel.is_running()})

    @app.delete("/api/accounts/<profile_id>")
    def api_account_delete(profile_id: str) -> Any:
        if not store.account_exists(profile_id):
            return jsonify({"error": "Account not found."}), 404
        sentinel.stop()
        features.audit("profile_delete","profile",profile_id,profile_id,{"profile_id":profile_id})
        sentinel.notify_report("Profile removed from Sentinel",[
            f"Profile: {profile_id}",
            "Local monitoring state was deleted.",
        ])
        store.delete_account(profile_id)
        remaining = [a for a in store.accounts() if a["active"]]
        if remaining:
            sentinel.start()
        return jsonify({"deleted": True, "running": sentinel.is_running()})

    @app.post("/api/settings/telegram")
    def api_telegram_save() -> Any:
        data = request_json()
        token = str(data.get("token", "")).strip()
        chat_id = str(data.get("chat_id", "")).strip()
        if not token or not chat_id:
            return jsonify({"error": "Telegram bot token and chat ID are required."}), 400
        try:
            validate_telegram_credentials(token, chat_id)
            store.set_secret("telegram_token", token)
            store.set_secret("telegram_chat_id", chat_id)
            sentinel.telegram_token = token
            sentinel.telegram_chat_id = chat_id
            features.audit("telegram_configured","settings","telegram",details={"chat_id":chat_id})
            return jsonify({"configured": True})
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/settings/telegram")
    def api_telegram_get() -> Any:
        token = store.get_secret("telegram_token")
        chat_id = store.get_secret("telegram_chat_id")
        return jsonify({
            "configured": bool(token and chat_id),
            "chat_id": chat_id,
            "token_configured": bool(token),
        })

    @app.delete("/api/settings/telegram")
    def api_telegram_delete() -> Any:
        store.delete_secret("telegram_token")
        store.delete_secret("telegram_chat_id")
        sentinel.telegram_token = ""
        sentinel.telegram_chat_id = ""
        features.audit("telegram_disabled","settings","telegram")
        return jsonify({"configured": False})

    @app.post("/api/settings/telegram/test")
    def api_telegram_test() -> Any:
        if not sentinel.telegram_token or not sentinel.telegram_chat_id:
            return jsonify({"error": "Telegram is not configured."}), 400
        ok = send_telegram(
            sentinel.telegram_token,
            sentinel.telegram_chat_id,
            "NextDNS Sentinel test notification.",
        )
        if not ok:
            return jsonify({"error": "Telegram test notification failed."}), 502
        return jsonify({"sent": True})

    @app.get("/api/risk-history")
    def api_risk_history() -> Any:
        return jsonify(features.risk_history(request.args.get("profile_id",""),int(request.args.get("days","30"))))

    @app.get("/api/baseline")
    def api_baseline() -> Any:
        return jsonify(features.baseline_view(request.args.get("profile_id","")))
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
        return jsonify({
            "rules": features.rules(),
            "maintenance": features.maintenance_active(),
            "safe_mode": store.setting("safe_mode","0")=="1",
            "api_auth": bool(store.setting("api_auth_token","")),
            "diagnostics": features.diagnostics(),
            "rate_limits": features.rate_limit_history(20),
        })

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