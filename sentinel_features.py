"""
NextDNS Sentinel intelligence, investigation and audit layer.

This module is deliberately local-first: it stores enrichment and investigation
state in the existing SQLite database and does not require an external service.
"""
from __future__ import annotations

import csv
import io
import json
import math
import re
import sqlite3
import statistics
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any


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
            checks['alerts'] = bool(db.execute("SELECT 1 FROM alerts LIMIT 1").fetchone() is not None)
            checks['tables'] = all(
                db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
                for name in ('alert_metadata','incidents','audit_log','delivery_events','sentinel_health')
            )
            return {"checks":checks,"healthy":all(checks.values()),"checked_at":now_iso()}

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
