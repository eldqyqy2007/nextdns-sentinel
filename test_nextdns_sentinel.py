import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cryptography.fernet import Fernet

os.environ.setdefault("NEXTDNS_SENTINEL_SECRET_KEY", Fernet.generate_key().decode())

import nextdns_sentinel as sentinel


class DomainAndEventTests(unittest.TestCase):
    def test_domain_matching(self) -> None:
        denylist = {"example.com", "*.blocked.test"}

        self.assertEqual(
            sentinel.find_matching_domain("example.com", denylist),
            "example.com",
        )
        self.assertEqual(
            sentinel.find_matching_domain("sub.example.com", denylist),
            "example.com",
        )
        self.assertEqual(
            sentinel.find_matching_domain("api.blocked.test", denylist),
            "*.blocked.test",
        )
        self.assertEqual(
            sentinel.find_matching_domain("other.test", denylist),
            "",
        )

    def test_event_parsing(self) -> None:
        log = {
            "domain": "WWW.Example.COM.",
            "root": "example.com",
            "timestamp": "2026-10-01T00:00:00Z",
            "status": "blocked",
            "reasons": [{"name": "denylist"}, "policy"],
            "clientIp": "192.0.2.10",
        }

        self.assertEqual(sentinel.event_domain(log), "www.example.com")
        self.assertEqual(sentinel.matched_domain(log), "example.com")
        self.assertEqual(sentinel.event_reason(log), "denylist, policy")
        self.assertEqual(sentinel.event_client_ip(log), "192.0.2.10")


class StoreNotificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = sentinel.Store(Path(self.tempdir.name) / "sentinel.db")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _add_alert(self, key: str = "event-1") -> None:
        self.assertTrue(
            self.store.add_alert(
                "profile",
                "Test",
                "example.com",
                "example.com",
                "denylist",
                "blocked",
                "",
                "2026-10-01T00:00:00Z",
                key,
            )
        )

    def test_suppressed_alert_is_not_retried(self) -> None:
        self._add_alert()
        self.store.mark_alert_suppressed("event-1")
        self.assertEqual(self.store.unnotified_alerts("profile"), [])

    def test_failed_alert_uses_retry_state(self) -> None:
        self._add_alert()
        self.store.mark_notification_failed("event-1")

        with sqlite3.connect(self.store.path) as db:
            row = db.execute(
                """
                SELECT notification_attempts, notification_status,
                       last_notification_attempt_at, next_retry_at
                FROM alerts WHERE event_key=?
                """,
                ("event-1",),
            ).fetchone()

        self.assertEqual(row[0], 1)
        self.assertEqual(row[1], "pending")
        self.assertTrue(row[2])
        self.assertTrue(row[3])

    def test_sent_alert_is_not_pending(self) -> None:
        self._add_alert()
        self.store.mark_alert_notified("event-1")
        self.assertEqual(self.store.unnotified_alerts("profile"), [])


if __name__ == "__main__":
    unittest.main()
