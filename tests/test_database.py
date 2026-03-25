"""Tests for database persistence layer."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from lib.database import Database


class TestDatabase:

    def _tmp_db(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        return path

    def test_start_run_returns_id(self):
        path = self._tmp_db()
        try:
            with Database(path) as db:
                run_id = db.start_run(["example.com"])
                assert isinstance(run_id, int)
                assert run_id >= 1
        finally:
            os.unlink(path)

    def test_multiple_runs_increment(self):
        path = self._tmp_db()
        try:
            with Database(path) as db:
                id1 = db.start_run(["a.com"])
                id2 = db.start_run(["b.com"])
                assert id2 > id1
        finally:
            os.unlink(path)

    def test_save_and_get_dns_records(self):
        path = self._tmp_db()
        try:
            with Database(path) as db:
                run_id = db.start_run(["example.com"])
                records = [
                    {"type": "A", "name": "example.com", "content": "1.2.3.4",
                     "ttl": 300, "proxied": True},
                    {"type": "MX", "name": "example.com", "content": "mail.example.com",
                     "ttl": 3600, "proxied": False},
                ]
                db.save_dns_records(run_id, "example.com", records)
                saved = db.get_dns_records(run_id)
                assert len(saved) == 2
                types = {r["type"] for r in saved}
                assert types == {"A", "MX"}
        finally:
            os.unlink(path)

    def test_save_and_get_email_check(self):
        path = self._tmp_db()
        try:
            with Database(path) as db:
                run_id = db.start_run(["example.com"])
                result = {
                    "domain": "example.com",
                    "has_mail": True,
                    "mx": [{"priority": 10, "host": "mail.example.com"}],
                    "spf": {"record": "v=spf1 -all", "grade": "PASS", "reason": "hard fail"},
                    "dmarc": {"record": "v=DMARC1; p=reject", "grade": "PASS",
                              "reason": "reject", "policy": "reject", "rua": None},
                    "dkim": [{"selector": "google", "record": "v=DKIM1; k=rsa; p=..."}],
                }
                db.save_email_check(run_id, result)
                saved = db.get_email_checks(run_id)
                assert len(saved) == 1
                assert saved[0]["spf_grade"] == "PASS"
                assert saved[0]["dmarc_grade"] == "PASS"
                assert len(saved[0]["mx_records"]) == 1
                assert len(saved[0]["dkim_found"]) == 1
        finally:
            os.unlink(path)

    def test_save_and_get_zone_settings(self):
        path = self._tmp_db()
        try:
            with Database(path) as db:
                run_id = db.start_run(["example.com"])
                checks = [
                    {"label": "SSL mode", "recommended": "full (strict)",
                     "actual": "full", "grade": "PASS", "note": "",
                     "explanation": "Validates origin cert"},
                ]
                db.save_zone_settings(run_id, "example.com", checks)
                saved = db.get_zone_settings(run_id)
                assert len(saved) == 1
                assert saved[0]["grade"] == "PASS"
        finally:
            os.unlink(path)

    def test_get_runs(self):
        path = self._tmp_db()
        try:
            with Database(path) as db:
                db.start_run(["a.com"])
                db.start_run(["b.com"])
                runs = db.get_runs()
                assert len(runs) == 2
                # Newest first
                assert "b.com" in runs[0]["domains"]
        finally:
            os.unlink(path)

    def test_context_manager_rollback_on_error(self):
        """Uncommitted writes after start_run are rolled back on error.
        start_run itself commits (the run row persists), but subsequent
        uncommitted inserts should be discarded."""
        path = self._tmp_db()
        try:
            try:
                with Database(path) as db:
                    run_id = db.start_run(["a.com"])
                    # This insert has NOT been committed yet
                    db.save_dns_records(run_id, "a.com", [
                        {"type": "A", "name": "a.com", "content": "1.2.3.4",
                         "ttl": 300, "proxied": False},
                    ])
                    raise ValueError("simulated error")
            except ValueError:
                pass

            with Database(path) as db:
                # The run row persists (committed by start_run)
                runs = db.get_runs()
                assert len(runs) == 1
                # But the DNS records were rolled back
                records = db.get_dns_records(runs[0]["id"])
                assert len(records) == 0
        finally:
            os.unlink(path)
