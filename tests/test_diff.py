"""Tests for diff computation and formatting."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from lib.diff import compute_diff, format_diff_text
from lib.database import Database


class TestComputeDiff:

    def _tmp_db(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        return path

    def test_first_run_returns_none(self):
        path = self._tmp_db()
        try:
            with Database(path) as db:
                run_id = db.start_run(["example.com"])
                db.save_email_check(run_id, {
                    "domain": "example.com", "has_mail": True,
                    "mx": [], "dkim": [],
                    "spf": {"record": "v=spf1 -all", "grade": "PASS", "reason": "ok"},
                    "dmarc": {"record": "v=DMARC1; p=reject", "grade": "PASS",
                              "reason": "ok", "policy": "reject", "rua": None},
                })
                result = compute_diff(db, run_id)
                assert result is None
        finally:
            os.unlink(path)

    def test_identical_runs_no_changes(self):
        path = self._tmp_db()
        try:
            with Database(path) as db:
                email = {
                    "domain": "example.com", "has_mail": True,
                    "mx": [], "dkim": [],
                    "spf": {"record": "v=spf1 -all", "grade": "PASS", "reason": "ok"},
                    "dmarc": {"record": "v=DMARC1; p=reject", "grade": "PASS",
                              "reason": "ok", "policy": "reject", "rua": None},
                }
                run1 = db.start_run(["example.com"])
                db.save_email_check(run1, email)

                run2 = db.start_run(["example.com"])
                db.save_email_check(run2, email)

                result = compute_diff(db, run2)
                assert result is not None
                assert result["summary"]["regressions"] == 0
                assert result["summary"]["improvements"] == 0
        finally:
            os.unlink(path)

    def test_grade_regression(self):
        path = self._tmp_db()
        try:
            with Database(path) as db:
                run1 = db.start_run(["example.com"])
                db.save_email_check(run1, {
                    "domain": "example.com", "has_mail": True,
                    "mx": [], "dkim": [],
                    "spf": {"record": "v=spf1 -all", "grade": "PASS", "reason": "ok"},
                    "dmarc": {"record": "v=DMARC1; p=reject", "grade": "PASS",
                              "reason": "ok", "policy": "reject", "rua": None},
                })

                run2 = db.start_run(["example.com"])
                db.save_email_check(run2, {
                    "domain": "example.com", "has_mail": True,
                    "mx": [], "dkim": [],
                    "spf": {"record": "v=spf1 ~all", "grade": "FAIL", "reason": "soft"},
                    "dmarc": {"record": "v=DMARC1; p=reject", "grade": "PASS",
                              "reason": "ok", "policy": "reject", "rua": None},
                })

                result = compute_diff(db, run2)
                assert result is not None
                assert result["summary"]["regressions"] >= 1
                regressions = [c for c in result["changes"] if c["direction"] == "regression"]
                checks = [c["check"] for c in regressions]
                assert "SPF" in checks
        finally:
            os.unlink(path)

    def test_grade_improvement(self):
        path = self._tmp_db()
        try:
            with Database(path) as db:
                run1 = db.start_run(["example.com"])
                db.save_email_check(run1, {
                    "domain": "example.com", "has_mail": True,
                    "mx": [], "dkim": [],
                    "spf": {"record": "v=spf1 -all", "grade": "PASS", "reason": "ok"},
                    "dmarc": {"record": "v=DMARC1; p=none", "grade": "FAIL",
                              "reason": "none", "policy": "none", "rua": None},
                })

                run2 = db.start_run(["example.com"])
                db.save_email_check(run2, {
                    "domain": "example.com", "has_mail": True,
                    "mx": [], "dkim": [],
                    "spf": {"record": "v=spf1 -all", "grade": "PASS", "reason": "ok"},
                    "dmarc": {"record": "v=DMARC1; p=reject", "grade": "PASS",
                              "reason": "ok", "policy": "reject", "rua": None},
                })

                result = compute_diff(db, run2)
                assert result is not None
                assert result["summary"]["improvements"] >= 1
                improvements = [c for c in result["changes"] if c["direction"] == "improvement"]
                checks = [c["check"] for c in improvements]
                assert "DMARC" in checks
        finally:
            os.unlink(path)

    def test_dns_record_added(self):
        path = self._tmp_db()
        try:
            with Database(path) as db:
                run1 = db.start_run(["example.com"])
                db.save_dns_records(run1, "example.com", [
                    {"type": "A", "name": "example.com", "content": "1.2.3.4",
                     "ttl": 300, "proxied": True},
                ])

                run2 = db.start_run(["example.com"])
                db.save_dns_records(run2, "example.com", [
                    {"type": "A", "name": "example.com", "content": "1.2.3.4",
                     "ttl": 300, "proxied": True},
                    {"type": "AAAA", "name": "example.com", "content": "::1",
                     "ttl": 300, "proxied": True},
                ])

                result = compute_diff(db, run2)
                assert result is not None
                assert result["summary"]["dns_added"] >= 1
                added = [c for c in result["dns_changes"] if c["action"] == "added"]
                assert any(c["type"] == "AAAA" for c in added)
        finally:
            os.unlink(path)

    def test_dns_record_removed(self):
        path = self._tmp_db()
        try:
            with Database(path) as db:
                run1 = db.start_run(["example.com"])
                db.save_dns_records(run1, "example.com", [
                    {"type": "A", "name": "example.com", "content": "1.2.3.4",
                     "ttl": 300, "proxied": True},
                    {"type": "MX", "name": "example.com", "content": "mail.example.com",
                     "ttl": 3600, "proxied": False},
                ])

                run2 = db.start_run(["example.com"])
                db.save_dns_records(run2, "example.com", [
                    {"type": "A", "name": "example.com", "content": "1.2.3.4",
                     "ttl": 300, "proxied": True},
                ])

                result = compute_diff(db, run2)
                assert result is not None
                assert result["summary"]["dns_removed"] >= 1
                removed = [c for c in result["dns_changes"] if c["action"] == "removed"]
                assert any(c["type"] == "MX" for c in removed)
        finally:
            os.unlink(path)

    def test_multiple_changes_across_categories(self):
        path = self._tmp_db()
        try:
            with Database(path) as db:
                run1 = db.start_run(["example.com"])
                db.save_email_check(run1, {
                    "domain": "example.com", "has_mail": True,
                    "mx": [], "dkim": [],
                    "spf": {"record": "v=spf1 -all", "grade": "PASS", "reason": "ok"},
                    "dmarc": {"record": "v=DMARC1; p=none", "grade": "FAIL",
                              "reason": "none", "policy": "none", "rua": None},
                })
                db.save_zone_settings(run1, "example.com", [
                    {"label": "SSL mode", "recommended": "strict",
                     "actual": "strict", "grade": "PASS", "note": "", "explanation": ""},
                ])

                run2 = db.start_run(["example.com"])
                db.save_email_check(run2, {
                    "domain": "example.com", "has_mail": True,
                    "mx": [], "dkim": [],
                    "spf": {"record": "v=spf1 ~all", "grade": "FAIL", "reason": "soft"},
                    "dmarc": {"record": "v=DMARC1; p=reject", "grade": "PASS",
                              "reason": "ok", "policy": "reject", "rua": None},
                })
                db.save_zone_settings(run2, "example.com", [
                    {"label": "SSL mode", "recommended": "strict",
                     "actual": "flexible", "grade": "WARN", "note": "", "explanation": ""},
                ])

                result = compute_diff(db, run2)
                assert result is not None
                assert result["summary"]["regressions"] >= 1
                assert result["summary"]["improvements"] >= 1
        finally:
            os.unlink(path)


class TestFormatDiffText:

    def test_format_with_regressions(self):
        diff = {
            "previous_run_id": 1,
            "previous_run_date": "2026-01-01T00:00:00",
            "current_run_id": 2,
            "current_run_date": "2026-01-02T00:00:00",
            "changes": [
                {"domain": "example.com", "category": "email", "check": "SPF",
                 "old_grade": "PASS", "new_grade": "FAIL", "direction": "regression"},
            ],
            "dns_changes": [],
            "summary": {"regressions": 1, "improvements": 0, "dns_added": 0, "dns_removed": 0},
        }
        text = format_diff_text(diff)
        assert "REGRESSION" in text
        assert "SPF" in text
        assert "PASS" in text
        assert "FAIL" in text

    def test_format_none_diff(self):
        text = format_diff_text(None)
        assert isinstance(text, str)
        assert "no previous" in text.lower()

    def test_format_dns_changes(self):
        diff = {
            "previous_run_id": 1,
            "previous_run_date": "2026-01-01T00:00:00",
            "current_run_id": 2,
            "current_run_date": "2026-01-02T00:00:00",
            "changes": [],
            "dns_changes": [
                {"domain": "example.com", "action": "added", "type": "AAAA",
                 "name": "example.com", "content": "::1"},
            ],
            "summary": {"regressions": 0, "improvements": 0, "dns_added": 1, "dns_removed": 0},
        }
        text = format_diff_text(diff)
        assert "DNS CHANGES" in text
        assert "AAAA" in text
