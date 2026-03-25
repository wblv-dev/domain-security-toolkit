"""Tests for new database tables: registrar, dns_security, blacklist, reverse_dns."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from database import Database


def _tmp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return path


class TestRegistrarChecks:

    def test_save_and_get(self):
        path = _tmp_db()
        try:
            with Database(path) as db:
                run_id = db.start_run(["example.com"])
                result = {
                    "domain": "example.com",
                    "registrar": "Cloudflare Inc.",
                    "nameservers": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
                    "expiry": {
                        "grade": "PASS",
                        "reason": "Expires in 300 day(s)",
                        "expiry": "2027-01-01T00:00:00+00:00",
                        "days_remaining": 300,
                    },
                    "lock": {
                        "grade": "PASS",
                        "reason": "Transfer lock enabled",
                        "locked": True,
                        "statuses": ["client transfer prohibited", "active"],
                    },
                }
                db.save_registrar_check(run_id, result)
                saved = db.get_registrar_checks(run_id)
                assert len(saved) == 1
                assert saved[0]["registrar"] == "Cloudflare Inc."
                assert saved[0]["expiry_grade"] == "PASS"
                assert saved[0]["lock_grade"] == "PASS"
                assert len(saved[0]["nameservers"]) == 2
                assert len(saved[0]["lock_statuses"]) == 2
        finally:
            os.unlink(path)


class TestDnsSecurity:

    def test_save_and_get(self):
        path = _tmp_db()
        try:
            with Database(path) as db:
                run_id = db.start_run(["example.com"])
                result = {
                    "domain": "example.com",
                    "dnssec": {
                        "grade": "PASS",
                        "reason": "DNSSEC fully deployed",
                        "has_dnskey": True,
                        "has_ds": True,
                    },
                    "caa": {
                        "grade": "PASS",
                        "reason": "CAA configured",
                        "records": [{"flags": "0", "tag": "issue", "value": "letsencrypt.org"}],
                        "cf_compatible": True,
                    },
                    "dangling": {
                        "grade": "PASS",
                        "reason": "No dangling CNAME records detected",
                        "dangling": [],
                    },
                }
                db.save_dns_security(run_id, result)
                saved = db.get_dns_security(run_id)
                assert len(saved) == 1
                assert saved[0]["dnssec_grade"] == "PASS"
                assert saved[0]["caa_grade"] == "PASS"
                assert saved[0]["dangling_grade"] == "PASS"
                assert len(saved[0]["caa_records"]) == 1
                assert saved[0]["dnssec_dnskey"] == 1
                assert saved[0]["dnssec_ds"] == 1
        finally:
            os.unlink(path)


class TestBlacklistChecks:

    def test_save_and_get_clean(self):
        path = _tmp_db()
        try:
            with Database(path) as db:
                run_id = db.start_run(["example.com"])
                result = {
                    "domain": "example.com",
                    "grade": "PASS",
                    "reason": "Not listed on any checked blacklist",
                    "checked_ips": ["1.2.3.4"],
                    "listings": [],
                }
                db.save_blacklist_check(run_id, result)
                saved = db.get_blacklist_checks(run_id)
                assert len(saved) == 1
                assert saved[0]["grade"] == "PASS"
                assert saved[0]["checked_ips"] == ["1.2.3.4"]
                assert saved[0]["listings"] == []
        finally:
            os.unlink(path)

    def test_save_and_get_listed(self):
        path = _tmp_db()
        try:
            with Database(path) as db:
                run_id = db.start_run(["example.com"])
                result = {
                    "domain": "example.com",
                    "grade": "FAIL",
                    "reason": "Listed on 1 major blacklist(s)",
                    "checked_ips": ["5.6.7.8"],
                    "listings": [
                        {"blacklist": "Spamhaus", "ip": "5.6.7.8",
                         "reason": "spam source", "severity": "major"},
                    ],
                }
                db.save_blacklist_check(run_id, result)
                saved = db.get_blacklist_checks(run_id)
                assert len(saved) == 1
                assert saved[0]["grade"] == "FAIL"
                assert len(saved[0]["listings"]) == 1
        finally:
            os.unlink(path)


class TestReverseDns:

    def test_save_and_get(self):
        path = _tmp_db()
        try:
            with Database(path) as db:
                run_id = db.start_run(["example.com"])
                result = {
                    "domain": "example.com",
                    "grade": "PASS",
                    "reason": "All 1 mail server IP(s) have valid rDNS",
                    "results": [
                        {"mx_host": "mx.example.com", "ip": "1.2.3.4",
                         "ptr": "mx.example.com", "fcrdns": True, "status": "confirmed"},
                    ],
                }
                db.save_reverse_dns(run_id, result)
                saved = db.get_reverse_dns(run_id)
                assert len(saved) == 1
                assert saved[0]["grade"] == "PASS"
                assert len(saved[0]["results"]) == 1
                assert saved[0]["results"][0]["fcrdns"] is True
        finally:
            os.unlink(path)
