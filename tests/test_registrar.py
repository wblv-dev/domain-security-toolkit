"""Tests for registrar grading logic and RDAP parsing."""

import sys
import os
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from registrar import (
    grade_expiry,
    grade_lock,
    _parse_expiry,
    _parse_statuses,
    _parse_nameservers,
    _parse_registrar,
    EXPIRY_FAIL_DAYS,
    EXPIRY_WARN_DAYS,
)


# ── Expiry grading ───────────────────────────────────────────────────────────

class TestGradeExpiry:

    def test_no_expiry(self):
        result = grade_expiry(None)
        assert result["grade"] == "INFO"
        assert result["days_remaining"] is None

    def test_expired(self):
        past = datetime.now(timezone.utc) - timedelta(days=5)
        result = grade_expiry(past)
        assert result["grade"] == "FAIL"
        assert "expired" in result["reason"].lower()

    def test_critical(self):
        soon = datetime.now(timezone.utc) + timedelta(days=10, hours=12)
        result = grade_expiry(soon)
        assert result["grade"] == "FAIL"
        assert result["days_remaining"] == 10

    def test_warn(self):
        medium = datetime.now(timezone.utc) + timedelta(days=60, hours=12)
        result = grade_expiry(medium)
        assert result["grade"] == "WARN"

    def test_pass(self):
        far = datetime.now(timezone.utc) + timedelta(days=365, hours=12)
        result = grade_expiry(far)
        assert result["grade"] == "PASS"
        assert result["days_remaining"] == 365

    def test_boundary_fail(self):
        boundary = datetime.now(timezone.utc) + timedelta(days=EXPIRY_FAIL_DAYS - 1, hours=12)
        result = grade_expiry(boundary)
        assert result["grade"] == "FAIL"

    def test_boundary_warn(self):
        boundary = datetime.now(timezone.utc) + timedelta(days=EXPIRY_WARN_DAYS - 1, hours=12)
        result = grade_expiry(boundary)
        assert result["grade"] == "WARN"

    def test_boundary_pass(self):
        boundary = datetime.now(timezone.utc) + timedelta(days=EXPIRY_WARN_DAYS + 1)
        result = grade_expiry(boundary)
        assert result["grade"] == "PASS"


# ── Lock grading ─────────────────────────────────────────────────────────────

class TestGradeLock:

    def test_locked(self):
        result = grade_lock(["client transfer prohibited", "active"])
        assert result["grade"] == "PASS"
        assert result["locked"] is True

    def test_locked_variant(self):
        result = grade_lock(["clienttransferprohibited"])
        assert result["grade"] == "PASS"

    def test_server_locked(self):
        result = grade_lock(["servertransferprohibited"])
        assert result["grade"] == "PASS"

    def test_unlocked(self):
        result = grade_lock(["active"])
        assert result["grade"] == "WARN"
        assert result["locked"] is False

    def test_empty_statuses(self):
        result = grade_lock([])
        assert result["grade"] == "WARN"
        assert result["locked"] is False


# ── RDAP parsing ─────────────────────────────────────────────────────────────

class TestParseExpiry:

    def test_valid_event(self):
        rdap = {
            "events": [
                {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2026-06-15T12:00:00Z"},
            ]
        }
        result = _parse_expiry(rdap)
        assert result is not None
        assert result.year == 2026
        assert result.month == 6

    def test_no_expiry_event(self):
        rdap = {"events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}]}
        assert _parse_expiry(rdap) is None

    def test_no_events(self):
        assert _parse_expiry({}) is None

    def test_malformed_date(self):
        rdap = {"events": [{"eventAction": "expiration", "eventDate": "not-a-date"}]}
        assert _parse_expiry(rdap) is None


class TestParseStatuses:

    def test_normal(self):
        rdap = {"status": ["active", "client transfer prohibited"]}
        result = _parse_statuses(rdap)
        assert "active" in result
        assert "client transfer prohibited" in result

    def test_empty(self):
        assert _parse_statuses({}) == []


class TestParseNameservers:

    def test_normal(self):
        rdap = {
            "nameservers": [
                {"ldhName": "ns1.example.com."},
                {"ldhName": "ns2.example.com"},
            ]
        }
        result = _parse_nameservers(rdap)
        assert result == ["ns1.example.com", "ns2.example.com"]

    def test_empty(self):
        assert _parse_nameservers({}) == []

    def test_unicode_fallback(self):
        rdap = {"nameservers": [{"unicodeName": "ns1.example.com"}]}
        result = _parse_nameservers(rdap)
        assert "ns1.example.com" in result


class TestParseRegistrar:

    def test_vcard_registrar(self):
        rdap = {
            "entities": [{
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Cloudflare Inc."]]],
            }]
        }
        assert _parse_registrar(rdap) == "Cloudflare Inc."

    def test_handle_fallback(self):
        rdap = {
            "entities": [{
                "roles": ["registrar"],
                "handle": "REG-1234",
            }]
        }
        assert _parse_registrar(rdap) == "REG-1234"

    def test_no_registrar(self):
        rdap = {"entities": [{"roles": ["registrant"]}]}
        assert _parse_registrar(rdap) is None

    def test_empty(self):
        assert _parse_registrar({}) is None
