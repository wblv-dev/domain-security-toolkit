"""Tests for blacklist grading logic and helpers."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from blacklist import _reverse_ip, _is_cloud_mail, grade_blacklist


# ── Helpers ──────────────────────────────────────────────────────────────────

class TestReverseIp:

    def test_normal(self):
        assert _reverse_ip("1.2.3.4") == "4.3.2.1"

    def test_all_same(self):
        assert _reverse_ip("10.10.10.10") == "10.10.10.10"

    def test_invalid(self):
        assert _reverse_ip("not-an-ip") is None

    def test_too_few_octets(self):
        assert _reverse_ip("1.2.3") is None


class TestIsCloudMail:

    def test_google(self):
        assert _is_cloud_mail("aspmx.l.google.com") is True

    def test_microsoft(self):
        assert _is_cloud_mail("mail.protection.outlook.com") is True

    def test_mimecast(self):
        assert _is_cloud_mail("us-smtp-inbound-1.mimecast.com") is True

    def test_self_hosted(self):
        assert _is_cloud_mail("mail.example.com") is False

    def test_case_insensitive(self):
        assert _is_cloud_mail("ASPMX.L.GOOGLE.COM") is True


# ── Blacklist grading ────────────────────────────────────────────────────────

class TestGradeBlacklist:

    def test_cloud_provider_only(self):
        ip_results = [
            {"ip": "1.2.3.4", "mx_host": "mx.google.com", "cloud": True, "listings": []},
        ]
        result = grade_blacklist(ip_results)
        assert result["grade"] == "INFO"

    def test_clean(self):
        ip_results = [
            {"ip": "5.6.7.8", "mx_host": "mail.example.com", "cloud": False, "listings": []},
        ]
        result = grade_blacklist(ip_results)
        assert result["grade"] == "PASS"

    def test_major_listing(self):
        ip_results = [{
            "ip": "5.6.7.8",
            "mx_host": "mail.example.com",
            "cloud": False,
            "listings": [
                {"blacklist": "Spamhaus ZEN", "severity": "major",
                 "host": "zen.spamhaus.org", "response": "127.0.0.2", "reason": "spam"},
            ],
        }]
        result = grade_blacklist(ip_results)
        assert result["grade"] == "FAIL"

    def test_minor_listing(self):
        ip_results = [{
            "ip": "5.6.7.8",
            "mx_host": "mail.example.com",
            "cloud": False,
            "listings": [
                {"blacklist": "SORBS", "severity": "minor",
                 "host": "dnsbl.sorbs.net", "response": "127.0.0.6", "reason": ""},
            ],
        }]
        result = grade_blacklist(ip_results)
        assert result["grade"] == "WARN"

    def test_mixed_severity(self):
        """Major listing should win over minor."""
        ip_results = [{
            "ip": "5.6.7.8",
            "mx_host": "mail.example.com",
            "cloud": False,
            "listings": [
                {"blacklist": "Spamhaus", "severity": "major",
                 "host": "zen.spamhaus.org", "response": "127.0.0.2", "reason": ""},
                {"blacklist": "SORBS", "severity": "minor",
                 "host": "dnsbl.sorbs.net", "response": "127.0.0.6", "reason": ""},
            ],
        }]
        result = grade_blacklist(ip_results)
        assert result["grade"] == "FAIL"

    def test_empty_results(self):
        result = grade_blacklist([])
        assert result["grade"] == "INFO"

    def test_multiple_ips_one_listed(self):
        ip_results = [
            {"ip": "1.1.1.1", "mx_host": "mx1.example.com", "cloud": False, "listings": []},
            {"ip": "2.2.2.2", "mx_host": "mx2.example.com", "cloud": False, "listings": [
                {"blacklist": "Spamhaus", "severity": "major",
                 "host": "zen.spamhaus.org", "response": "127.0.0.2", "reason": ""},
            ]},
        ]
        result = grade_blacklist(ip_results)
        assert result["grade"] == "FAIL"
        assert len(result["checked_ips"]) == 2
