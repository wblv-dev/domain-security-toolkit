"""Tests for dns_security grading logic."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from checks.dns_security import grade_dnssec, grade_caa, grade_dangling


# ── DNSSEC grading ───────────────────────────────────────────────────────────

class TestGradeDnssec:

    def test_fully_deployed(self):
        result = grade_dnssec(has_dnskey=True, has_ds=True)
        assert result["grade"] == "PASS"

    def test_dnskey_no_ds(self):
        """DNSKEY exists but DS missing at registrar — common misconfiguration."""
        result = grade_dnssec(has_dnskey=True, has_ds=False)
        assert result["grade"] == "WARN"
        assert "DS" in result["reason"] or "registrar" in result["reason"].lower()

    def test_not_enabled(self):
        result = grade_dnssec(has_dnskey=False, has_ds=False)
        assert result["grade"] == "WARN"

    def test_ds_without_dnskey(self):
        """Unusual: DS at parent but no DNSKEY at zone."""
        result = grade_dnssec(has_dnskey=False, has_ds=True)
        assert result["grade"] == "WARN"


# ── CAA grading ──────────────────────────────────────────────────────────────

class TestGradeCaa:

    def test_no_records(self):
        result = grade_caa([])
        assert result["grade"] == "WARN"
        assert result["cf_compatible"] is True

    def test_pass_with_letsencrypt(self):
        records = [
            {"flags": "0", "tag": "issue", "value": "letsencrypt.org"},
        ]
        result = grade_caa(records, is_cloudflare=True)
        assert result["grade"] == "PASS"
        assert result["cf_compatible"] is True

    def test_pass_with_digicert(self):
        records = [
            {"flags": "0", "tag": "issue", "value": "digicert.com"},
            {"flags": "0", "tag": "iodef", "value": "mailto:sec@example.com"},
        ]
        result = grade_caa(records, is_cloudflare=True)
        assert result["grade"] == "PASS"

    def test_fail_incompatible_ca(self):
        """CAA records that exclude all Cloudflare-compatible CAs."""
        records = [
            {"flags": "0", "tag": "issue", "value": "someca.example.com"},
        ]
        result = grade_caa(records, is_cloudflare=True)
        assert result["grade"] == "FAIL"
        assert result["cf_compatible"] is False

    def test_non_cloudflare_pass(self):
        """When not checking CF compatibility, any CAA is fine."""
        records = [
            {"flags": "0", "tag": "issue", "value": "someca.example.com"},
        ]
        result = grade_caa(records, is_cloudflare=False)
        assert result["grade"] == "PASS"

    def test_issuewild(self):
        records = [
            {"flags": "0", "tag": "issue", "value": "letsencrypt.org"},
            {"flags": "0", "tag": "issuewild", "value": "letsencrypt.org"},
        ]
        result = grade_caa(records, is_cloudflare=True)
        assert result["grade"] == "PASS"
        assert "issuewild" in result["reason"]

    def test_multiple_cas(self):
        records = [
            {"flags": "0", "tag": "issue", "value": "letsencrypt.org"},
            {"flags": "0", "tag": "issue", "value": "digicert.com"},
        ]
        result = grade_caa(records, is_cloudflare=True)
        assert result["grade"] == "PASS"


# ── Dangling CNAME grading ───────────────────────────────────────────────────

class TestGradeDangling:

    def test_no_dangling(self):
        result = grade_dangling([])
        assert result["grade"] == "PASS"

    def test_one_dangling(self):
        dangling = [{"name": "old.example.com", "target": "dead.service.com"}]
        result = grade_dangling(dangling)
        assert result["grade"] == "FAIL"
        assert "old.example.com" in result["reason"]

    def test_many_dangling(self):
        """Truncation for >5 dangling records."""
        dangling = [
            {"name": f"sub{i}.example.com", "target": f"dead{i}.com"}
            for i in range(8)
        ]
        result = grade_dangling(dangling)
        assert result["grade"] == "FAIL"
        assert "+3 more" in result["reason"]

    def test_reason_mentions_takeover(self):
        dangling = [{"name": "x.example.com", "target": "y.example.com"}]
        result = grade_dangling(dangling)
        assert "takeover" in result["reason"].lower()
