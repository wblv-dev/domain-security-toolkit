"""Tests for dns_resolver grading logic."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from lib.dns_resolver import grade_spf, grade_dmarc


# ── SPF grading ──────────────────────────────────────────────────────────────

class TestGradeSpf:

    def test_no_record(self):
        result = grade_spf(None)
        assert result["grade"] == "FAIL"
        assert result["record"] is None

    def test_hard_fail(self):
        result = grade_spf("v=spf1 include:_spf.google.com -all")
        assert result["grade"] == "PASS"

    def test_soft_fail(self):
        result = grade_spf("v=spf1 include:_spf.google.com ~all")
        assert result["grade"] == "WARN"

    def test_allow_all(self):
        result = grade_spf("v=spf1 +all")
        assert result["grade"] == "FAIL"

    def test_neutral(self):
        result = grade_spf("v=spf1 ?all")
        assert result["grade"] == "INFO"

    def test_no_all_mechanism(self):
        result = grade_spf("v=spf1 include:_spf.google.com")
        assert result["grade"] == "WARN"
        assert "incomplete" in result["reason"].lower()


# ── DMARC grading ────────────────────────────────────────────────────────────

class TestGradeDmarc:

    def test_no_record(self):
        result = grade_dmarc(None)
        assert result["grade"] == "FAIL"
        assert result["policy"] is None

    def test_reject(self):
        result = grade_dmarc("v=DMARC1; p=reject; rua=mailto:dmarc@example.com")
        assert result["grade"] == "PASS"
        assert result["policy"] == "reject"
        assert result["rua"] == "mailto:dmarc@example.com"

    def test_quarantine(self):
        result = grade_dmarc("v=DMARC1; p=quarantine")
        assert result["grade"] == "WARN"
        assert result["policy"] == "quarantine"

    def test_none_policy(self):
        result = grade_dmarc("v=DMARC1; p=none")
        assert result["grade"] == "INFO"
        assert result["policy"] == "none"

    def test_unknown_policy(self):
        result = grade_dmarc("v=DMARC1; p=bogus")
        assert result["grade"] == "WARN"
