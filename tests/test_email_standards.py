"""Tests for email_standards grading logic (MTA-STS, TLSRPT, BIMI)."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from checks.email_standards import grade_mta_sts, grade_tlsrpt, grade_bimi


# ── MTA-STS grading ─────────────────────────────────────────────────────────

class TestGradeMtaSts:

    def test_no_record(self):
        result = grade_mta_sts(None, None)
        assert result["grade"] == "INFO"

    def test_enforce_mode(self):
        txt = "v=STSv1; id=20240101"
        policy = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400"
        result = grade_mta_sts(txt, policy)
        assert result["grade"] == "PASS"
        assert result["mode"] == "enforce"

    def test_testing_mode(self):
        txt = "v=STSv1; id=20240101"
        policy = "version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 86400"
        result = grade_mta_sts(txt, policy)
        assert result["grade"] == "WARN"
        assert result["mode"] == "testing"

    def test_none_mode(self):
        txt = "v=STSv1; id=20240101"
        policy = "version: STSv1\nmode: none\nmx: mail.example.com\nmax_age: 86400"
        result = grade_mta_sts(txt, policy)
        assert result["grade"] == "FAIL"
        assert result["mode"] == "none"

    def test_txt_exists_but_policy_unreachable(self):
        txt = "v=STSv1; id=20240101"
        result = grade_mta_sts(txt, None)
        assert result["grade"] == "FAIL"
        assert "unreachable" in result["reason"].lower()

    def test_policy_with_no_mode(self):
        txt = "v=STSv1; id=20240101"
        policy = "version: STSv1\nmx: mail.example.com\nmax_age: 86400"
        result = grade_mta_sts(txt, policy)
        assert result["grade"] == "FAIL"


# ── TLSRPT grading ──────────────────────────────────────────────────────────

class TestGradeTlsrpt:

    def test_no_record(self):
        result = grade_tlsrpt(None)
        assert result["grade"] == "INFO"

    def test_valid_mailto(self):
        result = grade_tlsrpt("v=TLSRPTv1; rua=mailto:tls-reports@example.com")
        assert result["grade"] == "PASS"
        assert "mailto:" in result["rua"]

    def test_malformed_no_version(self):
        result = grade_tlsrpt("rua=mailto:tls-reports@example.com")
        assert result["grade"] == "FAIL"

    def test_valid_https_uri(self):
        result = grade_tlsrpt("v=TLSRPTv1; rua=https://report.example.com/tls")
        assert result["grade"] == "PASS"
        assert "https://" in result["rua"]

    def test_valid_but_no_rua(self):
        result = grade_tlsrpt("v=TLSRPTv1;")
        assert result["grade"] == "FAIL"


# ── BIMI grading ─────────────────────────────────────────────────────────────

class TestGradeBimi:

    def test_no_record(self):
        result = grade_bimi(None)
        assert result["grade"] == "INFO"

    def test_full_record(self):
        result = grade_bimi("v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem")
        assert result["grade"] == "PASS"

    def test_logo_only(self):
        result = grade_bimi("v=BIMI1; l=https://example.com/logo.svg")
        assert result["grade"] == "WARN"

    def test_malformed(self):
        result = grade_bimi("not a bimi record")
        assert result["grade"] == "FAIL"

    def test_empty_logo(self):
        result = grade_bimi("v=BIMI1; l=")
        assert result["grade"] == "FAIL"

    def test_logo_and_empty_authority(self):
        result = grade_bimi("v=BIMI1; l=https://example.com/logo.svg; a=")
        assert result["grade"] == "WARN"  # Logo present but no VMC
