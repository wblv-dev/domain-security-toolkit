"""Tests for remediation guidance module."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from lib.remediation import get_tooltip, get_remediation, collect_remediations, TOOLTIPS, REMEDIATIONS


class TestGetTooltip:

    def test_known_label(self):
        tip = get_tooltip("SPF")
        assert len(tip) > 0
        assert "Sender Policy" in tip

    def test_unknown_label(self):
        assert get_tooltip("nonexistent_check") == ""

    def test_all_tooltips_are_strings(self):
        for label, tip in TOOLTIPS.items():
            assert isinstance(tip, str), f"Tooltip for {label} is not a string"
            assert len(tip) > 10, f"Tooltip for {label} is too short"


class TestGetRemediation:

    def test_ssl_fail(self):
        rem = get_remediation("SSL mode", "FAIL")
        assert rem is not None
        assert rem["priority"] == "Critical"
        assert len(rem["steps"]) >= 2

    def test_spf_fail(self):
        rem = get_remediation("SPF", "FAIL")
        assert rem is not None
        assert rem["priority"] == "Critical"
        assert "steps" in rem

    def test_pass_returns_none(self):
        assert get_remediation("SSL mode", "PASS") is None

    def test_info_returns_none(self):
        assert get_remediation("DNSSEC", "INFO") is None

    def test_unknown_check(self):
        assert get_remediation("made_up_check", "FAIL") is None

    def test_all_remediations_have_required_fields(self):
        for check, grades in REMEDIATIONS.items():
            for grade, rem in grades.items():
                assert "priority" in rem, f"{check}/{grade} missing priority"
                assert "risk" in rem, f"{check}/{grade} missing risk"
                assert "steps" in rem, f"{check}/{grade} missing steps"
                assert len(rem["steps"]) > 0, f"{check}/{grade} has empty steps"


class TestCollectRemediations:

    def test_empty_results(self):
        findings = collect_remediations([], {}, {}, {}, {}, {}, {})
        assert findings == []

    def test_collects_fail_grades(self):
        findings = collect_remediations(
            domains=["example.com"],
            security_results={"example.com": {
                "results": [
                    {"label": "SSL mode", "grade": "FAIL", "actual": "off", "recommended": "strict"},
                ],
                "score": (0, 1),
            }},
            email_results={"example.com": {
                "spf": {"grade": "FAIL", "reason": "No SPF record"},
                "dmarc": {"grade": "PASS", "reason": "ok"},
            }},
            dns_sec_results={},
            registrar_results={},
            blacklist_results={},
            rdns_results={},
        )
        assert len(findings) >= 2
        checks = [f["check"] for f in findings]
        assert "SSL mode" in checks
        assert "SPF" in checks

    def test_sorted_by_priority(self):
        findings = collect_remediations(
            domains=["example.com"],
            security_results={"example.com": {
                "results": [
                    {"label": "Email obfuscation", "grade": "FAIL", "actual": "off", "recommended": "on"},
                    {"label": "SSL mode", "grade": "FAIL", "actual": "off", "recommended": "strict"},
                ],
                "score": (0, 2),
            }},
            email_results={"example.com": {
                "spf": {"grade": "PASS", "reason": "ok"},
                "dmarc": {"grade": "PASS", "reason": "ok"},
            }},
            dns_sec_results={},
            registrar_results={},
            blacklist_results={},
            rdns_results={},
        )
        # Critical should come before Low
        priorities = [f["priority"] for f in findings]
        assert priorities.index("Critical") < priorities.index("Low")

    def test_ignores_pass_and_info(self):
        findings = collect_remediations(
            domains=["example.com"],
            security_results={"example.com": {
                "results": [
                    {"label": "SSL mode", "grade": "PASS", "actual": "strict", "recommended": "strict"},
                ],
                "score": (1, 1),
            }},
            email_results={"example.com": {
                "spf": {"grade": "INFO", "reason": "neutral"},
                "dmarc": {"grade": "PASS", "reason": "ok"},
            }},
            dns_sec_results={"example.com": {
                "dnssec": {"grade": "INFO", "reason": "not available"},
                "caa": {"grade": "INFO", "reason": ""},
                "dangling": {"grade": "PASS", "reason": ""},
            }},
            registrar_results={},
            blacklist_results={},
            rdns_results={},
        )
        assert findings == []
