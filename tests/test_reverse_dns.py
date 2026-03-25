"""Tests for reverse_dns grading logic."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from reverse_dns import grade_reverse_dns


class TestGradeReverseDns:

    def test_no_mx(self):
        result = grade_reverse_dns([])
        assert result["grade"] == "INFO"

    def test_all_confirmed(self):
        results = [
            {"mx_host": "mx1.example.com", "ip": "1.2.3.4",
             "ptr": "mx1.example.com", "fcrdns": True, "status": "confirmed"},
            {"mx_host": "mx2.example.com", "ip": "5.6.7.8",
             "ptr": "mx2.example.com", "fcrdns": True, "status": "confirmed"},
        ]
        result = grade_reverse_dns(results)
        assert result["grade"] == "PASS"
        assert "2" in result["reason"]

    def test_missing_ptr(self):
        results = [
            {"mx_host": "mx1.example.com", "ip": "1.2.3.4",
             "ptr": None, "fcrdns": False, "status": "missing"},
        ]
        result = grade_reverse_dns(results)
        assert result["grade"] == "FAIL"
        assert "1.2.3.4" in result["reason"]

    def test_mismatch(self):
        results = [
            {"mx_host": "mx1.example.com", "ip": "1.2.3.4",
             "ptr": "other.host.com", "fcrdns": False, "status": "mismatch"},
        ]
        result = grade_reverse_dns(results)
        assert result["grade"] == "WARN"

    def test_mixed_missing_and_confirmed(self):
        """Missing should take priority over confirmed."""
        results = [
            {"mx_host": "mx1.example.com", "ip": "1.2.3.4",
             "ptr": "mx1.example.com", "fcrdns": True, "status": "confirmed"},
            {"mx_host": "mx2.example.com", "ip": "5.6.7.8",
             "ptr": None, "fcrdns": False, "status": "missing"},
        ]
        result = grade_reverse_dns(results)
        assert result["grade"] == "FAIL"

    def test_mixed_mismatch_and_confirmed(self):
        results = [
            {"mx_host": "mx1.example.com", "ip": "1.2.3.4",
             "ptr": "mx1.example.com", "fcrdns": True, "status": "confirmed"},
            {"mx_host": "mx2.example.com", "ip": "5.6.7.8",
             "ptr": "other.host.com", "fcrdns": False, "status": "mismatch"},
        ]
        result = grade_reverse_dns(results)
        assert result["grade"] == "WARN"

    def test_multiple_missing(self):
        results = [
            {"mx_host": f"mx{i}.example.com", "ip": f"1.2.3.{i}",
             "ptr": None, "fcrdns": False, "status": "missing"}
            for i in range(4)
        ]
        result = grade_reverse_dns(results)
        assert result["grade"] == "FAIL"
        # Should show up to 3 IPs
        assert "1.2.3.0" in result["reason"]
