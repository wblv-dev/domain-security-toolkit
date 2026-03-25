"""Tests for reporter helper functions."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from reporter import _worst, _sym, _truncate, _badge, GRADE_SYMBOL


class TestWorst:

    def test_single(self):
        assert _worst(["PASS"]) == "PASS"

    def test_fail_wins(self):
        assert _worst(["PASS", "WARN", "FAIL"]) == "FAIL"

    def test_warn_beats_pass(self):
        assert _worst(["PASS", "WARN"]) == "WARN"


class TestSym:

    def test_known_grades(self):
        for grade in ("PASS", "WARN", "FAIL", "INFO"):
            assert grade in _sym(grade)

    def test_unknown_grade(self):
        assert _sym("UNKNOWN") == "UNKNOWN"


class TestTruncate:

    def test_short_string(self):
        assert _truncate("hello", 80) == "hello"

    def test_long_string(self):
        result = _truncate("a" * 100, 20)
        assert len(result) == 20
        assert result.endswith("...")


class TestBadge:

    def test_pass_badge(self):
        html = _badge("PASS")
        assert "badge-success" in html
        assert "PASS" in html

    def test_custom_text(self):
        html = _badge("FAIL", "Critical")
        assert "Critical" in html
        assert "badge-danger" in html
