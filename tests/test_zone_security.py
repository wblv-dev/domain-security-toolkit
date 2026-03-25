"""Tests for zone_security grading functions."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from zone_security import _grade, _grade_hsts, CHECKS


class TestGrade:

    def _check(self, setting_name):
        return next(c for c in CHECKS if c["setting"] == setting_name)

    def test_ssl_full_strict_passes(self):
        result = _grade(self._check("ssl"), "strict")
        assert result["grade"] == "PASS"

    def test_ssl_full_passes(self):
        result = _grade(self._check("ssl"), "full")
        assert result["grade"] == "PASS"

    def test_ssl_flexible_warns(self):
        result = _grade(self._check("ssl"), "flexible")
        assert result["grade"] == "WARN"

    def test_ssl_off_fails(self):
        result = _grade(self._check("ssl"), "off")
        assert result["grade"] == "FAIL"

    def test_unavailable_setting(self):
        result = _grade(self._check("ssl"), None)
        assert result["grade"] == "INFO"

    def test_min_tls_12_passes(self):
        result = _grade(self._check("min_tls_version"), "1.2")
        assert result["grade"] == "PASS"

    def test_min_tls_10_fails(self):
        result = _grade(self._check("min_tls_version"), "1.0")
        assert result["grade"] == "FAIL"

    def test_tls_13_on_passes(self):
        result = _grade(self._check("tls_1_3"), "on")
        assert result["grade"] == "PASS"

    def test_always_https_off_fails(self):
        result = _grade(self._check("always_use_https"), "off")
        assert result["grade"] == "FAIL"


class TestGradeHsts:

    def test_disabled(self):
        result = _grade_hsts({"enabled": False, "max_age": 0,
                              "include_subdomains": False, "preload": False})
        assert result["grade"] == "WARN"

    def test_enabled_high_max_age(self):
        result = _grade_hsts({"enabled": True, "max_age": 31536000,
                              "include_subdomains": True, "preload": True})
        assert result["grade"] == "PASS"
        assert "preload" in result["note"]

    def test_enabled_low_max_age(self):
        result = _grade_hsts({"enabled": True, "max_age": 3600,
                              "include_subdomains": False, "preload": False})
        assert result["grade"] == "WARN"

    def test_unavailable(self):
        result = _grade_hsts({"enabled": None, "max_age": None,
                              "include_subdomains": None, "preload": None})
        assert result["grade"] == "INFO"
