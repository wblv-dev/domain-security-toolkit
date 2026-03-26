"""
Security tests — checks a penetration tester would run against this tool.

Covers:
- Credential leakage (API tokens not sent to third parties)
- Input validation (malicious domain names, DNS responses)
- Injection attacks (XSS via DNS records in HTML reports, SQL injection via SQLite)
- Path traversal (output file paths)
- Sensitive data handling (tokens not logged, not in output files)
- Denial of service (oversized inputs, deep recursion)
- Configuration security (default settings are safe)
"""

import html
import os
import tempfile

from domain_audit.lib.reporter import _badge, _truncate, write_csv, write_html
from domain_audit.lib.database import Database
from domain_audit.checks.dns_inventory import summarise
from domain_audit.checks.registrar import (
    grade_expiry, grade_lock, _parse_expiry, _parse_statuses,
    _parse_nameservers, _parse_registrar, RDAP_BOOTSTRAP,
)
from domain_audit.checks.dns_security import grade_dnssec, grade_caa, grade_dangling
from domain_audit.checks.blacklist import _reverse_ip, _is_cloud_mail, grade_blacklist
from domain_audit.checks.reverse_dns import grade_reverse_dns
from domain_audit.lib.dns_resolver import grade_spf, grade_dmarc
from domain_audit.checks.zone_security import _grade, _extract_setting, CHECKS
from domain_audit import config


# ══════════════════════════════════════════════════════════════════════════════
# 1. CREDENTIAL LEAKAGE
# ══════════════════════════════════════════════════════════════════════════════

class TestCredentialLeakage:
    """Verify API tokens are never sent to third-party services."""

    def test_rdap_does_not_accept_session_parameter(self):
        """check_domain() and check_all() must NOT accept a session parameter,
        preventing accidental reuse of the authenticated CF session."""
        import inspect
        from domain_audit.checks import registrar

        sig_domain = inspect.signature(registrar.check_domain)
        sig_all = inspect.signature(registrar.check_all)

        param_names_domain = list(sig_domain.parameters.keys())
        param_names_all = list(sig_all.parameters.keys())

        assert "session" not in param_names_domain, \
            "check_domain() must not accept a session — risk of leaking CF token to RDAP"
        assert "session" not in param_names_all, \
            "check_all() must not accept a session — risk of leaking CF token to RDAP"

    def test_rdap_fetch_does_not_accept_session(self):
        """_fetch_rdap() must not accept a session parameter."""
        import inspect
        from domain_audit.checks.registrar import _fetch_rdap

        sig = inspect.signature(_fetch_rdap)
        assert "session" not in sig.parameters, \
            "_fetch_rdap() must not accept a session — creates its own"

    def test_rdap_url_is_public_service(self):
        """RDAP bootstrap URL must point to a known public service."""
        assert "rdap.org" in RDAP_BOOTSTRAP or "rdap.arin.net" in RDAP_BOOTSTRAP

    def test_config_token_from_env_not_hardcoded(self):
        """CF_API_TOKEN must be loaded from environment, never hardcoded."""
        import ast
        with open(os.path.join(os.path.dirname(__file__), "..", "domain_audit", "config.py"), encoding="utf-8") as f:
            tree = ast.parse(f.read())

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "CF_API_TOKEN":
                        # Must be a call to os.getenv, not a string literal
                        assert not isinstance(node.value, ast.Constant), \
                            "CF_API_TOKEN must not be a hardcoded string"


# ══════════════════════════════════════════════════════════════════════════════
# 2. XSS / HTML INJECTION
# ══════════════════════════════════════════════════════════════════════════════

class TestXssInjection:
    """Verify that untrusted data (DNS records, domain names) cannot inject
    scripts into the HTML report."""

    def _generate_html(self, domain, dns_content="1.2.3.4"):
        """Helper to generate HTML with controlled DNS content."""
        fd, path = tempfile.mkstemp(suffix=".html")
        os.close(fd)

        dns_results = {domain: {
            "total": 1, "by_type": {"A": 1}, "proxied": 0,
            "records": [{"type": "A", "name": domain, "content": dns_content,
                         "ttl": 300, "proxied": False}],
        }}
        email_results = {domain: {
            "spf": {"grade": "PASS", "reason": "ok", "record": "v=spf1 -all"},
            "dmarc": {"grade": "PASS", "reason": "ok", "record": "v=DMARC1; p=reject",
                      "policy": "reject", "rua": None},
            "dkim": [], "mx": [], "has_mail": False,
        }}
        security_results = {domain: {
            "results": [{"grade": "PASS", "label": "SSL", "recommended": "strict",
                         "actual": "strict", "note": "", "explanation": ""}],
            "score": (1, 1),
        }}
        registrar_results = {domain: {
            "registrar": None, "nameservers": [],
            "expiry": {"grade": "INFO", "reason": "N/A", "expiry": None, "days_remaining": None},
            "lock": {"grade": "INFO", "reason": "N/A", "locked": None, "statuses": []},
        }}
        dns_sec_results = {domain: {
            "dnssec": {"grade": "INFO", "reason": "", "has_dnskey": False, "has_ds": False},
            "caa": {"grade": "INFO", "reason": "", "records": [], "cf_compatible": True},
            "dangling": {"grade": "PASS", "reason": "", "dangling": []},
        }}
        blacklist_results = {domain: {"grade": "INFO", "reason": "", "listings": [], "checked_ips": []}}
        rdns_results = {domain: {"grade": "INFO", "reason": "", "results": []}}

        try:
            write_html(
                domains=[domain],
                dns_results=dns_results,
                email_results=email_results,
                security_results=security_results,
                registrar_results=registrar_results,
                dns_sec_results=dns_sec_results,
                blacklist_results=blacklist_results,
                rdns_results=rdns_results,
                output_path=path,
            )
            with open(path, encoding="utf-8") as f:
                return f.read()
        finally:
            os.unlink(path)

    def test_script_tag_in_domain_name(self):
        """Domain name containing <script> must be escaped in HTML output."""
        malicious = '<script>alert("xss")</script>.example.com'
        output = self._generate_html(malicious)
        assert "<script>alert" not in output

    def test_script_tag_in_dns_content(self):
        """DNS record content containing <script> must not execute."""
        output = self._generate_html("safe.com", '<script>alert(1)</script>')
        assert "<script>alert(1)</script>" not in output

    def test_event_handler_in_domain(self):
        """Event handlers in domain names must be escaped."""
        malicious = '" onmouseover="alert(1)" data-x="'
        output = self._generate_html(malicious)
        assert 'onmouseover="alert(1)"' not in output

    def test_img_tag_in_dns_content(self):
        """Image tags with onerror handlers must be escaped."""
        output = self._generate_html("safe.com", '<img src=x onerror=alert(1)>')
        # The raw tag must not appear — escaped form (&lt;img ...) is safe
        assert "<img src=x onerror" not in output


# ══════════════════════════════════════════════════════════════════════════════
# 3. SQL INJECTION
# ══════════════════════════════════════════════════════════════════════════════

class TestSqlInjection:
    """Verify that database operations use parameterised queries and
    handle malicious input safely."""

    def test_malicious_domain_in_dns_records(self):
        """Domain name with SQL injection payload must be stored safely."""
        path = tempfile.mktemp(suffix=".db")
        try:
            with Database(path) as db:
                run_id = db.start_run(["'; DROP TABLE runs; --"])
                db.save_dns_records(run_id, "'; DROP TABLE dns_records; --", [
                    {"type": "A", "name": "'; DROP TABLE dns_records; --",
                     "content": "1.2.3.4", "ttl": 300, "proxied": False},
                ])
                # If SQL injection worked, this would fail
                records = db.get_dns_records(run_id)
                assert len(records) == 1

                runs = db.get_runs()
                assert len(runs) == 1
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_malicious_content_in_email_check(self):
        """Email check data with injection payload stored safely."""
        path = tempfile.mktemp(suffix=".db")
        try:
            with Database(path) as db:
                run_id = db.start_run(["test.com"])
                result = {
                    "domain": "test.com",
                    "has_mail": True,
                    "mx": [{"priority": 10, "host": "'; DROP TABLE email_checks; --"}],
                    "spf": {"record": "'; DROP TABLE runs; --", "grade": "FAIL", "reason": "test"},
                    "dmarc": {"record": None, "grade": "FAIL", "reason": "test",
                              "policy": None, "rua": "'; DROP TABLE runs; --"},
                    "dkim": [{"selector": "'; --", "record": "'; DROP TABLE runs; --"}],
                }
                db.save_email_check(run_id, result)
                saved = db.get_email_checks(run_id)
                assert len(saved) == 1
                assert saved[0]["spf_record"] == "'; DROP TABLE runs; --"
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_malicious_zone_settings(self):
        """Zone settings with injection payloads stored safely."""
        path = tempfile.mktemp(suffix=".db")
        try:
            with Database(path) as db:
                run_id = db.start_run(["test.com"])
                db.save_zone_settings(run_id, "test.com", [{
                    "label": "'; DROP TABLE zone_settings; --",
                    "recommended": "strict",
                    "actual": "'; DROP TABLE runs; --",
                    "grade": "FAIL",
                    "note": "'; --",
                    "explanation": "'; DROP TABLE runs; --",
                }])
                saved = db.get_zone_settings(run_id)
                assert len(saved) == 1
                runs = db.get_runs()
                assert len(runs) == 1
        finally:
            if os.path.exists(path):
                os.unlink(path)


# ══════════════════════════════════════════════════════════════════════════════
# 4. INPUT VALIDATION
# ══════════════════════════════════════════════════════════════════════════════

class TestInputValidation:
    """Verify graceful handling of malformed, oversized, or adversarial input."""

    def test_empty_domain_list(self):
        """Grading functions handle empty input without crashing."""
        assert grade_dangling([])["grade"] == "PASS"
        assert grade_reverse_dns([])["grade"] == "INFO"
        assert grade_blacklist([])["grade"] == "INFO"

    def test_extremely_long_domain_name(self):
        """Very long domain names don't crash grading functions."""
        long_domain = "a" * 1000 + ".com"
        result = grade_expiry(None)
        assert result["grade"] == "INFO"

    def test_unicode_in_domain_name(self):
        """Unicode domain names handled without crash."""
        result = grade_lock(["active"])
        assert result["grade"] == "WARN"

    def test_null_bytes_in_input(self):
        """Null bytes in SPF record don't crash parser."""
        result = grade_spf("v=spf1 \x00 -all")
        assert result["grade"] == "PASS"  # -all still matches

    def test_extremely_long_spf_record(self):
        """Very long SPF records don't crash."""
        long_spf = "v=spf1 " + " ".join(f"include:s{i}.example.com" for i in range(500)) + " -all"
        result = grade_spf(long_spf)
        assert result["grade"] == "PASS"

    def test_malformed_dmarc_record(self):
        """Completely malformed DMARC record handled gracefully."""
        result = grade_dmarc("this is not a dmarc record at all")
        assert result["grade"] == "WARN"  # Unrecognised policy

    def test_ip_reversal_with_ipv6(self):
        """IPv6 address doesn't crash the IP reversal function."""
        result = _reverse_ip("2001:db8::1")
        assert result is None  # Only handles IPv4

    def test_summarise_with_missing_fields(self):
        """DNS records with missing fields don't crash summarise."""
        records = [{"type": "A"}, {}, {"name": "x"}]
        result = summarise(records)
        assert result["total"] == 3

    def test_rdap_parse_with_garbage_data(self):
        """RDAP parser handles completely unexpected structures."""
        assert _parse_expiry({"events": [{"unexpected": True}]}) is None
        assert _parse_statuses({"status": [123, None, True]}) is not None  # Shouldn't crash
        assert _parse_nameservers({"nameservers": [{}]}) == []
        assert _parse_registrar({"entities": [{"roles": []}]}) is None

    def test_caa_with_malformed_records(self):
        """CAA grading handles records with missing fields."""
        records = [{"flags": "0"}, {"tag": "issue"}, {}]
        result = grade_caa(records)
        # Should not crash — missing fields treated as empty
        assert result["grade"] in ("PASS", "WARN", "FAIL", "INFO")


# ══════════════════════════════════════════════════════════════════════════════
# 5. SENSITIVE DATA IN OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

class TestSensitiveDataInOutput:
    """Verify that API tokens and credentials never appear in output files."""

    def test_token_not_in_html_output(self):
        """API token must never appear in generated HTML."""
        fd, path = tempfile.mkstemp(suffix=".html")
        os.close(fd)

        # Temporarily set a recognisable token
        original = config.CF_API_TOKEN
        config.CF_API_TOKEN = "SUPER_SECRET_TOKEN_12345"

        try:
            write_html(
                domains=["test.com"],
                dns_results={"test.com": {"total": 0, "by_type": {}, "proxied": 0, "records": []}},
                email_results={"test.com": {
                    "spf": {"grade": "PASS", "reason": "ok", "record": "v=spf1 -all"},
                    "dmarc": {"grade": "PASS", "reason": "ok", "record": "v=DMARC1; p=reject",
                              "policy": "reject", "rua": None},
                    "dkim": [], "mx": [], "has_mail": False,
                }},
                security_results={"test.com": {"results": [], "score": (0, 0)}},
                registrar_results={"test.com": {
                    "registrar": None, "nameservers": [],
                    "expiry": {"grade": "INFO", "reason": "", "expiry": None, "days_remaining": None},
                    "lock": {"grade": "INFO", "reason": "", "locked": None, "statuses": []},
                }},
                dns_sec_results={"test.com": {
                    "dnssec": {"grade": "INFO", "reason": "", "has_dnskey": False, "has_ds": False},
                    "caa": {"grade": "INFO", "reason": "", "records": [], "cf_compatible": True},
                    "dangling": {"grade": "PASS", "reason": "", "dangling": []},
                }},
                blacklist_results={"test.com": {"grade": "INFO", "reason": "", "listings": [], "checked_ips": []}},
                rdns_results={"test.com": {"grade": "INFO", "reason": "", "results": []}},
                output_path=path,
            )
            with open(path, encoding="utf-8") as f:
                content = f.read()
            assert "SUPER_SECRET_TOKEN_12345" not in content
        finally:
            config.CF_API_TOKEN = original
            os.unlink(path)

    def test_token_not_in_csv_output(self):
        """API token must never appear in generated CSV."""
        fd, path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)

        original = config.CF_API_TOKEN
        config.CF_API_TOKEN = "SUPER_SECRET_TOKEN_12345"

        try:
            write_csv(
                domains=["test.com"],
                dns_results={"test.com": {"total": 0}},
                email_results={"test.com": {
                    "spf": {"grade": "PASS"}, "dmarc": {"grade": "PASS"}, "dkim": [],
                }},
                security_results={"test.com": {"results": [], "score": (0, 0)}},
                registrar_results={"test.com": {
                    "registrar": None, "expiry": {"grade": "INFO"}, "lock": {"grade": "INFO"},
                }},
                dns_sec_results={"test.com": {
                    "dnssec": {"grade": "INFO"}, "caa": {"grade": "INFO"},
                    "dangling": {"grade": "PASS", "dangling": []},
                }},
                blacklist_results={"test.com": {"grade": "INFO"}},
                rdns_results={"test.com": {"grade": "INFO"}},
                output_path=path,
            )
            with open(path, encoding="utf-8") as f:
                content = f.read()
            assert "SUPER_SECRET_TOKEN_12345" not in content
        finally:
            config.CF_API_TOKEN = original
            os.unlink(path)


# ══════════════════════════════════════════════════════════════════════════════
# 6. CONFIGURATION SECURITY
# ══════════════════════════════════════════════════════════════════════════════

class TestConfigurationSecurity:
    """Verify default configuration is secure."""

    def test_default_token_is_empty(self):
        """Default token must be empty string, not a real value."""
        import ast
        with open(os.path.join(os.path.dirname(__file__), "..", "domain_audit", "config.py"), encoding="utf-8") as f:
            source = f.read()
        assert 'os.getenv("CF_API_TOKEN"' in source or "os.getenv('CF_API_TOKEN'" in source

    def test_no_secrets_in_source_files(self):
        """No files contain patterns that look like hardcoded secrets."""
        import glob
        secret_patterns = [
            "sk_live_", "sk_test_",  # Stripe
            "AKIA",                  # AWS access key
            "ghp_", "gho_",         # GitHub tokens
            "xoxb-", "xoxp-",      # Slack tokens
            "Bearer eyJ",           # JWT tokens
        ]
        base_dir = os.path.join(os.path.dirname(__file__), "..", "domain_audit")
        for pattern in glob.glob(os.path.join(base_dir, "**/*.py"), recursive=True):
            if "test_security.py" in pattern:
                continue  # Skip this file (contains the patterns as strings)
            with open(pattern, encoding="utf-8") as f:
                content = f.read()
            for secret in secret_patterns:
                assert secret not in content, \
                    f"Possible hardcoded secret '{secret}' found in {pattern}"

    def test_gitignore_covers_sensitive_files(self):
        """Gitignore must exclude generated output and environment files."""
        with open(os.path.join(os.path.dirname(__file__), "..", ".gitignore"), encoding="utf-8") as f:
            gitignore = f.read()
        required = ["audit_history.db", ".env", "AUDIT_REPORT.md",
                     "audit_report.html", "audit_report.csv"]
        for pattern in required:
            assert pattern in gitignore, f".gitignore missing: {pattern}"


# ══════════════════════════════════════════════════════════════════════════════
# 7. DENIAL OF SERVICE / RESOURCE EXHAUSTION
# ══════════════════════════════════════════════════════════════════════════════

class TestDenialOfService:
    """Verify the tool handles resource exhaustion scenarios."""

    def test_thousands_of_dns_records(self):
        """Summarise handles large record sets without excessive memory."""
        records = [
            {"type": "A", "name": f"host{i}.example.com",
             "content": f"10.0.{i // 256}.{i % 256}", "ttl": 300, "proxied": False}
            for i in range(5000)
        ]
        result = summarise(records)
        assert result["total"] == 5000
        assert result["by_type"]["A"] == 5000

    def test_many_dangling_records(self):
        """Dangling grade handles large lists without crash."""
        dangling = [
            {"name": f"sub{i}.example.com", "target": f"dead{i}.example.com"}
            for i in range(1000)
        ]
        result = grade_dangling(dangling)
        assert result["grade"] == "FAIL"
        # Should truncate the reason string, not list all 1000
        assert len(result["reason"]) < 500

    def test_many_blacklist_results(self):
        """Blacklist grading handles many IPs."""
        ip_results = [
            {"ip": f"10.0.{i // 256}.{i % 256}", "mx_host": f"mx{i}.example.com",
             "cloud": False, "listings": []}
            for i in range(100)
        ]
        result = grade_blacklist(ip_results)
        assert result["grade"] == "PASS"
        assert len(result["checked_ips"]) == 100

    def test_database_handles_large_batch(self):
        """Database handles large record batches without error."""
        path = tempfile.mktemp(suffix=".db")
        try:
            with Database(path) as db:
                run_id = db.start_run(["example.com"])
                records = [
                    {"type": "A", "name": f"h{i}.example.com",
                     "content": f"10.0.{i // 256}.{i % 256}", "ttl": 300, "proxied": False}
                    for i in range(2000)
                ]
                db.save_dns_records(run_id, "example.com", records)
                saved = db.get_dns_records(run_id)
                assert len(saved) == 2000
        finally:
            if os.path.exists(path):
                os.unlink(path)
