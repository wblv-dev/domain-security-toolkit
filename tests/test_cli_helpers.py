"""Tests for CLI helper functions: domain normalisation and file loading."""

import os
import tempfile

from domain_audit.cli import normalise_domain, _load_domains_file


class TestNormaliseDomain:

    def test_plain_domain(self):
        assert normalise_domain("example.com") == "example.com"

    def test_uppercase(self):
        assert normalise_domain("EXAMPLE.COM") == "example.com"

    def test_whitespace(self):
        assert normalise_domain("  example.com  ") == "example.com"

    def test_trailing_dot(self):
        assert normalise_domain("example.com.") == "example.com"

    def test_https_url(self):
        assert normalise_domain("https://example.com") == "example.com"

    def test_http_url(self):
        assert normalise_domain("http://example.com") == "example.com"

    def test_url_with_path(self):
        assert normalise_domain("https://example.com/some/path") == "example.com"

    def test_url_with_port(self):
        assert normalise_domain("https://example.com:8443") == "example.com"

    def test_url_with_query(self):
        assert normalise_domain("https://example.com?q=test") == "example.com"

    def test_url_with_fragment(self):
        assert normalise_domain("https://example.com#section") == "example.com"

    def test_full_url(self):
        assert normalise_domain("https://example.com:443/path?q=1#top") == "example.com"

    def test_subdomain(self):
        assert normalise_domain("www.example.com") == "www.example.com"

    def test_fqdn_with_url(self):
        assert normalise_domain("https://example.com./path") == "example.com"

    def test_empty_string(self):
        assert normalise_domain("") == ""

    def test_just_whitespace(self):
        assert normalise_domain("   ") == ""


class TestLoadDomainsFile:

    def test_basic_file(self):
        fd, path = tempfile.mkstemp(suffix=".txt")
        try:
            with os.fdopen(fd, "w") as f:
                f.write("example.com\nexample.org\n")
            result = _load_domains_file(path)
            assert result == ["example.com", "example.org"]
        finally:
            os.unlink(path)

    def test_comments_and_blanks(self):
        fd, path = tempfile.mkstemp(suffix=".txt")
        try:
            with os.fdopen(fd, "w") as f:
                f.write("# This is a comment\nexample.com\n\n# Another comment\nexample.org\n\n")
            result = _load_domains_file(path)
            assert result == ["example.com", "example.org"]
        finally:
            os.unlink(path)

    def test_whitespace_lines(self):
        fd, path = tempfile.mkstemp(suffix=".txt")
        try:
            with os.fdopen(fd, "w") as f:
                f.write("  example.com  \n  example.org  \n")
            result = _load_domains_file(path)
            assert result == ["example.com", "example.org"]
        finally:
            os.unlink(path)

    def test_empty_file(self):
        fd, path = tempfile.mkstemp(suffix=".txt")
        try:
            with os.fdopen(fd, "w") as f:
                f.write("")
            result = _load_domains_file(path)
            assert result == []
        finally:
            os.unlink(path)

    def test_file_not_found(self):
        try:
            _load_domains_file("/nonexistent/path/domains.txt")
            assert False, "Should have raised FileNotFoundError"
        except FileNotFoundError:
            pass
