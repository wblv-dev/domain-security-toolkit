"""Tests for dns_inventory.summarise()."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from dns_inventory import summarise


class TestSummarise:

    def test_empty(self):
        result = summarise([])
        assert result["total"] == 0
        assert result["by_type"] == {}
        assert result["proxied"] == 0
        assert result["records"] == []

    def test_counts_by_type(self):
        records = [
            {"type": "A", "name": "example.com", "content": "1.2.3.4", "ttl": 300, "proxied": True},
            {"type": "A", "name": "www.example.com", "content": "1.2.3.4", "ttl": 300, "proxied": True},
            {"type": "MX", "name": "example.com", "content": "mail.example.com", "ttl": 3600, "proxied": False},
        ]
        result = summarise(records)
        assert result["total"] == 3
        assert result["by_type"]["A"] == 2
        assert result["by_type"]["MX"] == 1
        assert result["proxied"] == 2

    def test_simplified_records(self):
        records = [
            {"type": "CNAME", "name": "www.example.com", "content": "example.com",
             "ttl": 1, "proxied": True, "extra_field": "ignored"},
        ]
        result = summarise(records)
        assert len(result["records"]) == 1
        rec = result["records"][0]
        assert rec["type"] == "CNAME"
        assert rec["proxied"] is True
        assert "extra_field" not in rec

    def test_by_type_sorted(self):
        records = [
            {"type": "TXT", "name": "x", "content": "y", "ttl": 1},
            {"type": "A", "name": "x", "content": "y", "ttl": 1},
            {"type": "MX", "name": "x", "content": "y", "ttl": 1},
        ]
        result = summarise(records)
        keys = list(result["by_type"].keys())
        assert keys == sorted(keys)
