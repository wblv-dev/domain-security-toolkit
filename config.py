"""
config.py — Toolkit configuration.

Set CF_API_TOKEN as an environment variable before running:
    export CF_API_TOKEN="your_token_here"

Token requires: Zone:Read, DNS:Read (read-only — this tool makes no changes).
"""

import os

# ── Cloudflare ────────────────────────────────────────────────────────────────

CF_API_TOKEN = os.getenv("CF_API_TOKEN", "")
CF_API_BASE  = "https://api.cloudflare.com/client/v4"
CF_TIMEOUT   = 30

# ── Domains to audit ──────────────────────────────────────────────────────────

# Leave empty to auto-discover all zones accessible to the API token.
DOMAINS = []

# ── DNS resolver ──────────────────────────────────────────────────────────────

# Public resolver used for live DNS validation.
# 1.1.1.1 = Cloudflare, 8.8.8.8 = Google — either works.
DNS_RESOLVER = "1.1.1.1"
DNS_TIMEOUT  = 5.0

# ── Output ────────────────────────────────────────────────────────────────────

OUTPUT_MD   = "AUDIT_REPORT.md"
OUTPUT_HTML = "audit_report.html"
DB_PATH     = "audit_history.db"
