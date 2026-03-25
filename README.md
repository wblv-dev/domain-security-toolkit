# cloudflare-reporting

A read-only Cloudflare DNS audit toolkit. Queries the Cloudflare API and performs
live DNS lookups to produce both a Markdown report and an HTML dashboard covering:

- **DNS inventory** — every record across all zones accessible to the token
- **Email security** — live MX, SPF, DMARC, and DKIM validation with grades
- **Zone security** — SSL mode, TLS version, HSTS, HTTPS redirect settings
- **Audit history** — every run persisted to SQLite, queryable over time

All checks are read-only. No changes are made to any zone.

## Requirements

- Python 3.10+
- Cloudflare API token with `Zone:Read` and `DNS:Read` scopes

## Setup

```bash
git clone https://github.com/wblv-dev/cloudflare-reporting
cd cloudflare-reporting
pip install -r requirements.txt
export CF_API_TOKEN="your_token_here"
```

## Usage

```bash
python audit.py
```

By default the tool **auto-discovers every zone** accessible to the API token.
To restrict to specific domains, set them in `config.py`:

```python
DOMAINS = [
    "yourdomain.com",
    "anotherdomain.org",
]
```

Three files are written on each run:

| File | Description |
|------|-------------|
| `AUDIT_REPORT.md` | Markdown report — Git-friendly, human-readable |
| `audit_report.html` | HTML dashboard — open in any browser |
| `audit_history.db` | SQLite database — grows with each run |

## Configuration

Edit `config.py` to customise behaviour:

| Setting | Default | Description |
|---------|---------|-------------|
| `DOMAINS` | `[]` (auto-discover) | Leave empty to audit all zones, or list specific domains |
| `DNS_RESOLVER` | `1.1.1.1` | Public resolver for live DNS validation |
| `CF_TIMEOUT` | `30` | Cloudflare API timeout in seconds |

To probe additional DKIM selectors for your mail provider, add them to
`DKIM_SELECTORS` in `email_security.py`.

## Structure

| File | Purpose |
|------|---------|
| `audit.py` | Entry point — async orchestrator |
| `config.py` | Domains, token, output paths |
| `cf_client.py` | Async aiohttp Cloudflare API client with retry/backoff |
| `dns_resolver.py` | Live DNS lookups and grading (dnspython) |
| `dns_inventory.py` | Fetches and summarises all DNS records via API |
| `email_security.py` | MX / SPF / DMARC / DKIM checks (async) |
| `zone_security.py` | SSL, TLS, HSTS and security settings (async) |
| `database.py` | SQLite persistence — single connection, context manager |
| `reporter.py` | Writes Markdown and HTML reports |
| `tests/` | Unit tests (pytest) |

## Testing

```bash
pip install pytest
python -m pytest tests/ -v
```

## Grading

| Grade | Meaning |
|-------|---------|
| ✅ PASS | Meets recommended configuration |
| ⚠️ WARN | Functional but not optimal (e.g. SPF `~all` vs `-all`) |
| ❌ FAIL | Missing or insecure (e.g. no DMARC, TLS 1.0 enabled) |
| ℹ️ INFO | Neutral finding or setting unavailable on Free plan |

## Querying audit history

```bash
sqlite3 audit_history.db

-- All runs
SELECT id, started_at, domains FROM runs;

-- DMARC grade over time for a domain
SELECT r.started_at, e.dmarc_grade
FROM email_checks e JOIN runs r ON r.id = e.run_id
WHERE e.domain = 'yourdomain.com'
ORDER BY r.id DESC;

-- Security check failures across all runs
SELECT r.started_at, zs.domain, zs.label, zs.actual
FROM zone_settings zs JOIN runs r ON r.id = zs.run_id
WHERE zs.grade = 'FAIL'
ORDER BY r.id DESC;
```

## Notes

- WAF managed ruleset checks require Cloudflare Pro or above and are not included.
- DKIM probes common selectors. Add your provider's selector to `email_security.py`
  if it isn't in the default list.
- Concurrent API requests via `asyncio` and `aiohttp` — fast even on large accounts.
