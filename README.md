# cloudflare-reporting

A read-only Cloudflare DNS audit toolkit. Queries the Cloudflare API and performs
live DNS lookups to produce both a Markdown report and an HTML dashboard covering:

- **DNS inventory** — every record across all zones accessible to the token
- **Email security** — live MX, SPF, DMARC, and DKIM validation with grades
- **Zone security** — SSL mode, TLS version, HSTS, HTTPS redirect settings
- **Registrar status** — domain expiry, transfer lock, nameservers via RDAP
- **DNSSEC** — DNSKEY and DS record validation
- **CAA records** — Certificate Authority Authorization with Cloudflare compatibility check
- **Dangling CNAMEs** — subdomain takeover risk detection
- **Blacklist (DNSBL)** — mail server IP reputation against major DNS blacklists
- **Reverse DNS** — PTR record validation with forward-confirmed rDNS (FCrDNS)
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

## Checks

### Cloudflare API checks (require token)

| Check | What it does |
|-------|-------------|
| DNS inventory | Fetches all DNS records per zone via the API |
| Zone security | Reads SSL mode, min TLS version, TLS 1.3, HSTS, HTTPS redirect, opportunistic encryption |

### Live DNS checks (no token required)

| Check | What it does |
|-------|-------------|
| SPF | Validates `v=spf1` TXT record and grades the `all` mechanism |
| DMARC | Validates `_dmarc` TXT record and grades the policy (`reject`/`quarantine`/`none`) |
| DKIM | Probes 10 common selectors (`google`, `selector1`, `protonmail`, etc.) |
| MX | Lists mail exchangers and detects null MX (RFC 7505) |
| DNSSEC | Queries DNSKEY at the zone and DS at the parent to verify the chain of trust |
| CAA | Reads CAA records and checks Cloudflare CA compatibility (`letsencrypt.org`, `digicert.com`, `pki.goog`, etc.) |
| Dangling CNAMEs | Resolves all CNAME targets and flags any returning NXDOMAIN (subdomain takeover risk) |
| Blacklist (DNSBL) | Resolves MX to IPs, checks against 6 major blacklists (Spamhaus, SpamCop, Barracuda, etc.) |
| Reverse DNS | PTR lookup for mail server IPs with forward-confirmed rDNS validation |

### Registrar checks (via RDAP)

| Check | What it does |
|-------|-------------|
| Domain expiry | FAIL if <30 days, WARN if <90 days, PASS if >90 days |
| Transfer lock | Checks for `clientTransferProhibited` status |
| Nameservers | Lists nameservers from RDAP registration data |
| Registrar | Identifies the current registrar |

## Structure

```
├── audit.py                  # Entry point — async orchestrator
├── config.py                 # Domains, token, output paths
├── requirements.txt
├── checks/                   # Audit check modules
│   ├── blacklist.py          #   DNSBL checks for mail server IPs
│   ├── dns_inventory.py      #   Fetches and summarises all DNS records via API
│   ├── dns_security.py       #   DNSSEC, CAA, and dangling CNAME checks
│   ├── email_security.py     #   MX / SPF / DMARC / DKIM checks (async)
│   ├── registrar.py          #   Domain registration checks via RDAP
│   ├── reverse_dns.py        #   PTR / rDNS validation for mail servers
│   └── zone_security.py      #   SSL, TLS, HSTS and security settings (async)
├── lib/                      # Shared infrastructure
│   ├── cf_client.py          #   Async aiohttp Cloudflare API client with retry/backoff
│   ├── database.py           #   SQLite persistence — single connection, context manager
│   ├── dns_resolver.py       #   Live DNS lookups and grading (dnspython)
│   └── reporter.py           #   Writes Markdown and HTML reports
└── tests/                    # Unit tests (pytest) — 113 tests
```

## Testing

```bash
pip install pytest
python -m pytest tests/ -v
```

### Test coverage

| Test file | Module | Tests | What's covered |
|-----------|--------|-------|----------------|
| `test_dns_resolver.py` | `dns_resolver` | 11 | SPF grading (hard fail, soft fail, +all, neutral, missing, incomplete), DMARC grading (reject, quarantine, none, missing, unknown policy) |
| `test_dns_inventory.py` | `dns_inventory` | 4 | `summarise()` — empty input, type counting, proxied counting, simplified record shape, sorted by_type keys |
| `test_zone_security.py` | `zone_security` | 13 | SSL mode grading (full/strict/flexible/off), min TLS version, TLS 1.3, Always HTTPS, unavailable settings, HSTS (disabled/enabled/low max-age/unavailable) |
| `test_reporter.py` | `reporter` | 9 | `_worst()` grade ordering, `_sym()` symbol mapping, `_truncate()` string truncation, `_badge()` HTML badge generation |
| `test_database.py` | `database` | 7 | Run creation, ID incrementing, DNS record save/get, email check save/get, zone settings save/get, run listing, rollback on error |
| `test_database_new.py` | `database` | 5 | Registrar check save/get, DNS security save/get, blacklist check save/get (clean + listed), reverse DNS save/get |
| `test_registrar.py` | `registrar` | 20 | Expiry grading (expired, critical, warn, pass, boundary cases), lock grading (locked/unlocked/server-locked/empty), RDAP parsing (expiry events, statuses, nameservers, registrar vCard/handle) |
| `test_dns_security.py` | `dns_security` | 15 | DNSSEC grading (full/partial/none/DS-without-DNSKEY), CAA grading (no records, CF-compatible CAs, incompatible CAs, issuewild, non-CF mode), dangling CNAME grading (none, one, many with truncation) |
| `test_blacklist.py` | `blacklist` | 16 | IP reversal, cloud mail detection (Google/Microsoft/Mimecast/self-hosted), blacklist grading (cloud-only, clean, major listing, minor listing, mixed severity, empty, multi-IP) |
| `test_reverse_dns.py` | `reverse_dns` | 7 | PTR grading — no MX, all confirmed, missing PTR, mismatch, mixed missing+confirmed, mixed mismatch+confirmed, multiple missing |

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

-- Domain expiry trend
SELECT r.started_at, rc.domain, rc.expiry_days, rc.expiry_grade
FROM registrar_checks rc JOIN runs r ON r.id = rc.run_id
ORDER BY r.id DESC;

-- Blacklist history
SELECT r.started_at, bc.domain, bc.grade, bc.reason
FROM blacklist_checks bc JOIN runs r ON r.id = bc.run_id
ORDER BY r.id DESC;
```

## Notes

- WAF managed ruleset checks require Cloudflare Pro or above and are not included.
- DKIM probes common selectors. Add your provider's selector to `email_security.py`
  if it isn't in the default list.
- Concurrent API requests via `asyncio` and `aiohttp` — fast even on large accounts.
- RDAP is used for registrar checks (no API key required). Some ccTLDs may not support RDAP.
- Blacklist checks skip cloud mail provider IPs (Google, Microsoft, etc.) as they
  are managed by the provider and not actionable.
