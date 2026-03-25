<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-3776ab?logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/cloudflare-free%20plan-f38020?logo=cloudflare&logoColor=white" alt="Cloudflare Free Plan">
  <img src="https://img.shields.io/badge/tests-190%20passing-brightgreen" alt="190 tests passing">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT License">
  <img src="https://img.shields.io/badge/read--only-no%20changes%20made-informational" alt="Read-only">
</p>

# Cloudflare Reporting

A read-only security audit toolkit for Cloudflare. Auto-discovers all zones on an API token, runs 20+ checks across DNS, email, TLS, registrar, and infrastructure, and produces interactive HTML, Markdown, and CSV reports.

Works on **Cloudflare Free plan**. No changes are made to any zone.

## Example output

```
[1/6] Discovering all zones on this API token ...
       Found 2 zone(s): example.com, example.org

[2/6] Fetching DNS inventory and zone settings ...
  [DNS] example.com: 19 record(s) fetched
  [SECURITY] example.com: 8/11 checks passed

[3/6] Running live DNS checks ...
  [DNSSEC] example.com: PASS
  [CAA] example.com: PASS
  [DANGLING] example.com: PASS
  [EMAIL] example.com: SPF=PASS  DMARC=PASS
  [BLACKLIST] example.com: PASS
  [rDNS] example.com: PASS

[4/6] Saving results to audit_history.db ...
[5/6] Writing reports ...
[6/6] Summary
============================================================
  example.com          zone:8/11  SPF:PASS  DMARC:PASS  DNSSEC:PASS  BL:PASS
```

The HTML report includes tabbed navigation, dark mode, domain search/filter, sortable tables, and interactive progress rings:

| Grade | Meaning |
|-------|---------|
| **PASS** | Meets recommended configuration |
| **WARN** | Functional but not optimal (e.g. SPF `~all` instead of `-all`) |
| **FAIL** | Missing or insecure (e.g. no DMARC record, TLS 1.0 enabled) |
| **INFO** | Neutral finding or setting not available on current plan |

---

## Quick start

### 1. Prerequisites

| Tool | Install |
|------|---------|
| **Git** | [git-scm.com](https://git-scm.com/downloads) — on Windows, reopen PowerShell after installing |
| **Python 3.10+** | **Windows:** search "Python" in the Microsoft Store (recommended) or `winget install Python.Python.3.12`<br>**macOS:** `brew install python` or [python.org](https://www.python.org/downloads/macos/)<br>**Linux:** `sudo apt install python3 python3-pip python3-venv` |

### 2. Clone and install

<details>
<summary><strong>macOS / Linux</strong></summary>

```bash
git clone https://github.com/wblv-dev/cloudflare-reporting
cd cloudflare-reporting
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
</details>

<details>
<summary><strong>Windows (PowerShell)</strong></summary>

```powershell
git clone https://github.com/wblv-dev/cloudflare-reporting
cd cloudflare-reporting
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

> If PowerShell blocks the activate script, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` first.
</details>

### 3. Create a Cloudflare API token

1. Log in to the [Cloudflare dashboard](https://dash.cloudflare.com/)
2. Go to **My Profile** → **API Tokens** → **Create Token**
3. Choose **Custom token** and set:
   - **Permissions:** Zone → Zone → Read, Zone → DNS → Read
   - **Zone resources:** Include → All zones
4. Copy the token

> Full guide: [Cloudflare API token docs](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/)

### 4. Run the audit

```bash
# macOS / Linux
export CF_API_TOKEN="your_token_here"
python3 audit.py

# Windows (PowerShell)
$env:CF_API_TOKEN="your_token_here"
python audit.py
```

### CLI options

```
python3 audit.py --help

options:
  --domains DOMAIN [DOMAIN ...]   Specific domains to audit (default: auto-discover all)
  --output-dir DIR                Directory for output files (default: current)
  --format {html,md,csv}          Output formats (default: all three)
  --verbose, -v                   Enable debug logging
  --log-file FILE                 Write detailed log to file
  --no-diff                       Skip comparison with previous run
```

**Exit codes:** `0` = all checks passed or warned, `2` = at least one FAIL grade (useful for CI/cron alerting).

Four output files are generated:

| File | Format | Description |
|------|--------|-------------|
| `audit_report.html` | HTML | Interactive dashboard with tabs, search, dark mode |
| `AUDIT_REPORT.md` | Markdown | Git-friendly, human-readable |
| `audit_report.csv` | CSV | One row per domain — for spreadsheets or automation |
| `audit_history.db` | SQLite | Cumulative history across runs |

---

## What it checks

### Cloudflare API (requires token)

Uses a single bulk `GET /zones/{id}/settings` call per zone:

| Check | Recommended | Grades |
|-------|-------------|--------|
| SSL mode | `full (strict)` | `off` = FAIL, `flexible` = WARN |
| Minimum TLS version | `1.2` | `1.0` = FAIL, `1.1` = WARN |
| TLS 1.3 | `on` | `off` = FAIL |
| Always Use HTTPS | `on` | `off` = FAIL |
| Automatic HTTPS Rewrites | `on` | `off` = FAIL |
| HSTS | enabled, max-age >= 1 year | disabled = WARN, low max-age = WARN |
| Security Level | `medium`+ | `off` = FAIL, `low` = WARN |
| Browser Integrity Check | `on` | `off` = FAIL |
| Email Obfuscation | `on` | `off` = FAIL |
| Hotlink Protection | `on` | `off` = FAIL |
| Opportunistic Encryption | `on` | `off` = FAIL |

### Live DNS (no token needed)

| Check | Method | What it catches |
|-------|--------|-----------------|
| SPF | TXT lookup at domain | Missing record, `+all`, soft fail vs hard fail |
| DMARC | TXT lookup at `_dmarc.` | Missing record, `p=none` vs `p=reject` |
| DKIM | TXT lookup at 10 common selectors | Missing selectors for Google, Microsoft 365, ProtonMail, etc. |
| DNSSEC | DNSKEY + DS record queries | Enabled in Cloudflare but DS not added at registrar |
| CAA | CAA record lookup | Missing records, incompatible CAs for Cloudflare |
| Dangling CNAMEs | Resolve all CNAME targets | Subdomain takeover risk (target returns NXDOMAIN) |
| Blacklist (DNSBL) | Reverse lookup against 6 lists | Mail server IPs on Spamhaus, SpamCop, Barracuda, etc. |
| Reverse DNS | PTR + forward confirmation | Missing PTR records on mail servers |
| MTA-STS | TXT at `_mta-sts.` + HTTPS policy fetch | Broken MTA-STS configs, enforce vs testing mode |
| TLSRPT | TXT at `_smtp._tls.` | Missing TLS reporting destination |
| BIMI | TXT at `default._bimi.` | Brand logo presence, VMC certificate |

### Registrar (via RDAP)

| Check | Thresholds |
|-------|-----------|
| Domain expiry | FAIL < 30 days, WARN < 90 days |
| Transfer lock | WARN if `clientTransferProhibited` missing |

---

## How it works

The audit runs in 6 stages:

```
1. Zone discovery      Finds all zones on the API token (or uses config list)
2. API checks          Fetches DNS records + zone settings via Cloudflare API
3. Live DNS checks     SPF, DMARC, DKIM, DNSSEC, CAA, dangling CNAMEs,
                       blacklists, reverse DNS — all via dnspython
4. Persist             Saves everything to SQLite (audit_history.db)
5. Report              Generates HTML, Markdown, and CSV
6. Summary             Prints grade summary to terminal
```

All API and DNS checks run concurrently using `asyncio` — a 50-zone account typically completes in under 30 seconds.

### Code structure

```
cloudflare-reporting/
├── audit.py                  # Entry point — async orchestrator
├── config.py                 # Domains, token, output paths
├── requirements.txt          # aiohttp, dnspython
│
├── checks/                   # One module per check category
│   ├── blacklist.py          #   DNSBL checks for mail server IPs
│   ├── dns_inventory.py      #   DNS record fetching via Cloudflare API
│   ├── dns_security.py       #   DNSSEC, CAA, dangling CNAME detection
│   ├── email_security.py     #   MX, SPF, DMARC, DKIM validation
│   ├── email_standards.py    #   MTA-STS, TLSRPT, BIMI checks
│   ├── registrar.py          #   Domain expiry + lock via RDAP
│   ├── reverse_dns.py        #   PTR / forward-confirmed rDNS
│   └── zone_security.py      #   TLS, HSTS, security settings (bulk API)
│
├── lib/                      # Shared infrastructure
│   ├── cf_client.py          #   Async Cloudflare API client + retry/backoff
│   ├── database.py           #   SQLite persistence layer
│   ├── diff.py               #   Run-to-run comparison engine
│   ├── dns_resolver.py       #   dnspython wrapper + grading functions
│   ├── log.py                #   Structured logging
│   └── reporter.py           #   HTML, Markdown, and CSV report generation
│
└── tests/                    # 163 tests (pytest)
    ├── test_blacklist.py
    ├── test_database.py
    ├── test_database_new.py
    ├── test_dns_inventory.py
    ├── test_dns_resolver.py
    ├── test_dns_security.py
    ├── test_registrar.py
    ├── test_reporter.py
    ├── test_reverse_dns.py
    ├── test_security.py      # Security/pentest tests (XSS, SQLi, credential leak)
    └── test_zone_security.py
```

### Key code excerpts

**Grading a setting** (`checks/zone_security.py`):

```python
CHECKS = [
    {
        "setting":     "ssl",
        "label":       "SSL mode",
        "recommended": "full (strict)",
        "values_pass": {"full", "strict"},
        "values_warn": {"flexible"},
        "values_fail": {"off"},
    },
    # ... 10 more checks
]
```

Each check is a declarative dict — add new checks by appending to the list.

**Dangling CNAME detection** (`checks/dns_security.py`):

```python
for record in cname_records:
    target = record.get("content", "").rstrip(".")
    results = resolver.query(target, "A")
    if not results:
        results = resolver.query(target, "AAAA")
    if not results:
        dangling.append({"name": record["name"], "target": target})
```

**DNSBL lookup** (`checks/blacklist.py`):

```python
# To check if 1.2.3.4 is listed on zen.spamhaus.org:
# Reverse the IP → 4.3.2.1.zen.spamhaus.org → DNS A lookup
# Response = listed, NXDOMAIN = clean
reversed_ip = _reverse_ip(ip)         # "1.2.3.4" → "4.3.2.1"
lookup = f"{reversed_ip}.{bl['host']}" # "4.3.2.1.zen.spamhaus.org"
results = resolver.query(lookup, "A")  # Listed if response exists
```

---

## Configuration

Edit `config.py`:

| Setting | Default | Description |
|---------|---------|-------------|
| `DOMAINS` | `[]` | Empty = auto-discover all zones. Set specific domains to restrict. |
| `DNS_RESOLVER` | `1.1.1.1` | Public resolver for live DNS checks |
| `CF_TIMEOUT` | `30` | Cloudflare API timeout in seconds |

Custom DKIM selectors can be added in `checks/email_security.py` → `DKIM_SELECTORS`.

---

## Querying audit history

Every run is persisted to SQLite. Query directly:

```sql
-- All audit runs
SELECT id, started_at, domains FROM runs;

-- DMARC grade trend for a domain
SELECT r.started_at, e.dmarc_grade
FROM email_checks e JOIN runs r ON r.id = e.run_id
WHERE e.domain = 'example.com' ORDER BY r.id DESC;

-- All FAIL results across runs
SELECT r.started_at, zs.domain, zs.label, zs.actual
FROM zone_settings zs JOIN runs r ON r.id = zs.run_id
WHERE zs.grade = 'FAIL' ORDER BY r.id DESC;

-- Domain expiry tracking
SELECT r.started_at, rc.domain, rc.expiry_days, rc.expiry_grade
FROM registrar_checks rc JOIN runs r ON r.id = rc.run_id
ORDER BY r.id DESC;
```

---

## Testing

```bash
pip install pytest
python3 -m pytest tests/ -v         # macOS / Linux
python -m pytest tests/ -v          # Windows
```

163 tests across 11 test files covering grading logic, database persistence, report generation, and security:

| Suite | Tests | Covers |
|-------|-------|--------|
| `test_security.py` | 30 | XSS injection, SQL injection, credential leakage, input validation, DoS, config security |
| `test_zone_security.py` | 26 | All 11 zone settings + HSTS + bulk extraction |
| `test_registrar.py` | 20 | Expiry/lock grading, RDAP parsing |
| `test_blacklist.py` | 16 | IP reversal, cloud detection, DNSBL grading |
| `test_dns_security.py` | 15 | DNSSEC, CAA, dangling CNAME grading |
| `test_dns_resolver.py` | 11 | SPF + DMARC grading |
| `test_reporter.py` | 11 | Grade helpers, badge generation, CSV output |
| `test_database.py` | 7 | Core CRUD + rollback |
| `test_reverse_dns.py` | 7 | PTR grading |
| `test_database_new.py` | 5 | Registrar, DNS security, blacklist, rDNS persistence |
| `test_dns_inventory.py` | 4 | Record summarisation |
| `test_email_standards.py` | 17 | MTA-STS grading (enforce/testing/none/unreachable), TLSRPT (valid/malformed), BIMI (full/logo-only/malformed) |
| `test_diff.py` | 10 | Run comparison (first run, identical, regression, improvement, DNS added/removed, multi-category, formatting) |

---

## Security

- **Read-only** — the tool never writes to Cloudflare. Token only needs `Zone:Read` + `DNS:Read`.
- **No credential leakage** — RDAP calls use their own unauthenticated HTTP sessions. The Cloudflare API token is never sent to third parties.
- **XSS-safe reports** — all user-controlled data (domain names, DNS records, etc.) is HTML-escaped in report output.
- **Parameterised queries** — all SQLite operations use parameterised statements. No string interpolation in SQL.
- **Security test suite** — 30 dedicated tests covering XSS, SQL injection, credential leakage, input validation, and denial of service.

---

## Notes

- WAF managed ruleset checks require Cloudflare Pro or above and are not included.
- DKIM probes 10 common selectors. Add your provider's selector to `DKIM_SELECTORS` if needed.
- RDAP is used for registrar checks (no API key required). Some ccTLDs may have limited RDAP support.
- Blacklist checks skip cloud mail provider IPs (Google, Microsoft, etc.) as they are managed by the provider.
- Concurrent requests via `asyncio` and `aiohttp` — fast even on large accounts.

## References

| Topic | Link |
|-------|------|
| Cloudflare API | [developers.cloudflare.com/api](https://developers.cloudflare.com/api/) |
| Creating API tokens | [Cloudflare token docs](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/) |
| SSL/TLS settings | [Cloudflare SSL docs](https://developers.cloudflare.com/ssl/) |
| SPF (RFC 7208) | [rfc-editor.org/rfc/rfc7208](https://www.rfc-editor.org/rfc/rfc7208) |
| DMARC (RFC 7489) | [rfc-editor.org/rfc/rfc7489](https://www.rfc-editor.org/rfc/rfc7489) |
| DKIM (RFC 6376) | [rfc-editor.org/rfc/rfc6376](https://www.rfc-editor.org/rfc/rfc6376) |
| CAA (RFC 8659) | [rfc-editor.org/rfc/rfc8659](https://www.rfc-editor.org/rfc/rfc8659) |
| DNSSEC | [cloudflare.com/dns/dnssec](https://www.cloudflare.com/dns/dnssec/how-dnssec-works/) |
| RDAP | [about.rdap.org](https://about.rdap.org/) |
| DNSBL | [spamhaus.org/faq](https://www.spamhaus.org/faq/section/DNSBL%20Usage) |
| Python | [python.org/downloads](https://www.python.org/downloads/) |
| Git | [git-scm.com/downloads](https://git-scm.com/downloads) |
