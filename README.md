<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-3776ab?logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/cloudflare-free%20plan-f38020?logo=cloudflare&logoColor=white" alt="Cloudflare Free Plan">
  <img src="https://img.shields.io/badge/tests-203%20passing-brightgreen" alt="203 tests passing">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT License">
  <img src="https://img.shields.io/badge/read--only-no%20changes%20made-informational" alt="Read-only">
</p>

# Cloudflare Reporting

A read-only security audit toolkit for Cloudflare. Auto-discovers all zones on an API token, runs 25+ checks across DNS, email, TLS, registrar, and infrastructure, then produces reports and an interactive dashboard.

Works on **Cloudflare Free plan**. No changes are made to any zone.

---

## Quick start

### 1. Install

**Prerequisites:** [Git](https://git-scm.com/downloads) and [Python 3.10+](https://www.python.org/downloads/) (Windows: install Python from the Microsoft Store for the easiest setup).

<details>
<summary><strong>macOS / Linux</strong></summary>

```bash
git clone https://github.com/wblv-dev/cloudflare-reporting
cd cloudflare-reporting
python3 -m venv .venv
source .venv/bin/activate
pip install .
```
</details>

<details>
<summary><strong>Windows (PowerShell)</strong></summary>

```powershell
git clone https://github.com/wblv-dev/cloudflare-reporting
cd cloudflare-reporting
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install .
```

> If PowerShell blocks the activate script, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` first.
</details>

### 2. Create a Cloudflare API token

1. Log in to the [Cloudflare dashboard](https://dash.cloudflare.com/)
2. Go to **My Profile** → **API Tokens** → **Create Token**
3. Choose **Custom token** and set:
   - **Permissions:** Zone → Zone → Read, Zone → DNS → Read
   - **Zone resources:** Include → All zones
4. Copy the token

> Full guide: [Cloudflare API token docs](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/)

### 3. Run the audit

```bash
export CF_API_TOKEN="your_token_here"    # Windows: $env:CF_API_TOKEN="your_token_here"
cf-audit
```

That's it. The tool auto-discovers every zone on the token and produces:

| File | Description |
|------|-------------|
| `audit_report.html` | Static report with tabs, search, dark mode, remediations |
| `AUDIT_REPORT.md` | Markdown — Git-friendly, human-readable |
| `audit_report.csv` | One row per domain — for spreadsheets or automation |
| `audit_history.db` | SQLite database — cumulative across runs |

### 4. Launch the dashboard

```bash
cf-dashboard
```

Opens an interactive dashboard at [http://localhost:8001](http://localhost:8001) powered by [Datasette](https://datasette.io/). Includes pre-built queries for compliance overview, all failures, grade trends, domain summary, and audit history — plus a SQL editor for custom queries.

---

## Example output

```
$ cf-audit --domains example.com

[1/7] Resolving zone IDs for 1 domain(s) ...
       Found 1 zone(s): example.com
[2/7] Fetching DNS inventory and zone settings ...
  [DNS] example.com: 24 record(s) fetched
  [SECURITY] example.com: 9/11 checks passed
[3/7] Running live DNS checks ...
  [DNSSEC] example.com: PASS
  [CAA] example.com: PASS
  [EMAIL] example.com: SPF=PASS  DMARC=PASS
  [BLACKLIST] example.com: PASS
[4/7] Saving results to audit_history.db ...
[5/7] Comparing with previous run ...
[6/7] Writing reports ...
[7/7] Summary
============================================================
  example.com          zone:9/11  SPF:PASS  DMARC:PASS  DNSSEC:PASS  BL:PASS
```

---

## CLI reference

```
cf-audit [options]

Options:
  --domains DOMAIN [...]     Specific domains (default: auto-discover all)
  --output-dir DIR           Output directory (default: current)
  --format {html,md,csv}     Output formats (default: all three)
  --concurrency N            Max concurrent domains (default: 20)
  --verbose, -v              Debug logging to stderr
  --log-file FILE            Write detailed log to file
  --no-diff                  Skip comparison with previous run
  -h, --help                 Full help with all checks listed

cf-dashboard [options]

Options:
  --db FILE                  SQLite database path (default: audit_history.db)
  --port PORT                Port (default: 8001)
  --host HOST                Bind address (default: 127.0.0.1)

Exit codes:
  0     All checks passed or warned
  1     Configuration or runtime error
  2     At least one FAIL grade
```

---

## What it checks

### Cloudflare API (single bulk call per zone)

| Check | Recommended | FAIL when |
|-------|-------------|-----------|
| SSL mode | `full (strict)` | `off` |
| Minimum TLS version | `1.2` | `1.0` |
| TLS 1.3 | `on` | `off` |
| Always Use HTTPS | `on` | `off` |
| Automatic HTTPS Rewrites | `on` | `off` |
| HSTS | enabled, max-age >= 1yr | disabled |
| Security Level | `medium`+ | `off` |
| Browser Integrity Check | `on` | `off` |
| Email Obfuscation | `on` | `off` |
| Hotlink Protection | `on` | `off` |
| Opportunistic Encryption | `on` | `off` |

### Live DNS (no token required)

| Check | What it catches |
|-------|-----------------|
| SPF | Missing record, `+all`, soft fail vs hard fail |
| DMARC | Missing record, `p=none` vs `p=reject` |
| DKIM | Missing selectors for Google, Microsoft 365, ProtonMail, etc. |
| DNSSEC | Enabled in Cloudflare but DS not added at registrar |
| CAA | Missing records, incompatible CAs for Cloudflare |
| Dangling CNAMEs | Subdomain takeover risk (target returns NXDOMAIN) |
| Blacklist (DNSBL) | Mail server IPs on Spamhaus, SpamCop, Barracuda, etc. |
| Reverse DNS | Missing PTR records on mail servers |
| MTA-STS | Broken configs, enforce vs testing mode |
| TLSRPT | Missing TLS reporting destination |
| BIMI | Brand logo presence, VMC certificate |

### Registrar (via RDAP)

| Check | Thresholds |
|-------|-----------|
| Domain expiry | FAIL < 30 days, WARN < 90 days |
| Transfer lock | WARN if missing |

---

## Grading

| Grade | Meaning |
|-------|---------|
| **PASS** | Meets recommended configuration |
| **WARN** | Functional but not optimal |
| **FAIL** | Missing or insecure |
| **INFO** | Neutral or unavailable on current plan |

The HTML report includes a **Remediations** tab with step-by-step fix instructions for every FAIL and WARN finding, prioritised as Critical / High / Medium / Low.

---

## Project structure

```
cloudflare-reporting/
├── README.md
├── LICENSE
├── pyproject.toml
├── .gitignore
│
├── cloudflare_reporting/          # Python package
│   ├── __main__.py                # python -m cloudflare_reporting
│   ├── cli.py                     # cf-audit entry point
│   ├── dashboard.py               # cf-dashboard entry point
│   ├── config.py                  # Defaults (overridden by CLI args)
│   ├── datasette_metadata.json    # Dashboard queries
│   ├── checks/                    # One module per check category
│   │   ├── blacklist.py
│   │   ├── dns_inventory.py
│   │   ├── dns_security.py
│   │   ├── email_security.py
│   │   ├── email_standards.py
│   │   ├── registrar.py
│   │   ├── reverse_dns.py
│   │   └── zone_security.py
│   └── lib/                       # Shared infrastructure
│       ├── cf_client.py           # Cloudflare API client + retry
│       ├── concurrency.py         # Semaphore throttling
│       ├── database.py            # SQLite persistence
│       ├── diff.py                # Run-to-run comparison
│       ├── dns_resolver.py        # dnspython wrapper
│       ├── log.py                 # Structured logging
│       ├── remediation.py         # Fix instructions + tooltips
│       └── reporter.py            # HTML, Markdown, CSV output
│
└── tests/                         # 203 tests
```

---

## Testing

```bash
pip install pytest
python -m pytest tests/ -v
```

203 tests across 14 files covering grading logic, database persistence, report generation, and security:

| Suite | Tests | Covers |
|-------|-------|--------|
| `test_security.py` | 30 | XSS, SQL injection, credential leakage, input validation, DoS |
| `test_zone_security.py` | 26 | All 11 zone settings + HSTS + bulk extraction |
| `test_registrar.py` | 20 | Expiry/lock grading, RDAP parsing |
| `test_email_standards.py` | 17 | MTA-STS, TLSRPT, BIMI grading |
| `test_blacklist.py` | 16 | IP reversal, cloud detection, DNSBL grading |
| `test_dns_security.py` | 15 | DNSSEC, CAA, dangling CNAME grading |
| `test_remediation.py` | 13 | Tooltip lookup, fix instructions, priority sorting |
| `test_dns_resolver.py` | 11 | SPF + DMARC grading |
| `test_reporter.py` | 11 | Grade helpers, badges, CSV output |
| `test_diff.py` | 10 | Run comparison, regressions, DNS changes |
| `test_database.py` | 7 | Core CRUD + rollback |
| `test_reverse_dns.py` | 7 | PTR grading |
| `test_database_new.py` | 5 | Registrar, DNS security, blacklist, rDNS persistence |
| `test_dns_inventory.py` | 4 | Record summarisation |

---

## Configuration

Defaults are in `cloudflare_reporting/config.py` but CLI arguments override everything:

| Setting | Default | CLI flag |
|---------|---------|----------|
| Domains | Auto-discover all | `--domains` |
| Output directory | Current | `--output-dir` |
| Output formats | html, md, csv | `--format` |
| DNS resolver | `1.1.1.1` | Edit config.py |
| API timeout | 30s | Edit config.py |
| Concurrency | 20 domains | `--concurrency` |

Custom DKIM selectors can be added in `cloudflare_reporting/checks/email_security.py` → `DKIM_SELECTORS`.

---

## Large accounts

The tool is designed for accounts with 100+ zones. Concurrency is controlled by semaphores:

| Resource | Default limit | Purpose |
|----------|---------------|---------|
| Domains | 20 concurrent | `--concurrency` flag |
| Cloudflare API | 10 concurrent | Stays within 1,200 req/5min |
| DNS queries | 30 concurrent | Prevents resolver flooding |
| RDAP lookups | 5 concurrent + retry | rdap.org rate limits |
| HTTP fetches | 10 concurrent | MTA-STS policy fetches |

For a 180-zone enterprise account, expect 2–5 minutes at default concurrency.

---

## Security

- **Read-only** — never writes to Cloudflare. Token only needs `Zone:Read` + `DNS:Read`.
- **No credential leakage** — RDAP and MTA-STS calls use their own unauthenticated HTTP sessions.
- **XSS-safe reports** — all user-controlled data is HTML-escaped.
- **Parameterised SQL** — no string interpolation in queries.
- **30 security tests** — XSS, SQL injection, credential leakage, input validation, denial of service.

---

## References

| Topic | Link |
|-------|------|
| Cloudflare API | [developers.cloudflare.com/api](https://developers.cloudflare.com/api/) |
| API token setup | [Cloudflare token docs](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/) |
| Datasette | [datasette.io](https://datasette.io/) |
| SPF (RFC 7208) | [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc7208) |
| DMARC (RFC 7489) | [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc7489) |
| DKIM (RFC 6376) | [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc6376) |
| CAA (RFC 8659) | [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc8659) |
| DNSSEC | [cloudflare.com](https://www.cloudflare.com/dns/dnssec/how-dnssec-works/) |
| RDAP | [about.rdap.org](https://about.rdap.org/) |
