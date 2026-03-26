<div align="center">

# Cloudflare Reporting

**The easiest way to audit your Cloudflare security configuration.**

Run one command. Get a full security report across every zone on your account.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776ab?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Cloudflare Free Plan](https://img.shields.io/badge/cloudflare-free%20plan-f38020?logo=cloudflare&logoColor=white)](https://www.cloudflare.com/)
[![Tests](https://img.shields.io/badge/tests-203%20passing-brightgreen)](https://github.com/wblv-dev/cloudflare-reporting/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

</div>

---

```
$ cf-audit

[1/7] Discovering all zones on this API token ...
       Found 3 zone(s): example.com, example.org, example.co.uk
[2/7] Fetching DNS inventory and zone settings ...
[3/7] Running live DNS checks ...
[4/7] Saving results to audit_history.db ...
[5/7] Comparing with previous run ...
[6/7] Writing reports ...
[7/7] Summary
============================================================
  example.com          zone:9/11  SPF:PASS  DMARC:PASS  DNSSEC:PASS
  example.org          zone:8/11  SPF:PASS  DMARC:WARN  DNSSEC:WARN
  example.co.uk        zone:6/11  SPF:FAIL  DMARC:FAIL  DNSSEC:WARN
```

`cf-audit` auto-discovers every zone on your API token and checks **25+ security settings** — TLS configuration, email authentication, DNSSEC, dangling CNAMEs, blacklists, domain expiry, and more. Results go into a static HTML report with remediation guidance, plus an interactive [Datasette](https://datasette.io/) dashboard for drilling into the data.

**Read-only.** Never writes to Cloudflare. Your token only needs `Zone:Read` + `DNS:Read`.

---

## Install

```bash
git clone https://github.com/wblv-dev/cloudflare-reporting
cd cloudflare-reporting
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
pip install .
```

<details>
<summary>Don't have Python?</summary>

| Platform | Easiest method |
|----------|---------------|
| **Windows** | Search "Python" in the Microsoft Store |
| **macOS** | `brew install python` |
| **Linux** | `sudo apt install python3 python3-pip python3-venv` |

</details>

## Set up your Cloudflare token

1. [Cloudflare dashboard](https://dash.cloudflare.com/) → **My Profile** → **API Tokens** → **Create Token**
2. Permissions: **Zone → Zone → Read** and **Zone → DNS → Read**
3. Zone resources: **Include → All zones**

```bash
export CF_API_TOKEN="your_token_here"       # Windows: $env:CF_API_TOKEN="your_token_here"
```

> Full guide → [Cloudflare API token docs](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/)

## Run

```bash
cf-audit                                     # Audit all zones
cf-audit --domains example.com example.org   # Specific domains only
cf-audit --output-dir /tmp/reports           # Custom output location
cf-audit --verbose --log-file audit.log      # Debug logging
```

Opens four output files:

| File | What |
|------|------|
| `audit_report.html` | Static report — tabs, search, dark mode, **remediation steps** |
| `AUDIT_REPORT.md` | Markdown — commit it, diff it |
| `audit_report.csv` | One row per domain — for spreadsheets |
| `audit_history.db` | SQLite — cumulative across runs |

### Dashboard

```bash
cf-dashboard                                 # http://localhost:8001
```

Interactive [Datasette](https://datasette.io/) dashboard with pre-built queries, charts, SQL editor, and full audit history. [See Datasette docs →](https://docs.datasette.io/)

---

## What it checks

<table>
<tr><td>

**Cloudflare settings** (API)
- SSL mode
- Minimum TLS version
- TLS 1.3
- Always Use HTTPS
- HTTPS Rewrites
- HSTS (+ preload, subdomains)
- Security Level
- Browser Integrity Check
- Email Obfuscation
- Hotlink Protection
- Opportunistic Encryption

</td><td>

**Email security** (DNS)
- SPF record + grading
- DMARC policy + grading
- DKIM (10 selectors)
- MTA-STS
- TLSRPT
- BIMI

</td><td>

**Infrastructure** (DNS + RDAP)
- DNSSEC validation
- CAA records (CF compatibility)
- Dangling CNAMEs (takeover risk)
- DNSBL blacklist (6 lists)
- Reverse DNS (FCrDNS)
- Domain expiry
- Transfer lock
- DNS record inventory

</td></tr>
</table>

Every check grades as **PASS** / **WARN** / **FAIL** / **INFO**. The HTML report includes a **Remediations** tab with step-by-step fix instructions for every finding, prioritised Critical → Low.

---

## CLI reference

```
cf-audit [options]

  --domains DOMAIN [...]     Audit specific domains (default: all zones)
  --output-dir DIR           Output directory (default: .)
  --format {html,md,csv}     Output formats (default: all)
  --concurrency N            Max concurrent domains (default: 20)
  --verbose, -v              Debug logging
  --log-file FILE            Log to file
  --no-diff                  Skip previous-run comparison
  -h, --help                 Full help

cf-dashboard [options]

  --db FILE                  Database path (default: audit_history.db)
  --port PORT                Port (default: 8001)
  --host HOST                Bind address (default: 127.0.0.1)

Exit codes:  0 = pass/warn   1 = error   2 = at least one FAIL
```

---

## Large accounts

Built for enterprise — tested with 100+ zones. Concurrency is semaphore-controlled:

| Resource | Limit | Why |
|----------|-------|-----|
| Domains | 20 concurrent | `--concurrency` flag |
| Cloudflare API | 10 concurrent | Stays within rate limits |
| DNS queries | 30 concurrent | Prevents resolver flooding |
| RDAP lookups | 5 + retry | rdap.org rate limits |
| HTTP fetches | 10 concurrent | MTA-STS policy fetches |

A 180-zone account completes in 2–5 minutes.

---

## Security

- **Read-only** — never writes to Cloudflare
- **No credential leakage** — RDAP/MTA-STS use separate unauthenticated sessions
- **XSS-safe** — all user data HTML-escaped in reports
- **Parameterised SQL** — no string interpolation
- **203 tests** including 30 dedicated security tests (XSS, SQLi, credential leakage, input validation, DoS)

---

## Project structure

```
cloudflare-reporting/
├── README.md
├── LICENSE
├── pyproject.toml
├── cloudflare_reporting/       # pip install .
│   ├── cli.py                  # cf-audit
│   ├── dashboard.py            # cf-dashboard
│   ├── checks/                 # One module per check category
│   └── lib/                    # API client, database, reporter, etc.
└── tests/                      # 203 tests
```

## Testing

```bash
pip install pytest
python -m pytest tests/ -v
```

---

## Contributing

Issues and pull requests welcome. Please run the test suite before submitting.

## License

[MIT](LICENSE)

## References

[Cloudflare API](https://developers.cloudflare.com/api/) · [Datasette](https://datasette.io/) · [SPF (RFC 7208)](https://www.rfc-editor.org/rfc/rfc7208) · [DMARC (RFC 7489)](https://www.rfc-editor.org/rfc/rfc7489) · [DKIM (RFC 6376)](https://www.rfc-editor.org/rfc/rfc6376) · [CAA (RFC 8659)](https://www.rfc-editor.org/rfc/rfc8659) · [DNSSEC](https://www.cloudflare.com/dns/dnssec/how-dnssec-works/) · [RDAP](https://about.rdap.org/)
