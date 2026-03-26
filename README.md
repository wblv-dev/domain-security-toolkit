<div align="center">

<h1>🔒 Domain Security Toolkit</h1>

**Open-source domain security auditing backed by industry standards.**

Run one command. Get a customer-ready security report for any domain.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776ab?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-235%20passing-brightgreen)](https://github.com/wblv-dev/domain-security-toolkit/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Checks](https://img.shields.io/badge/security%20checks-35%2B-8b5cf6)](https://github.com/wblv-dev/domain-security-toolkit)
[![Standards](https://img.shields.io/badge/standards-NIST%20%7C%20OWASP%20%7C%20NCSC%20%7C%20GDPR-f59e0b)](https://github.com/wblv-dev/domain-security-toolkit)

<br>

[Quick start](#quick-start) · [What it checks](#what-it-checks) · [Report output](#what-you-get) · [CLI reference](#all-cli-options) · [OSINT enrichment](#optional-osint-enrichment) · [Cloudflare](#optional-cloudflare-integration) · [Troubleshooting](#troubleshooting)

</div>

---

<!-- TODO: Add screenshot of HTML report dashboard here -->
<!-- <p align="center"><img src="docs/screenshot.png" alt="Domain Security Report" width="800"></p> -->

## Why?

Security teams use 6-8 different tools to audit a domain: MXToolbox for email, SSL Labs for TLS, Mozilla Observatory for headers, crt.sh for certificates, Shodan for ports, plus manual WHOIS and DNS checks. Then they compile findings into a spreadsheet.

**This tool does all of that in one command** and produces a professional HTML report you can hand directly to a customer — with charts, prioritised findings, step-by-step remediation guidance, and citations to the specific NIST, OWASP, NCSC, or GDPR standard behind each check.

No API keys required. No accounts. No configuration. Just `pip install` and go.

---

## Quick start

### 1. Prerequisites

| | Windows | macOS | Linux |
|---|---------|-------|-------|
| **Git** | [git-scm.com](https://git-scm.com/downloads/win) — reopen PowerShell after | `brew install git` | `sudo apt install git` |
| **Python 3.10+** | Search **"Python"** in Microsoft Store | `brew install python` | `sudo apt install python3 python3-pip python3-venv` |

### 2. Install

**Windows (PowerShell):**
```powershell
git clone https://github.com/wblv-dev/domain-security-toolkit
cd domain-security-toolkit
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install .
```

**macOS / Linux:**
```bash
git clone https://github.com/wblv-dev/domain-security-toolkit
cd domain-security-toolkit
python3 -m venv .venv
source .venv/bin/activate
pip install .
```

> **PowerShell error?** Run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` first.

### 3. Audit

```bash
domain-audit --domains yourdomain.com
```

**Multiple domains from a file** (one per line — ideal for large audits):
```bash
domain-audit --domains-file my-domains.txt
```

That's it. Open `audit_report.html` in your browser.

---

## What you get

```
$ domain-audit --domains example.com

[3/7] Running live DNS and HTTP checks ...
  [EMAIL] example.com: SPF=PASS  DMARC=PASS
  [DNSSEC] example.com: PASS
  [WEB] example.com: 4/6 headers, security.txt=PASS
  [SHODAN] example.com: PASS (2 ports, 0 CVEs)
  [OBSERVATORY] example.com: B+ (score: 70)
  [CT] example.com: 12 certs, 5 subdomains
[7/7] Summary
============================================================
  example.com     SPF:PASS  DMARC:PASS  DNSSEC:PASS  Headers:4/6

  Reports: audit_report.html, AUDIT_REPORT.md, audit_report.csv
```

| Output file | What it's for |
|-------------|--------------|
| **`audit_report.html`** | Interactive dashboard with charts, clickable findings, remediation steps, and standards references. **Send this to customers.** Print as PDF with Ctrl+P. |
| `AUDIT_REPORT.md` | Same findings in Markdown — for Git repos or documentation. |
| `audit_report.csv` | One row per domain — open in Excel/Sheets. |
| `audit_history.db` | SQLite database — accumulates across runs for trend tracking. |

---

## What it checks

<table>
<tr><td>

**✉️ Email security**
- SPF record + grading
- DMARC policy + grading
- DKIM (10 selectors)
- MTA-STS
- TLSRPT
- BIMI

</td><td>

**🔐 DNS security**
- DNSSEC validation
- CAA records
- Dangling CNAMEs
- DNSBL blacklists (6 lists)
- Reverse DNS (FCrDNS)

</td><td>

**🌐 Web security**
- X-Frame-Options
- Content-Security-Policy
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- HSTS (HTTP header)
- security.txt (RFC 9116)
- Mozilla Observatory grade

</td></tr>
<tr><td>

**🏗️ Infrastructure**
- Domain expiry (RDAP)
- Transfer lock status
- Open ports + CVEs (Shodan)
- Certificate Transparency
- Technology fingerprint

</td><td>

**☁️ Cloudflare** *(optional)*
- SSL mode
- TLS version
- HSTS, HTTPS redirect
- Security level
- Browser Integrity Check
- +6 more zone settings

</td><td>

**📋 Standards**

Every finding cites:
- NIST SP 800-52/177/81
- OWASP Secure Headers
- NCSC UK guidance
- CISA BOD 18-01
- PCI DSS v4.0
- GDPR Article 32
- NIS2, BSI, ENISA

</td></tr>
</table>

---

## Optional: OSINT enrichment

The tool works fully without any API keys. For deeper intelligence, set any of these — all have free tiers:

| Service | Env var | Free tier | What it adds |
|---------|---------|-----------|-------------|
| [VirusTotal](https://www.virustotal.com/gui/join-us) | `VIRUSTOTAL_KEY` | 500/day | Reputation from 70+ engines |
| [AlienVault OTX](https://otx.alienvault.com/) | `OTX_KEY` | 10K/hr | Threat intelligence feeds |
| [AbuseIPDB](https://www.abuseipdb.com/register) | `ABUSEIPDB_KEY` | 1K/day | IP abuse scoring |
| [Shodan](https://account.shodan.io/register) | `SHODAN_API_KEY` | 100/month | Detailed port/service data |
| [URLhaus](https://auth.abuse.ch/) | `URLHAUS_KEY` | Fair use | Malware URL checking |
| [Google Safe Browsing](https://developers.google.com/safe-browsing/) | `GOOGLE_SAFEBROWSING_KEY` | 10K+/day | Phishing/malware flagging |

```bash
# macOS / Linux
export VIRUSTOTAL_KEY="your_key"
domain-audit --domains example.com

# Windows (PowerShell)
$env:VIRUSTOTAL_KEY="your_key"
domain-audit --domains example.com
```

---

## Optional: Cloudflare integration

Not required. Adds 11 zone security checks when provided.

1. [Cloudflare dashboard](https://dash.cloudflare.com/) → **My Profile** → **API Tokens** → **Create Token**
2. Permissions: **Zone → Zone → Read** and **Zone → DNS → Read**

```bash
domain-audit --domains example.com --cloudflare-token YOUR_TOKEN
```

---

## All CLI options

```
domain-audit --domains DOMAIN [DOMAIN ...]   Domains to audit
             --domains-file FILE              Load domains from file (one per line)
             --cloudflare-token TOKEN         Cloudflare API token (optional)
             --output-dir DIR                 Where to save reports (default: .)
             --format {html,md,csv}           Which reports (default: all)
             --concurrency N                  Parallel domains (default: 20)
             --verbose                        Debug output
             --log-file FILE                  Save log to file
             --no-diff                        Skip previous-run comparison

domain-dashboard                              Interactive data explorer (Datasette)
```

**Exit codes:** `0` = pass/warn · `1` = error · `2` = at least one FAIL

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `domain-audit: command not found` | Activate your venv first (`.venv\Scripts\Activate.ps1` or `source .venv/bin/activate`) |
| `python: command not found` | Install Python — see [prerequisites](#1-prerequisites) |
| `git: command not found` | Install Git and reopen your terminal |
| `Activate.ps1 cannot be loaded` | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| Report looks broken | Open in Chrome, Firefox, or Edge (not Internet Explorer) |
| Slow on many domains | `domain-audit --domains ... --concurrency 10` |

---

## FAQ

<details>
<summary><strong>Do I need a Cloudflare account?</strong></summary>
No. Cloudflare is optional. 25+ checks work against any domain without any API keys.
</details>

<details>
<summary><strong>Can I audit domains I don't own?</strong></summary>
Yes. All checks use publicly available data (DNS records, HTTP headers, certificate transparency logs, RDAP). This is standard OSINT.
</details>

<details>
<summary><strong>Is this tool free?</strong></summary>
Yes. MIT licensed. Free to use, modify, and distribute — including commercially.
</details>

<details>
<summary><strong>How is this different from MXToolbox / Hardenize / SecurityScorecard?</strong></summary>
Those are web-based SaaS tools ($0-$26K/year). This is a CLI that produces a self-contained HTML report you can send to anyone. It also cites regulatory standards (NIST, OWASP, NCSC, GDPR) in every finding — most tools don't.
</details>

<details>
<summary><strong>Can I run this on a schedule?</strong></summary>
Yes. It's a CLI with exit codes — set up a cron job or scheduled task. Exit code 2 means failures were found.
</details>

---

## Contributing

Issues and pull requests welcome.

## License

[MIT](LICENSE)

---

<div align="center">
<sub>Built with Python · Backed by NIST, OWASP, NCSC, CISA, and GDPR standards</sub>
</div>
