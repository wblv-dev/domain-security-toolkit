"""
remediation.py — Remediation guidance for audit findings.

Maps check labels/grades to actionable fix instructions. Used by the
reporter to generate the Remediations tab in the HTML dashboard.
"""

from typing import Dict, List


# ── Tooltips for technical terms ─────────────────────────────────────────────

TOOLTIPS = {
    "SSL mode": "Controls how Cloudflare connects to your origin server. 'Full (strict)' validates the origin's SSL certificate.",
    "Minimum TLS version": "The oldest TLS protocol version allowed. TLS 1.0 and 1.1 have known vulnerabilities and are deprecated.",
    "TLS 1.3": "The latest TLS protocol version, offering faster handshakes and improved forward secrecy.",
    "Automatic HTTPS rewrites": "Automatically changes HTTP URLs to HTTPS in your HTML, preventing mixed content warnings.",
    "Opportunistic encryption": "Advertises HTTPS support via the Alt-Svc header, allowing browsers to upgrade HTTP/2 connections.",
    "Always use HTTPS": "Redirects all HTTP requests to HTTPS using a 301 redirect.",
    "Security level": "Controls how aggressively Cloudflare challenges suspicious visitors. Higher levels show more CAPTCHAs.",
    "Browser Integrity Check": "Evaluates HTTP headers from visitors and blocks requests with suspicious or missing headers.",
    "Email obfuscation": "Hides email addresses on your pages from bots and email harvesters by encoding them in JavaScript.",
    "Hotlink protection": "Prevents other websites from embedding your images, saving bandwidth.",
    "HSTS": "HTTP Strict Transport Security — tells browsers to only connect via HTTPS for a set period. Preload adds your domain to browser built-in lists.",
    "SPF": "Sender Policy Framework — a DNS TXT record that lists which mail servers can send email for your domain.",
    "DMARC": "Domain-based Message Authentication, Reporting, and Conformance — tells receiving servers what to do with emails that fail SPF/DKIM checks.",
    "DKIM": "DomainKeys Identified Mail — cryptographically signs outgoing emails so recipients can verify they haven't been tampered with.",
    "DNSSEC": "DNS Security Extensions — cryptographically signs DNS records to prevent spoofing and cache poisoning.",
    "CAA": "Certificate Authority Authorization — DNS records that specify which certificate authorities can issue SSL certificates for your domain.",
    "Dangling CNAMEs": "CNAME records pointing to services that no longer exist. Attackers can register the target and take over the subdomain.",
    "MTA-STS": "Mail Transfer Agent Strict Transport Security — forces receiving mail servers to use TLS encryption for inbound email.",
    "TLSRPT": "SMTP TLS Reporting — tells mail servers where to send reports about TLS negotiation failures.",
    "BIMI": "Brand Indicators for Message Identification — displays your brand logo next to emails in supporting clients (requires DMARC p=quarantine or p=reject).",
    "Transfer lock": "Prevents your domain from being transferred to another registrar without explicit authorisation.",
    "Domain expiry": "When your domain registration expires. An expired domain can be registered by anyone.",
    "Blacklist (DNSBL)": "DNS-based blacklists that track IP addresses known to send spam. Being listed can cause email delivery failures.",
    "Reverse DNS": "PTR records that map IP addresses back to hostnames. Mail servers often reject email from IPs without valid reverse DNS.",
    "FCrDNS": "Forward-Confirmed reverse DNS — the PTR record's hostname must resolve back to the original IP address.",
}


# ── Remediation instructions ─────────────────────────────────────────────────

REMEDIATIONS = {
    # Zone security
    "SSL mode": {
        "WARN": {
            "priority": "High",
            "risk": "Traffic between Cloudflare and your origin server is unencrypted. Attackers on the same network can intercept data.",
            "steps": [
                "Install a valid SSL certificate on your origin server (Cloudflare offers free origin certificates)",
                "In the Cloudflare dashboard, go to SSL/TLS → Overview",
                "Change the encryption mode to 'Full (strict)'",
                "Test your site still loads correctly",
            ],
        },
        "FAIL": {
            "priority": "Critical",
            "risk": "SSL is disabled. All traffic is sent in plain text — passwords, cookies, and personal data are exposed.",
            "steps": [
                "In the Cloudflare dashboard, go to SSL/TLS → Overview",
                "Set encryption mode to at least 'Flexible' immediately, then work towards 'Full (strict)'",
                "Install a valid SSL certificate on your origin server",
            ],
        },
    },
    "Minimum TLS version": {
        "FAIL": {
            "priority": "High",
            "risk": "TLS 1.0 has known vulnerabilities (BEAST, POODLE). It is deprecated by all major browsers and fails PCI DSS compliance.",
            "steps": [
                "In the Cloudflare dashboard, go to SSL/TLS → Edge Certificates",
                "Set 'Minimum TLS Version' to 1.2",
                "This may break very old clients (IE 10, Android 4.x) — check your analytics first",
            ],
        },
        "WARN": {
            "priority": "Medium",
            "risk": "TLS 1.1 is deprecated and has known weaknesses. Most modern browsers no longer support it.",
            "steps": [
                "In the Cloudflare dashboard, go to SSL/TLS → Edge Certificates",
                "Set 'Minimum TLS Version' to 1.2",
            ],
        },
    },
    "TLS 1.3": {
        "FAIL": {
            "priority": "Medium",
            "risk": "TLS 1.3 provides better performance and security than older versions. Disabling it means visitors miss out on faster connections.",
            "steps": [
                "In the Cloudflare dashboard, go to SSL/TLS → Edge Certificates",
                "Enable TLS 1.3",
            ],
        },
    },
    "Always use HTTPS": {
        "FAIL": {
            "priority": "High",
            "risk": "Visitors can access your site over plain HTTP, exposing them to man-in-the-middle attacks and data interception.",
            "steps": [
                "In the Cloudflare dashboard, go to SSL/TLS → Edge Certificates",
                "Enable 'Always Use HTTPS'",
                "This creates an automatic 301 redirect from HTTP to HTTPS",
            ],
        },
    },
    "Automatic HTTPS rewrites": {
        "FAIL": {
            "priority": "Medium",
            "risk": "Mixed content (HTTP resources on HTTPS pages) causes browser warnings and can break page functionality.",
            "steps": [
                "In the Cloudflare dashboard, go to SSL/TLS → Edge Certificates",
                "Enable 'Automatic HTTPS Rewrites'",
            ],
        },
    },
    "HSTS": {
        "WARN": {
            "priority": "Medium",
            "risk": "Without HSTS, browsers may still attempt HTTP connections before being redirected, leaving a window for interception.",
            "steps": [
                "In the Cloudflare dashboard, go to SSL/TLS → Edge Certificates",
                "Enable HSTS with max-age of at least 31536000 (1 year)",
                "Enable 'Include subdomains' if all subdomains support HTTPS",
                "Enable 'Preload' to be included in browser preload lists",
                "Warning: Once enabled with preload, it's difficult to revert — ensure all subdomains support HTTPS first",
            ],
        },
    },
    "Security level": {
        "FAIL": {
            "priority": "Medium",
            "risk": "Security level is effectively off. Cloudflare won't challenge suspicious visitors, increasing exposure to automated attacks.",
            "steps": [
                "In the Cloudflare dashboard, go to Security → Settings",
                "Set Security Level to at least 'Medium'",
            ],
        },
    },
    "Browser Integrity Check": {
        "FAIL": {
            "priority": "Low",
            "risk": "Requests with suspicious HTTP headers (common in bots and automated tools) are not being blocked.",
            "steps": [
                "In the Cloudflare dashboard, go to Security → Settings",
                "Enable 'Browser Integrity Check'",
            ],
        },
    },
    "Email obfuscation": {
        "FAIL": {
            "priority": "Low",
            "risk": "Email addresses on your pages are visible to scraping bots, which may lead to increased spam.",
            "steps": [
                "In the Cloudflare dashboard, go to Scrape Shield",
                "Enable 'Email Address Obfuscation'",
            ],
        },
    },
    "Hotlink protection": {
        "FAIL": {
            "priority": "Low",
            "risk": "Other websites can embed your images, consuming your bandwidth.",
            "steps": [
                "In the Cloudflare dashboard, go to Scrape Shield",
                "Enable 'Hotlink Protection'",
            ],
        },
    },

    # Email
    "SPF": {
        "FAIL": {
            "priority": "Critical",
            "risk": "Without an SPF record, anyone can send email pretending to be your domain. This is the most common email spoofing vector.",
            "steps": [
                "Identify your email provider (Microsoft 365, Google Workspace, etc.)",
                "Add a TXT record to your DNS: v=spf1 include:<provider_spf> -all",
                "For Microsoft 365: v=spf1 include:spf.protection.outlook.com -all",
                "For Google Workspace: v=spf1 include:_spf.google.com -all",
                "Use -all (hard fail) not ~all (soft fail) for maximum protection",
            ],
        },
        "WARN": {
            "priority": "Medium",
            "risk": "Your SPF record uses ~all (soft fail) which marks suspicious emails but doesn't reject them. Spoofed emails may still reach inboxes.",
            "steps": [
                "Change ~all to -all in your SPF TXT record",
                "Monitor for any legitimate email sources you may have missed before making this change",
            ],
        },
    },
    "DMARC": {
        "FAIL": {
            "priority": "Critical",
            "risk": "Without DMARC, receiving servers have no policy for handling emails that fail SPF/DKIM checks. Your domain can be freely spoofed.",
            "steps": [
                "Add a TXT record at _dmarc.yourdomain.com",
                "Start with monitoring: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com",
                "Review DMARC reports for 2-4 weeks to identify all legitimate email sources",
                "Move to quarantine: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com",
                "Finally enforce: v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com",
            ],
        },
        "WARN": {
            "priority": "Medium",
            "risk": "DMARC is set to quarantine, which sends failing emails to spam. Moving to p=reject would block them entirely.",
            "steps": [
                "Review DMARC reports to ensure all legitimate sources pass",
                "Change p=quarantine to p=reject in your _dmarc TXT record",
            ],
        },
    },

    # DNS security
    "DNSSEC": {
        "WARN": {
            "priority": "Medium",
            "risk": "Without DNSSEC, DNS responses can be spoofed. An attacker could redirect your visitors to a malicious server.",
            "steps": [
                "In the Cloudflare dashboard, go to DNS → Settings",
                "Click 'Enable DNSSEC'",
                "Cloudflare will provide a DS record",
                "Add the DS record at your domain registrar (this is a separate step from Cloudflare)",
                "DNSSEC is not fully active until the DS record is published at the registrar",
            ],
        },
    },
    "CAA": {
        "WARN": {
            "priority": "Low",
            "risk": "Without CAA records, any certificate authority can issue SSL certificates for your domain. A rogue CA could issue a certificate to an attacker.",
            "steps": [
                "Add CAA DNS records specifying which CAs can issue certificates",
                "For Cloudflare: Add CAA records for letsencrypt.org, digicert.com, and pki.goog",
                'Example: 0 issue "letsencrypt.org"',
                'Example: 0 issue "digicert.com"',
                "Optionally add an iodef record for violation reports",
            ],
        },
        "FAIL": {
            "priority": "High",
            "risk": "CAA records exist but don't include Cloudflare's certificate authorities. This will prevent Cloudflare from issuing or renewing SSL certificates for your domain.",
            "steps": [
                "Add CAA issue records for Cloudflare's CAs: letsencrypt.org, digicert.com, pki.goog",
                "Keep any existing CAA records for other services you use",
                "Test by checking certificate issuance in the Cloudflare dashboard",
            ],
        },
    },
    "Dangling CNAMEs": {
        "FAIL": {
            "priority": "Critical",
            "risk": "Dangling CNAME records point to services that no longer exist. An attacker can register the target and serve malicious content on your subdomain.",
            "steps": [
                "Review each dangling CNAME record listed above",
                "If the service is no longer needed, delete the CNAME record from your DNS",
                "If the service should exist, re-provision it at the target",
                "This is a subdomain takeover vulnerability — treat with urgency",
            ],
        },
    },

    # Registrar
    "Transfer lock": {
        "WARN": {
            "priority": "Medium",
            "risk": "Without a transfer lock, your domain could be transferred to another registrar without your knowledge (domain hijacking).",
            "steps": [
                "Log in to your domain registrar",
                "Find the domain lock or transfer lock setting",
                "Enable 'clientTransferProhibited' or equivalent",
                "This is usually a single toggle in your registrar's dashboard",
            ],
        },
    },
    "Domain expiry": {
        "FAIL": {
            "priority": "Critical",
            "risk": "Your domain is expired or about to expire. An expired domain can be registered by anyone, resulting in complete loss of your web presence and email.",
            "steps": [
                "Renew your domain immediately at your registrar",
                "Enable auto-renewal to prevent future expiry",
                "Consider registering for multiple years",
            ],
        },
        "WARN": {
            "priority": "High",
            "risk": "Your domain expires within 90 days. If renewal fails (e.g. expired payment card), you could lose the domain.",
            "steps": [
                "Verify auto-renewal is enabled at your registrar",
                "Check the payment method on file is current",
                "Consider renewing early for peace of mind",
            ],
        },
    },
}


def get_tooltip(label: str) -> str:
    """Return tooltip text for a check label, or empty string."""
    return TOOLTIPS.get(label, "")


def get_remediation(label: str, grade: str) -> dict:
    """Return remediation guidance for a check/grade, or None."""
    check_remediations = REMEDIATIONS.get(label, {})
    return check_remediations.get(grade)


def collect_remediations(
    domains: list,
    security_results: dict,
    email_results: dict,
    dns_sec_results: dict,
    registrar_results: dict,
    blacklist_results: dict,
    rdns_results: dict,
) -> List[Dict]:
    """Collect all findings that need remediation across all domains.

    Returns a list of dicts sorted by priority (Critical > High > Medium > Low).
    """
    PRIORITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings = []

    for domain in domains:
        # Zone security
        sec = security_results.get(domain, {})
        for r in sec.get("results", []):
            grade = r.get("grade")
            if grade in ("FAIL", "WARN"):
                rem = get_remediation(r.get("label", ""), grade)
                if rem:
                    findings.append({
                        "domain": domain,
                        "category": "Zone Security",
                        "check": r.get("label", ""),
                        "grade": grade,
                        "actual": r.get("actual", ""),
                        "recommended": r.get("recommended", ""),
                        **rem,
                    })

        # Email
        email = email_results.get(domain, {})
        for check_key, check_label in [("spf", "SPF"), ("dmarc", "DMARC")]:
            grade = email.get(check_key, {}).get("grade")
            if grade in ("FAIL", "WARN"):
                rem = get_remediation(check_label, grade)
                if rem:
                    findings.append({
                        "domain": domain,
                        "category": "Email Security",
                        "check": check_label,
                        "grade": grade,
                        "actual": email.get(check_key, {}).get("reason", ""),
                        "recommended": "",
                        **rem,
                    })

        # DNS security
        ds = dns_sec_results.get(domain, {})
        for check_key, check_label in [("dnssec", "DNSSEC"), ("caa", "CAA"), ("dangling", "Dangling CNAMEs")]:
            grade = ds.get(check_key, {}).get("grade")
            if grade in ("FAIL", "WARN"):
                rem = get_remediation(check_label, grade)
                if rem:
                    findings.append({
                        "domain": domain,
                        "category": "DNS Security",
                        "check": check_label,
                        "grade": grade,
                        "actual": ds.get(check_key, {}).get("reason", ""),
                        "recommended": "",
                        **rem,
                    })

        # Registrar
        reg = registrar_results.get(domain, {})
        for check_key, check_label in [("expiry", "Domain expiry"), ("lock", "Transfer lock")]:
            grade = reg.get(check_key, {}).get("grade")
            if grade in ("FAIL", "WARN"):
                rem = get_remediation(check_label, grade)
                if rem:
                    findings.append({
                        "domain": domain,
                        "category": "Registrar",
                        "check": check_label,
                        "grade": grade,
                        "actual": reg.get(check_key, {}).get("reason", ""),
                        "recommended": "",
                        **rem,
                    })

    findings.sort(key=lambda f: PRIORITY_ORDER.get(f.get("priority", "Low"), 99))
    return findings
