"""
email_security.py — Live email security posture checks.

Performs real DNS lookups (not just API inventory) to validate what is
actually published for MX, SPF, DMARC, and common DKIM selectors.
Runs all domain checks concurrently via asyncio.
"""

import asyncio
from typing import Dict, List

from lib import dns_resolver


DKIM_SELECTORS = [
    "default",
    "google",
    "selector1",    # Microsoft 365
    "selector2",    # Microsoft 365 rotation
    "protonmail",
    "protonmail2",
    "protonmail3",
    "k1",           # Mailchimp
    "mandrill",
    "mail",
]


def _check_domain_sync(domain: str) -> dict:
    """
    Run all email security checks for a single domain (synchronous — called
    from a thread pool so it doesn't block the event loop).
    """
    mx_records = dns_resolver.get_mx(domain)

    # Null MX detection (RFC 7505)
    has_mail = bool(mx_records) and not (
        len(mx_records) == 1
        and mx_records[0]["priority"] == 0
        and mx_records[0]["host"] in (".", "")
    )

    spf   = dns_resolver.get_spf(domain)
    dmarc = dns_resolver.get_dmarc(domain)

    dkim_found = []
    for selector in DKIM_SELECTORS:
        record = dns_resolver.get_dkim(domain, selector)
        if record:
            dkim_found.append({"selector": selector, "record": record})

    return {
        "domain":   domain,
        "mx":       mx_records,
        "spf":      dns_resolver.grade_spf(spf),
        "dmarc":    dns_resolver.grade_dmarc(dmarc),
        "dkim":     dkim_found,
        "has_mail": has_mail,
    }


async def check_domain(domain: str) -> dict:
    """Async wrapper — runs DNS lookups in a thread pool to avoid blocking."""
    loop   = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _check_domain_sync, domain)
    print(f"  [EMAIL] {domain}: SPF={result['spf']['grade']}  DMARC={result['dmarc']['grade']}")
    return result


async def check_all(domains: List[str]) -> Dict[str, dict]:
    """Run email security checks for all domains concurrently."""
    tasks = {
        domain: asyncio.create_task(check_domain(domain))
        for domain in domains
    }
    results = {}
    for domain, task in tasks.items():
        try:
            results[domain] = await task
        except Exception as e:
            print(f"  [ERROR] Email check failed for {domain}: {e}")
    return results
