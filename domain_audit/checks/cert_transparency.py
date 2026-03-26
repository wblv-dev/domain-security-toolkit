"""
cert_transparency.py — Certificate Transparency log search via crt.sh.

Queries the free crt.sh API to find all SSL certificates ever issued for
a domain. Reveals hidden subdomains, unauthorized certificates, and
shadow IT. No API key required.
"""

from typing import Dict, List, Optional
from datetime import datetime

import aiohttp


CRT_SH_URL = "https://crt.sh"


async def _fetch_certs(domain: str) -> Optional[List[dict]]:
    """Fetch certificate transparency data from crt.sh."""
    from domain_audit.lib.concurrency import sem

    url = f"{CRT_SH_URL}/?q=%.{domain}&output=json"
    try:
        async with sem.http:
            timeout = aiohttp.ClientTimeout(total=30)  # crt.sh can be slow
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url) as r:
                    if r.status != 200:
                        return None
                    return await r.json(content_type=None)
    except Exception:
        return None


def _parse_certs(raw: List[dict], domain: str) -> dict:
    """Parse crt.sh results into structured data."""
    if not raw:
        return {
            "total_certs": 0,
            "unique_subdomains": [],
            "issuers": {},
            "recent_certs": [],
            "expired_certs": 0,
            "wildcard_certs": 0,
        }

    # Deduplicate by (common_name, issuer, not_before)
    seen = set()
    certs = []
    subdomains = set()
    issuers = {}
    expired = 0
    wildcard = 0

    for entry in raw:
        cn = entry.get("common_name", "").lower().strip()
        issuer = entry.get("issuer_name", "")
        not_before = entry.get("not_before", "")
        not_after = entry.get("not_after", "")

        key = (cn, not_before)
        if key in seen:
            continue
        seen.add(key)

        # Extract subdomains
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name and name.endswith(f".{domain}") or name == domain:
                subdomains.add(name)

        # Count issuers
        issuer_short = _short_issuer(issuer)
        issuers[issuer_short] = issuers.get(issuer_short, 0) + 1

        # Check wildcards
        if cn.startswith("*."):
            wildcard += 1

        # Check expired
        try:
            exp = datetime.fromisoformat(not_after.replace("T", " ").split(".")[0])
            if exp < datetime.now():
                expired += 1
        except (ValueError, AttributeError):
            pass

        certs.append({
            "common_name": cn,
            "issuer": issuer_short,
            "not_before": not_before[:10],
            "not_after": not_after[:10],
        })

    # Sort by most recent first
    certs.sort(key=lambda c: c.get("not_before", ""), reverse=True)

    return {
        "total_certs": len(certs),
        "unique_subdomains": sorted(subdomains),
        "issuers": issuers,
        "recent_certs": certs[:20],  # Last 20 certs
        "expired_certs": expired,
        "wildcard_certs": wildcard,
    }


def _short_issuer(issuer: str) -> str:
    """Extract readable issuer name from the full issuer string."""
    if not issuer:
        return "Unknown"
    # Try to find O= (Organisation) in the issuer
    for part in issuer.split(","):
        part = part.strip()
        if part.startswith("O="):
            return part[2:].strip()
        if part.startswith("CN="):
            return part[3:].strip()
    return issuer[:60]


def grade_ct(parsed: dict) -> dict:
    """Grade certificate transparency findings."""
    subs = parsed["unique_subdomains"]
    total = parsed["total_certs"]

    if total == 0:
        return {
            "grade": "INFO",
            "reason": "No certificate data found in CT logs",
        }

    # Having CT data is normal — grade based on findings
    findings = []
    if parsed["wildcard_certs"] > 3:
        findings.append(f"{parsed['wildcard_certs']} wildcard certificates issued")

    if len(subs) > 50:
        findings.append(f"{len(subs)} unique subdomains found in CT logs — review for shadow IT")

    if findings:
        return {
            "grade": "WARN",
            "reason": "; ".join(findings),
        }

    return {
        "grade": "PASS",
        "reason": f"{total} certificates found, {len(subs)} subdomains, from {len(parsed['issuers'])} issuer(s)",
    }


async def check_domain(domain: str) -> dict:
    """Run CT log check for a single domain."""
    raw = await _fetch_certs(domain)
    parsed = _parse_certs(raw or [], domain)
    graded = grade_ct(parsed)

    print(f"  [CT] {domain}: {graded['grade']} ({parsed['total_certs']} certs, {len(parsed['unique_subdomains'])} subdomains)")

    return {
        "domain": domain,
        **parsed,
        **graded,
    }


async def check_all(domains: List[str]) -> Dict[str, dict]:
    """Run CT checks for all domains, throttled."""
    from domain_audit.lib.concurrency import throttled_gather
    return await throttled_gather(
        {d: check_domain(d) for d in domains}, label="CT log check"
    )
