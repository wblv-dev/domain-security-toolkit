"""
blacklist.py — DNS-based blacklist (DNSBL) checks for mail server IPs.

Resolves MX records to IP addresses and checks each IP against major
public DNS blacklists. All checks are pure DNS lookups.
"""

import asyncio
from typing import Dict, List, Optional

import dns_resolver as resolver


# Major public DNSBLs — free for low-volume/non-commercial use
DNSBLS = [
    {"host": "zen.spamhaus.org", "name": "Spamhaus ZEN", "severity": "major"},
    {"host": "bl.spamcop.net", "name": "SpamCop", "severity": "major"},
    {"host": "b.barracudacentral.org", "name": "Barracuda", "severity": "major"},
    {"host": "dnsbl.sorbs.net", "name": "SORBS", "severity": "minor"},
    {"host": "bl.mailspike.net", "name": "Mailspike", "severity": "minor"},
    {"host": "dnsbl-1.uceprotect.net", "name": "UCEProtect L1", "severity": "minor"},
]

# Known cloud mail providers — listing is expected/irrelevant
CLOUD_MAIL_PATTERNS = [
    "google.com",
    "googlemail.com",
    "outlook.com",
    "microsoft.com",
    "pphosted.com",
    "mimecast.com",
]


def _reverse_ip(ip: str) -> Optional[str]:
    """Reverse an IPv4 address for DNSBL lookup."""
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    return ".".join(reversed(parts))


def _is_cloud_mail(mx_host: str) -> bool:
    """Check if an MX host belongs to a major cloud mail provider."""
    mx_lower = mx_host.lower()
    return any(pattern in mx_lower for pattern in CLOUD_MAIL_PATTERNS)


def _resolve_mx_ips_sync(domain: str) -> List[dict]:
    """Resolve MX records to IP addresses."""
    mx_records = resolver.get_mx(domain)
    results = []

    for mx in mx_records:
        host = mx["host"]
        ips = resolver.query(host, "A")
        for ip in ips:
            results.append({
                "mx_host": host,
                "ip": ip,
                "cloud": _is_cloud_mail(host),
            })

    return results


def _check_ip_sync(ip: str) -> List[dict]:
    """Check a single IP against all DNSBLs."""
    reversed_ip = _reverse_ip(ip)
    if not reversed_ip:
        return []

    listings = []
    for bl in DNSBLS:
        lookup = f"{reversed_ip}.{bl['host']}"
        results = resolver.query(lookup, "A")
        if results:
            # Get reason from TXT if available
            txt_results = resolver.query(lookup, "TXT")
            reason = txt_results[0].strip('"') if txt_results else ""

            listings.append({
                "blacklist": bl["name"],
                "host": bl["host"],
                "severity": bl["severity"],
                "response": results[0],
                "reason": reason,
            })

    return listings


def grade_blacklist(ip_results: List[dict]) -> dict:
    """Grade overall blacklist status for a domain."""
    all_listings = []
    checked_ips = []

    for ip_info in ip_results:
        if ip_info.get("cloud"):
            continue  # Skip cloud provider IPs

        checked_ips.append(ip_info["ip"])
        for listing in ip_info.get("listings", []):
            all_listings.append({
                **listing,
                "ip": ip_info["ip"],
                "mx_host": ip_info["mx_host"],
            })

    if not checked_ips:
        return {
            "grade": "INFO",
            "reason": "MX handled by cloud provider — blacklist check not applicable",
            "listings": [],
            "checked_ips": [],
        }

    major = [l for l in all_listings if l["severity"] == "major"]
    minor = [l for l in all_listings if l["severity"] == "minor"]

    if major:
        return {
            "grade": "FAIL",
            "reason": f"Listed on {len(major)} major blacklist(s)",
            "listings": all_listings,
            "checked_ips": checked_ips,
        }
    elif minor:
        return {
            "grade": "WARN",
            "reason": f"Listed on {len(minor)} minor blacklist(s)",
            "listings": all_listings,
            "checked_ips": checked_ips,
        }
    else:
        return {
            "grade": "PASS",
            "reason": f"Not listed on any checked blacklist ({len(checked_ips)} IP(s) checked)",
            "listings": [],
            "checked_ips": checked_ips,
        }


def _check_domain_sync(domain: str) -> dict:
    """Run blacklist checks for a domain's mail servers (synchronous)."""
    ip_results = _resolve_mx_ips_sync(domain)

    for ip_info in ip_results:
        if not ip_info["cloud"]:
            ip_info["listings"] = _check_ip_sync(ip_info["ip"])
        else:
            ip_info["listings"] = []

    graded = grade_blacklist(ip_results)
    return {
        "domain": domain,
        "ip_results": ip_results,
        **graded,
    }


async def check_domain(domain: str) -> dict:
    """Async wrapper — runs DNSBL lookups in a thread pool."""
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _check_domain_sync, domain)
    print(f"  [BLACKLIST] {domain}: {result['grade']}")
    return result


async def check_all(domains: List[str]) -> Dict[str, dict]:
    """Run blacklist checks for all domains concurrently."""
    tasks = {
        domain: asyncio.create_task(check_domain(domain))
        for domain in domains
    }
    results = {}
    for domain, task in tasks.items():
        try:
            results[domain] = await task
        except Exception as e:
            print(f"  [ERROR] Blacklist check failed for {domain}: {e}")
    return results
