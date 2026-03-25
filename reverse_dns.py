"""
reverse_dns.py — Reverse DNS (PTR) validation for mail server IPs.

Resolves MX hostnames to IPs, performs PTR lookups, and verifies
Forward-Confirmed reverse DNS (FCrDNS). All checks are pure DNS.
"""

import asyncio
from typing import Dict, List

import dns.reversename

import dns_resolver as resolver


def _ptr_lookup(ip: str) -> List[str]:
    """Perform a PTR lookup for an IP address."""
    try:
        rev_name = dns.reversename.from_address(ip)
        results = resolver.query(str(rev_name), "PTR")
        return [r.rstrip(".") for r in results]
    except Exception:
        return []


def _forward_confirm(ptr_name: str, original_ip: str) -> bool:
    """Check if a PTR hostname resolves back to the original IP (FCrDNS)."""
    a_results = resolver.query(ptr_name, "A")
    return original_ip in a_results


def _check_mx_ptr_sync(domain: str) -> dict:
    """Check PTR records for all MX server IPs (synchronous)."""
    mx_records = resolver.get_mx(domain)

    if not mx_records:
        return {
            "domain": domain,
            "results": [],
            **grade_reverse_dns([]),
        }

    ptr_results = []

    for mx in mx_records:
        host = mx["host"]
        ips = resolver.query(host, "A")

        for ip in ips:
            ptr_names = _ptr_lookup(ip)

            if not ptr_names:
                ptr_results.append({
                    "mx_host": host,
                    "ip": ip,
                    "ptr": None,
                    "fcrdns": False,
                    "status": "missing",
                })
                continue

            ptr_name = ptr_names[0]
            confirmed = _forward_confirm(ptr_name, ip)

            ptr_results.append({
                "mx_host": host,
                "ip": ip,
                "ptr": ptr_name,
                "fcrdns": confirmed,
                "status": "confirmed" if confirmed else "mismatch",
            })

    graded = grade_reverse_dns(ptr_results)
    return {
        "domain": domain,
        "results": ptr_results,
        **graded,
    }


def grade_reverse_dns(ptr_results: List[dict]) -> dict:
    """Grade reverse DNS results."""
    if not ptr_results:
        return {
            "grade": "INFO",
            "reason": "No MX records — reverse DNS not applicable",
        }

    missing = [r for r in ptr_results if r["status"] == "missing"]
    mismatched = [r for r in ptr_results if r["status"] == "mismatch"]
    confirmed = [r for r in ptr_results if r["status"] == "confirmed"]

    if missing:
        ips = ", ".join(r["ip"] for r in missing[:3])
        return {
            "grade": "FAIL",
            "reason": f"No PTR record for {len(missing)} IP(s): {ips}",
        }
    elif mismatched:
        return {
            "grade": "WARN",
            "reason": f"{len(mismatched)} IP(s) have PTR but fail forward confirmation",
        }
    else:
        return {
            "grade": "PASS",
            "reason": f"All {len(confirmed)} mail server IP(s) have valid forward-confirmed rDNS",
        }


async def check_domain(domain: str) -> dict:
    """Async wrapper — runs PTR lookups in a thread pool."""
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _check_mx_ptr_sync, domain)
    print(f"  [rDNS] {domain}: {result['grade']}")
    return result


async def check_all(domains: List[str]) -> Dict[str, dict]:
    """Run reverse DNS checks for all domains concurrently."""
    tasks = {
        domain: asyncio.create_task(check_domain(domain))
        for domain in domains
    }
    results = {}
    for domain, task in tasks.items():
        try:
            results[domain] = await task
        except Exception as e:
            print(f"  [ERROR] Reverse DNS check failed for {domain}: {e}")
    return results
