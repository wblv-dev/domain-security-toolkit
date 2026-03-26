"""
shodan_internetdb.py — Free open port and vulnerability data via Shodan InternetDB.

Queries the Shodan InternetDB API for each domain's IP addresses to find
open ports, known CVEs, and service tags. Completely free, no API key needed.

https://internetdb.shodan.io/docs
"""

from typing import Dict, List, Optional

import aiohttp

from domain_audit.lib import dns_resolver


INTERNETDB_URL = "https://internetdb.shodan.io"


async def _query_ip(ip: str) -> Optional[dict]:
    """Query InternetDB for a single IP."""
    from domain_audit.lib.concurrency import sem

    try:
        async with sem.http:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(f"{INTERNETDB_URL}/{ip}") as r:
                    if r.status == 404:
                        return None  # No data for this IP
                    if r.status != 200:
                        return None
                    return await r.json(content_type=None)
    except Exception:
        return None


def _resolve_ips_sync(domain: str) -> List[str]:
    """Resolve domain to IP addresses."""
    ips = dns_resolver.query(domain, "A")
    return ips


def grade_internetdb(ip_results: List[dict]) -> dict:
    """Grade based on open ports and vulnerabilities found."""
    all_ports = set()
    all_vulns = set()
    all_tags = set()

    for r in ip_results:
        if r.get("data"):
            all_ports.update(r["data"].get("ports", []))
            all_vulns.update(r["data"].get("vulns", []))
            all_tags.update(r["data"].get("tags", []))

    # Risky ports that shouldn't be exposed
    risky_ports = {21, 22, 23, 25, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200}
    exposed_risky = all_ports & risky_ports

    if all_vulns:
        return {
            "grade": "FAIL",
            "reason": f"{len(all_vulns)} known CVE(s) found on exposed services",
        }
    elif exposed_risky:
        port_list = ", ".join(str(p) for p in sorted(exposed_risky)[:5])
        return {
            "grade": "WARN",
            "reason": f"Potentially risky port(s) exposed: {port_list}",
        }
    elif all_ports:
        return {
            "grade": "PASS",
            "reason": f"{len(all_ports)} port(s) visible, no known vulnerabilities",
        }
    else:
        return {
            "grade": "INFO",
            "reason": "No data available in Shodan InternetDB",
        }


async def check_domain(domain: str) -> dict:
    """Check a domain's IPs against Shodan InternetDB."""
    from domain_audit.lib.concurrency import run_in_executor_throttled

    ips = await run_in_executor_throttled(_resolve_ips_sync, domain)

    ip_results = []
    for ip in ips[:5]:  # Limit to first 5 IPs
        data = await _query_ip(ip)
        ip_results.append({
            "ip": ip,
            "data": data,
            "ports": (data or {}).get("ports", []),
            "vulns": (data or {}).get("vulns", []),
            "hostnames": (data or {}).get("hostnames", []),
            "tags": (data or {}).get("tags", []),
        })

    graded = grade_internetdb(ip_results)
    total_ports = sum(len(r["ports"]) for r in ip_results)
    total_vulns = sum(len(r["vulns"]) for r in ip_results)
    print(f"  [SHODAN] {domain}: {graded['grade']} ({total_ports} ports, {total_vulns} CVEs)")

    return {
        "domain": domain,
        "ip_results": ip_results,
        **graded,
    }


async def check_all(domains: List[str]) -> Dict[str, dict]:
    """Run Shodan InternetDB checks for all domains, throttled."""
    from domain_audit.lib.concurrency import throttled_gather
    return await throttled_gather(
        {d: check_domain(d) for d in domains}, label="Shodan InternetDB"
    )
