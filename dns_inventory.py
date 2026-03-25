"""
dns_inventory.py — Async DNS record inventory via the Cloudflare API.

Fetches all DNS records for each configured domain concurrently
and returns structured data ready for the database and report.
"""

import asyncio
from typing import Dict, List

import aiohttp

from cf_client import paginate


NOTABLE_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA"}


async def fetch_domain(
    session: aiohttp.ClientSession,
    domain: str,
    zone_id: str,
) -> List[dict]:
    """Fetch all DNS records for a single zone."""
    records = await paginate(session, f"/zones/{zone_id}/dns_records")
    print(f"  [DNS] {domain}: {len(records)} record(s) fetched")
    return records


async def fetch_all(
    session: aiohttp.ClientSession,
    zone_ids: Dict[str, str],
) -> Dict[str, List[dict]]:
    """Fetch DNS records for all zones concurrently."""
    tasks = {
        domain: asyncio.create_task(fetch_domain(session, domain, zone_id))
        for domain, zone_id in zone_ids.items()
    }
    results = {}
    for domain, task in tasks.items():
        try:
            results[domain] = await task
        except Exception as e:
            print(f"  [ERROR] DNS fetch failed for {domain}: {e}")
            results[domain] = []
    return results


def summarise(records: List[dict]) -> dict:
    """
    Return a summary dict for a list of DNS records:
    {total, by_type, proxied, records (simplified)}
    """
    by_type    = {}
    proxied    = 0
    simplified = []

    for r in records:
        rtype = r.get("type", "?")
        by_type[rtype] = by_type.get(rtype, 0) + 1

        if r.get("proxied"):
            proxied += 1

        simplified.append({
            "type":    rtype,
            "name":    r.get("name", ""),
            "content": r.get("content", ""),
            "ttl":     r.get("ttl"),
            "proxied": r.get("proxied", False),
        })

    return {
        "total":   len(records),
        "by_type": dict(sorted(by_type.items())),
        "proxied": proxied,
        "records": simplified,
    }
