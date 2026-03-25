"""
dns_inventory.py — Async DNS record inventory via the Cloudflare API.

Fetches all DNS records for each configured domain concurrently
and returns structured data ready for the database and report.
"""

import asyncio
from typing import Dict, List

import aiohttp

from lib.cf_client import paginate


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
    """Fetch DNS records for all zones, throttled."""
    from lib.concurrency import throttled_gather
    results = await throttled_gather(
        {d: fetch_domain(session, d, zid) for d, zid in zone_ids.items()},
        label="DNS fetch",
    )
    # Ensure every domain has at least an empty list
    for d in zone_ids:
        if d not in results:
            results[d] = []
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
