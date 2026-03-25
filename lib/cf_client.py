"""
cf_client.py — Async Cloudflare API client.

Uses aiohttp for concurrent requests. Provides retry/backoff on 429/5xx,
paginated list helpers, and zone ID resolution. All API calls are
throttled via the shared semaphore to stay within rate limits.
"""

import sys
import asyncio
from typing import Dict, List, Optional

import aiohttp

import config
from lib.concurrency import sem


def _get_headers() -> Dict[str, str]:
    if not config.CF_API_TOKEN:
        raise SystemExit(
            "[ERROR] CF_API_TOKEN is not set.\n"
            "        export CF_API_TOKEN='your_token_here'\n"
            "        Token needs: Zone:Read, DNS:Read"
        )
    return {
        "Authorization": f"Bearer {config.CF_API_TOKEN}",
        "Content-Type":  "application/json",
    }


def build_session() -> aiohttp.ClientSession:
    """Return an aiohttp ClientSession pre-configured with auth headers."""
    return aiohttp.ClientSession(
        headers=_get_headers(),
        timeout=aiohttp.ClientTimeout(total=config.CF_TIMEOUT),
    )


async def cf_get(
    session: aiohttp.ClientSession,
    path: str,
    params: Optional[Dict] = None,
    max_retries: int = 6,
) -> Dict:
    """Async GET with exponential back-off on 429/5xx.

    Throttled by the cf_api semaphore to prevent rate-limit hits
    on large accounts (Cloudflare allows 1,200 req/5min).
    """
    url     = f"{config.CF_API_BASE}{path}"
    backoff = 1.5

    for attempt in range(1, max_retries + 1):
        try:
            async with sem.cf_api, session.get(url, params=params) as r:
                if r.status in (429, 500, 502, 503, 504):
                    wait        = backoff ** attempt
                    retry_after = r.headers.get("Retry-After")
                    if retry_after and retry_after.isdigit():
                        wait = max(wait, int(retry_after))
                    print(f"  [WARN] HTTP {r.status} on {path} — retrying in {wait:.1f}s ...",
                          file=sys.stderr)
                    await asyncio.sleep(wait)
                    continue

                r.raise_for_status()
                payload = await r.json()

                if not payload.get("success", False):
                    raise RuntimeError(
                        f"Cloudflare API error on {path}: {payload.get('errors')}"
                    )

                return payload

        except aiohttp.ClientError:
            if attempt == max_retries:
                raise
            await asyncio.sleep(backoff ** attempt)

    raise RuntimeError(f"cf_get: exhausted retries for {path}")


async def paginate(
    session: aiohttp.ClientSession,
    path: str,
    params: Optional[Dict] = None,
    per_page: int = 100,
) -> List[Dict]:
    """Collect all pages from a Cloudflare V4 list endpoint into a flat list."""
    results = []
    page    = 1

    while True:
        p       = {**(params or {}), "page": page, "per_page": per_page}
        payload = await cf_get(session, path, params=p)
        batch   = payload.get("result") or []

        results.extend(batch)

        info        = payload.get("result_info") or {}
        total_pages = info.get("total_pages")

        if total_pages is not None:
            if page >= int(total_pages):
                break
        elif len(batch) < per_page:
            break

        page += 1

    return results


async def list_all_zones(session: aiohttp.ClientSession) -> Dict[str, str]:
    """Return {domain: zone_id} for every zone accessible to the token."""
    zones = await paginate(session, "/zones")
    return {z["name"]: z["id"] for z in zones}


async def get_zone_id(session: aiohttp.ClientSession, domain: str) -> Optional[str]:
    """Return the Cloudflare Zone ID for a domain, or None if not found."""
    payload = await cf_get(session, "/zones", params={"name": domain})
    zones   = payload.get("result", [])
    return zones[0]["id"] if zones else None


async def get_zone_ids(
    session: aiohttp.ClientSession,
    domains: List[str],
) -> Dict[str, str]:
    """Resolve zone IDs for all domains concurrently."""
    tasks   = {domain: asyncio.create_task(get_zone_id(session, domain)) for domain in domains}
    results = {}

    for domain, task in tasks.items():
        zid = await task
        if zid:
            results[domain] = zid
        else:
            print(f"  [WARN] Zone not found for {domain} — skipping.", file=sys.stderr)

    return results
