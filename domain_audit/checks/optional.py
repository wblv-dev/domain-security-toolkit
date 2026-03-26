"""
optional.py — Optional OSINT integrations that require API keys.

Each integration is completely silent if its env var is not set.
No errors, no warnings — just skipped.

Supported:
    SHODAN_API_KEY         — Detailed port/service data (beyond InternetDB)
    VIRUSTOTAL_KEY         — Domain reputation from 70+ engines
    OTX_KEY                — AlienVault OTX threat intelligence
    ABUSEIPDB_KEY          — IP abuse reputation scoring
    URLHAUS_KEY            — Malware URL checking
    GOOGLE_SAFEBROWSING_KEY — Google phishing/malware flagging
"""

import os
from typing import Dict, List, Optional

import aiohttp


_KEYS = {
    "shodan": "SHODAN_API_KEY",
    "virustotal": "VIRUSTOTAL_KEY",
    "otx": "OTX_KEY",
    "abuseipdb": "ABUSEIPDB_KEY",
    "urlhaus": "URLHAUS_KEY",
    "safebrowsing": "GOOGLE_SAFEBROWSING_KEY",
}


def _key(name: str) -> str:
    return os.environ.get(_KEYS.get(name, ""), "")


# ── Shodan (full API, beyond InternetDB) ─────────────────────────────────────

async def _shodan_lookup(domain: str) -> Optional[dict]:
    from domain_audit.lib.concurrency import sem
    api_key = _key("shodan")
    try:
        async with sem.http:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(f"https://api.shodan.io/dns/resolve?hostnames={domain}&key={api_key}") as r:
                    if r.status != 200:
                        return None
                    ips = await r.json()
                    ip = ips.get(domain)
                    if not ip:
                        return None
                async with session.get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}") as r2:
                    if r2.status != 200:
                        return {"ip": ip, "ports": [], "vulns": []}
                    data = await r2.json()
                    return {"ip": ip, "ports": data.get("ports", []),
                            "vulns": list(data.get("vulns", [])),
                            "org": data.get("org", ""), "isp": data.get("isp", "")}
    except Exception:
        return None


# ── VirusTotal ───────────────────────────────────────────────────────────────

async def _virustotal_lookup(domain: str) -> Optional[dict]:
    from domain_audit.lib.concurrency import sem
    api_key = _key("virustotal")
    try:
        async with sem.http:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                                       headers={"x-apikey": api_key}) as r:
                    if r.status != 200:
                        return None
                    data = await r.json()
                    attrs = data.get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    return {"malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "harmless": stats.get("harmless", 0),
                            "reputation": attrs.get("reputation", 0)}
    except Exception:
        return None


# ── AlienVault OTX ───────────────────────────────────────────────────────────

async def _otx_lookup(domain: str) -> Optional[dict]:
    from domain_audit.lib.concurrency import sem
    api_key = _key("otx")
    try:
        async with sem.http:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                    headers={"X-OTX-API-KEY": api_key},
                ) as r:
                    if r.status != 200:
                        return None
                    data = await r.json()
                    pulses = data.get("pulse_info", {})
                    return {
                        "pulse_count": pulses.get("count", 0),
                        "pulses": [p.get("name", "") for p in pulses.get("pulses", [])[:5]],
                        "reputation": data.get("reputation", 0),
                        "sections": data.get("sections", []),
                    }
    except Exception:
        return None


# ── AbuseIPDB ────────────────────────────────────────────────────────────────

async def _abuseipdb_lookup(ip: str) -> Optional[dict]:
    from domain_audit.lib.concurrency import sem
    api_key = _key("abuseipdb")
    try:
        async with sem.http:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": "90"},
                    headers={"Key": api_key, "Accept": "application/json"},
                ) as r:
                    if r.status != 200:
                        return None
                    data = await r.json()
                    d = data.get("data", {})
                    return {
                        "abuse_score": d.get("abuseConfidenceScore", 0),
                        "total_reports": d.get("totalReports", 0),
                        "isp": d.get("isp", ""),
                        "usage_type": d.get("usageType", ""),
                        "country": d.get("countryCode", ""),
                    }
    except Exception:
        return None


# ── URLhaus ──────────────────────────────────────────────────────────────────

async def _urlhaus_lookup(domain: str) -> Optional[dict]:
    from domain_audit.lib.concurrency import sem
    try:
        async with sem.http:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    "https://urlhaus-api.abuse.ch/v1/host/",
                    data={"host": domain},
                ) as r:
                    if r.status != 200:
                        return None
                    data = await r.json(content_type=None)
                    return {
                        "urls_count": data.get("urls_count", 0) if data.get("urls_count") else 0,
                        "status": data.get("query_status", ""),
                        "urls": [u.get("url", "") for u in (data.get("urls", []) or [])[:5]],
                    }
    except Exception:
        return None


# ── Google Safe Browsing ─────────────────────────────────────────────────────

async def _safebrowsing_lookup(domain: str) -> Optional[dict]:
    from domain_audit.lib.concurrency import sem
    api_key = _key("safebrowsing")
    try:
        async with sem.http:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                body = {
                    "client": {"clientId": "domain-security-toolkit", "clientVersion": "1.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": f"https://{domain}/"}],
                    },
                }
                async with session.post(
                    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
                    json=body,
                ) as r:
                    if r.status != 200:
                        return None
                    data = await r.json()
                    matches = data.get("matches", [])
                    return {
                        "flagged": len(matches) > 0,
                        "threats": [m.get("threatType", "") for m in matches],
                    }
    except Exception:
        return None


# ── Public API ───────────────────────────────────────────────────────────────

async def check_domain(domain: str) -> dict:
    """Run all optional integrations for a domain. Skip if keys not set."""
    result = {"domain": domain}

    lookups = {}
    if _key("shodan"):
        lookups["shodan"] = _shodan_lookup(domain)
    if _key("virustotal"):
        lookups["virustotal"] = _virustotal_lookup(domain)
    if _key("otx"):
        lookups["otx"] = _otx_lookup(domain)
    if _key("urlhaus"):
        lookups["urlhaus"] = _urlhaus_lookup(domain)
    if _key("safebrowsing"):
        lookups["safebrowsing"] = _safebrowsing_lookup(domain)
    # AbuseIPDB needs an IP, resolve first
    if _key("abuseipdb"):
        from domain_audit.lib import dns_resolver
        from domain_audit.lib.concurrency import run_in_executor_throttled
        ips = await run_in_executor_throttled(dns_resolver.query, domain, "A")
        if ips:
            lookups["abuseipdb"] = _abuseipdb_lookup(ips[0])

    if not lookups:
        return result

    for name, coro in lookups.items():
        try:
            result[name] = await coro
        except Exception:
            pass

    active = [k for k in lookups if result.get(k)]
    if active:
        print(f"  [OSINT] {domain}: {', '.join(active)}")

    return result


async def check_all(domains: List[str]) -> Dict[str, dict]:
    """Run optional checks. Returns empty dict if no keys set."""
    if not any(_key(k) for k in _KEYS):
        return {}

    from domain_audit.lib.concurrency import throttled_gather
    return await throttled_gather(
        {d: check_domain(d) for d in domains}, label="OSINT check"
    )
