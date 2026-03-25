"""
registrar.py — Domain registration checks via RDAP.

Queries the public RDAP bootstrap service (rdap.org) for each domain to
determine registration expiry, registrar lock status, and nameservers.
No API key required — RDAP is the IETF standard replacement for WHOIS.
"""

import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Optional

import aiohttp


RDAP_BOOTSTRAP = "https://rdap.org/domain"

# Statuses that indicate the domain is locked against transfer
LOCK_STATUSES = {
    "client transfer prohibited",
    "clienttransferprohibited",
    "servertransferprohibited",
    "server transfer prohibited",
}

# Expiry thresholds in days
EXPIRY_FAIL_DAYS = 30
EXPIRY_WARN_DAYS = 90


async def _fetch_rdap(domain: str, max_retries: int = 3) -> Optional[dict]:
    """
    Fetch RDAP data for a domain using a dedicated session.

    IMPORTANT: Uses its own aiohttp session with NO auth headers.
    The Cloudflare session must never be reused here — it carries
    the CF API token which would be leaked to rdap.org.

    Throttled by the RDAP semaphore and retries on 429/5xx.
    """
    from lib.concurrency import sem

    url = f"{RDAP_BOOTSTRAP}/{domain}"
    for attempt in range(1, max_retries + 1):
        try:
            async with sem.rdap:
                async with aiohttp.ClientSession() as rdap_session:
                    async with rdap_session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
                        if r.status == 429 or r.status >= 500:
                            if attempt < max_retries:
                                wait = 2 ** attempt
                                await asyncio.sleep(wait)
                                continue
                            return None
                        if r.status != 200:
                            return None
                        return await r.json(content_type=None)
        except Exception:
            if attempt < max_retries:
                await asyncio.sleep(2 ** attempt)
                continue
            return None
    return None


def _parse_expiry(rdap: dict) -> Optional[datetime]:
    """Extract the expiration date from RDAP events."""
    for event in rdap.get("events", []):
        if event.get("eventAction") == "expiration":
            try:
                date_str = event["eventDate"]
                # RDAP dates are ISO 8601
                return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            except (KeyError, ValueError):
                continue
    return None


def _parse_statuses(rdap: dict) -> List[str]:
    """Extract domain status codes from RDAP."""
    return [str(s).lower().strip() for s in rdap.get("status", []) if s is not None]


def _parse_nameservers(rdap: dict) -> List[str]:
    """Extract nameserver hostnames from RDAP."""
    ns_list = []
    for ns in rdap.get("nameservers", []):
        name = ns.get("ldhName") or ns.get("unicodeName")
        if name:
            ns_list.append(name.lower().rstrip("."))
    return sorted(ns_list)


def _parse_registrar(rdap: dict) -> Optional[str]:
    """Extract registrar name from RDAP entities."""
    for entity in rdap.get("entities", []):
        roles = [r.lower() for r in entity.get("roles", [])]
        if "registrar" in roles:
            # Try vCard first
            vcard = entity.get("vcardArray", [None, []])
            if len(vcard) > 1:
                for field in vcard[1]:
                    if field[0] == "fn":
                        return field[3]
            # Fallback to handle
            if entity.get("handle"):
                return entity["handle"]
    return None


def grade_expiry(expiry: Optional[datetime]) -> dict:
    """Grade domain expiry date."""
    if expiry is None:
        return {
            "grade": "INFO",
            "reason": "Expiry date not available in RDAP",
            "expiry": None,
            "days_remaining": None,
        }

    now = datetime.now(timezone.utc)
    delta = expiry - now
    days = delta.days

    if days < 0:
        grade, reason = "FAIL", f"Domain expired {abs(days)} day(s) ago"
    elif days < EXPIRY_FAIL_DAYS:
        grade, reason = "FAIL", f"Expires in {days} day(s) — renewal critical"
    elif days < EXPIRY_WARN_DAYS:
        grade, reason = "WARN", f"Expires in {days} day(s) — renewal recommended"
    else:
        grade, reason = "PASS", f"Expires in {days} day(s)"

    return {
        "grade": grade,
        "reason": reason,
        "expiry": expiry.isoformat(),
        "days_remaining": days,
    }


def grade_lock(statuses: List[str]) -> dict:
    """Grade registrar lock status."""
    locked = any(s in LOCK_STATUSES for s in statuses)

    if locked:
        return {
            "grade": "PASS",
            "reason": "Transfer lock enabled",
            "locked": True,
            "statuses": statuses,
        }
    else:
        return {
            "grade": "WARN",
            "reason": "No transfer lock — domain could be transferred without authorisation",
            "locked": False,
            "statuses": statuses,
        }


async def check_domain(domain: str) -> dict:
    """Run all registrar checks for a single domain."""
    rdap = await _fetch_rdap(domain)

    if rdap is None:
        return {
            "domain": domain,
            "available": False,
            "registrar": None,
            "nameservers": [],
            "expiry": grade_expiry(None),
            "lock": {
                "grade": "INFO",
                "reason": "RDAP data not available for this TLD",
                "locked": None,
                "statuses": [],
            },
        }

    expiry_dt = _parse_expiry(rdap)
    statuses = _parse_statuses(rdap)
    nameservers = _parse_nameservers(rdap)
    registrar = _parse_registrar(rdap)

    result = {
        "domain": domain,
        "available": True,
        "registrar": registrar,
        "nameservers": nameservers,
        "expiry": grade_expiry(expiry_dt),
        "lock": grade_lock(statuses),
    }

    grades = f"Expiry={result['expiry']['grade']}  Lock={result['lock']['grade']}"
    print(f"  [REGISTRAR] {domain}: {grades}")
    return result


async def check_all(domains: List[str]) -> Dict[str, dict]:
    """Run registrar checks for all domains, throttled.

    Note: Does NOT accept a Cloudflare session. RDAP calls use their
    own unauthenticated sessions to avoid leaking the CF API token.
    """
    from lib.concurrency import throttled_gather
    return await throttled_gather(
        {d: check_domain(d) for d in domains}, label="Registrar check"
    )
