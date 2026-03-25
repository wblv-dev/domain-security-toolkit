"""
email_standards.py — MTA-STS, TLSRPT, and BIMI checks.

Performs DNS lookups for TXT records that support modern email standards,
plus an HTTPS fetch for the MTA-STS policy file.  Runs all domain checks
concurrently via asyncio.
"""

import asyncio
from typing import Dict, List, Optional

import aiohttp

from lib import dns_resolver


# ── Pure grading functions (no I/O — easy to unit-test) ──────────────────────

def grade_mta_sts(txt_record: Optional[str], policy_text: Optional[str]) -> dict:
    """
    Grade MTA-STS configuration.

    Grades:
        PASS — TXT record present and policy mode is enforce
        WARN — TXT record present and policy mode is testing
        INFO — No MTA-STS TXT record (not configured)
        FAIL — TXT record exists but policy is unreachable or mode=none
    """
    if not txt_record:
        return {
            "grade": "INFO",
            "reason": "No MTA-STS TXT record — not configured",
            "record": None,
            "mode": None,
        }

    if not policy_text:
        return {
            "grade": "FAIL",
            "reason": "MTA-STS TXT record present but policy file unreachable",
            "record": txt_record,
            "mode": None,
        }

    # Parse mode from policy
    mode = None
    for line in policy_text.splitlines():
        line = line.strip()
        if line.lower().startswith("mode:"):
            mode = line.split(":", 1)[1].strip().lower()
            break

    if mode == "enforce":
        return {
            "grade": "PASS",
            "reason": "MTA-STS enforced — TLS required for inbound mail",
            "record": txt_record,
            "mode": mode,
        }
    elif mode == "testing":
        return {
            "grade": "WARN",
            "reason": "MTA-STS in testing mode — failures reported but not enforced",
            "record": txt_record,
            "mode": mode,
        }
    elif mode == "none":
        return {
            "grade": "FAIL",
            "reason": "MTA-STS mode=none — policy has no effect",
            "record": txt_record,
            "mode": mode,
        }
    else:
        return {
            "grade": "FAIL",
            "reason": f"MTA-STS policy has unrecognised mode: {mode!r}",
            "record": txt_record,
            "mode": mode,
        }


def grade_tlsrpt(txt_record: Optional[str]) -> dict:
    """
    Grade TLSRPT (SMTP TLS Reporting) configuration.

    Grades:
        PASS — Valid TLSRPTv1 record with rua= destination
        INFO — No TLSRPT record (not configured)
        FAIL — Record present but malformed
    """
    if not txt_record:
        return {
            "grade": "INFO",
            "reason": "No TLSRPT record — not configured",
            "record": None,
            "rua": None,
        }

    if not txt_record.startswith("v=TLSRPTv1"):
        return {
            "grade": "FAIL",
            "reason": "TLSRPT record malformed — missing v=TLSRPTv1 prefix",
            "record": txt_record,
            "rua": None,
        }

    rua = None
    for tag in txt_record.split(";"):
        tag = tag.strip()
        if tag.startswith("rua="):
            rua = tag[4:].strip()
            break

    if rua:
        return {
            "grade": "PASS",
            "reason": f"TLSRPT configured — reports sent to {rua}",
            "record": txt_record,
            "rua": rua,
        }
    else:
        return {
            "grade": "FAIL",
            "reason": "TLSRPT record present but missing rua= destination",
            "record": txt_record,
            "rua": None,
        }


def grade_bimi(txt_record: Optional[str]) -> dict:
    """
    Grade BIMI configuration.

    Grades:
        PASS — v=BIMI1 with both l= (logo) and a= (VMC certificate)
        WARN — v=BIMI1 with l= only (no VMC)
        INFO — No BIMI record (not configured)
        FAIL — Record present but malformed

    Note: BIMI requires DMARC p=quarantine or p=reject to be effective.
    """
    if not txt_record:
        return {
            "grade": "INFO",
            "reason": "No BIMI record — not configured",
            "record": None,
            "logo_url": None,
            "vmc_url": None,
        }

    if not txt_record.startswith("v=BIMI1"):
        return {
            "grade": "FAIL",
            "reason": "BIMI record malformed — missing v=BIMI1 prefix",
            "record": txt_record,
            "logo_url": None,
            "vmc_url": None,
        }

    logo_url = None
    vmc_url = None
    for tag in txt_record.split(";"):
        tag = tag.strip()
        if tag.startswith("l="):
            logo_url = tag[2:].strip()
        elif tag.startswith("a="):
            vmc_url = tag[2:].strip()

    if logo_url and vmc_url:
        return {
            "grade": "PASS",
            "reason": "BIMI configured with logo and VMC certificate",
            "record": txt_record,
            "logo_url": logo_url,
            "vmc_url": vmc_url,
        }
    elif logo_url:
        return {
            "grade": "WARN",
            "reason": "BIMI logo present but no VMC certificate — display not guaranteed",
            "record": txt_record,
            "logo_url": logo_url,
            "vmc_url": None,
        }
    else:
        return {
            "grade": "FAIL",
            "reason": "BIMI record present but missing l= (logo URL)",
            "record": txt_record,
            "logo_url": None,
            "vmc_url": None,
        }


# ── I/O helpers ──────────────────────────────────────────────────────────────

def _check_domain_sync(domain: str) -> dict:
    """
    Run DNS lookups for MTA-STS, TLSRPT, and BIMI (synchronous — called from
    a thread pool so it doesn't block the event loop).
    """
    # MTA-STS TXT record: _mta-sts.<domain>
    mta_sts_txt = None
    for txt in dns_resolver.get_txt(f"_mta-sts.{domain}"):
        if txt.startswith("v=STSv1"):
            mta_sts_txt = txt
            break

    # TLSRPT TXT record: _smtp._tls.<domain>
    tlsrpt_txt = None
    for txt in dns_resolver.get_txt(f"_smtp._tls.{domain}"):
        if txt.startswith("v=TLSRPTv1"):
            tlsrpt_txt = txt
            break

    # BIMI TXT record: default._bimi.<domain>
    bimi_txt = None
    for txt in dns_resolver.get_txt(f"default._bimi.{domain}"):
        if txt.startswith("v=BIMI1"):
            bimi_txt = txt
            break

    return {
        "mta_sts_txt": mta_sts_txt,
        "tlsrpt_txt":  tlsrpt_txt,
        "bimi_txt":    bimi_txt,
    }


async def _fetch_mta_sts_policy(domain: str) -> Optional[str]:
    """
    Fetch the MTA-STS policy file over HTTPS, throttled.

    IMPORTANT: Uses its own aiohttp session with NO auth headers.
    The Cloudflare session must never be reused here — it carries
    the CF API token which would be leaked to the target domain.
    """
    from lib.concurrency import sem

    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        async with sem.http:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
                    if r.status != 200:
                        return None
                    return await r.text()
    except Exception:
        return None


# ── Public async interface ───────────────────────────────────────────────────

async def check_domain(domain: str) -> dict:
    """Run all email standards checks for a single domain, throttled."""
    from lib.concurrency import run_in_executor_throttled

    # DNS lookups in a thread pool (blocking I/O), throttled
    dns_result = await run_in_executor_throttled(_check_domain_sync, domain)

    # Fetch MTA-STS policy over HTTPS only if the TXT record exists
    policy_text = None
    if dns_result["mta_sts_txt"]:
        policy_text = await _fetch_mta_sts_policy(domain)

    mta_sts = grade_mta_sts(dns_result["mta_sts_txt"], policy_text)
    tlsrpt  = grade_tlsrpt(dns_result["tlsrpt_txt"])
    bimi    = grade_bimi(dns_result["bimi_txt"])

    result = {
        "domain":  domain,
        "mta_sts": mta_sts,
        "tlsrpt":  tlsrpt,
        "bimi":    bimi,
    }

    print(f"  [MTA-STS] {domain}: {mta_sts['grade']}")
    print(f"  [TLSRPT] {domain}: {tlsrpt['grade']}")
    print(f"  [BIMI]   {domain}: {bimi['grade']}")
    return result


async def check_all(domains: List[str]) -> Dict[str, dict]:
    """Run email standards checks for all domains, throttled."""
    from lib.concurrency import throttled_gather
    return await throttled_gather(
        {d: check_domain(d) for d in domains}, label="Email standards check"
    )
