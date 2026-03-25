"""
dns_security.py — DNSSEC, CAA, and dangling CNAME checks via live DNS.

All checks are pure DNS lookups using dnspython. No API calls required.
"""

import asyncio
from typing import Dict, List, Optional

import dns.flags
import dns.name
import dns.rdatatype
import dns.resolver
import dns.message
import dns.query

import config
from lib import dns_resolver as resolver


# Cloudflare-compatible CAs (used for edge certificate issuance)
CLOUDFLARE_CAS = {
    "digicert.com",
    "letsencrypt.org",
    "pki.goog",
    "comodoca.com",
    "sectigo.com",
    "ssl.com",
    "google.com",
}


# ── DNSSEC ───────────────────────────────────────────────────────────────────

def _check_dnssec_sync(domain: str) -> dict:
    """Check DNSSEC deployment for a domain (synchronous)."""
    has_dnskey = False
    has_ds = False

    # Check for DNSKEY at the zone
    try:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [config.DNS_RESOLVER]
        r.timeout = config.DNS_TIMEOUT
        r.lifetime = config.DNS_TIMEOUT
        r.edns = 0
        r.ednsflags = dns.flags.DO

        answers = r.resolve(domain, "DNSKEY")
        has_dnskey = len(answers) > 0
    except Exception:
        pass

    # Check for DS record at parent
    ds_records = resolver.query(domain, "DS")
    has_ds = len(ds_records) > 0

    return grade_dnssec(has_dnskey, has_ds)


def grade_dnssec(has_dnskey: bool, has_ds: bool) -> dict:
    """Grade DNSSEC status."""
    if has_dnskey and has_ds:
        return {
            "grade": "PASS",
            "reason": "DNSSEC fully deployed — DNSKEY and DS records present",
            "has_dnskey": True,
            "has_ds": True,
        }
    elif has_dnskey and not has_ds:
        return {
            "grade": "WARN",
            "reason": "DNSKEY exists but DS record missing at registrar — chain of trust incomplete",
            "has_dnskey": True,
            "has_ds": False,
        }
    else:
        return {
            "grade": "WARN",
            "reason": "DNSSEC not enabled",
            "has_dnskey": False,
            "has_ds": False,
        }


# ── CAA ──────────────────────────────────────────────────────────────────────

def _check_caa_sync(domain: str) -> dict:
    """Check CAA records for a domain (synchronous)."""
    raw = resolver.query(domain, "CAA")

    if not raw:
        return grade_caa([], is_cloudflare=True)

    records = []
    for r in raw:
        # CAA format: "0 issue "letsencrypt.org""
        parts = r.strip().split(None, 2)
        if len(parts) >= 3:
            records.append({
                "flags": parts[0],
                "tag": parts[1],
                "value": parts[2].strip('"'),
            })

    return grade_caa(records, is_cloudflare=True)


def grade_caa(records: List[dict], is_cloudflare: bool = True) -> dict:
    """Grade CAA record configuration."""
    if not records:
        return {
            "grade": "WARN",
            "reason": "No CAA records — any CA can issue certificates",
            "records": [],
            "cf_compatible": True,
        }

    issue_cas = set()
    issuewild_cas = set()
    has_iodef = False

    for r in records:
        tag = r.get("tag", "").lower()
        value = r.get("value", "").lower().rstrip(".")
        if tag == "issue":
            issue_cas.add(value)
        elif tag == "issuewild":
            issuewild_cas.add(value)
        elif tag == "iodef":
            has_iodef = True

    # Check Cloudflare compatibility
    cf_compatible = True
    if is_cloudflare and issue_cas:
        cf_compatible = bool(issue_cas & CLOUDFLARE_CAS)

    if not cf_compatible:
        return {
            "grade": "FAIL",
            "reason": "CAA records do not include any Cloudflare-compatible CA — "
                      "certificate issuance will fail",
            "records": records,
            "cf_compatible": False,
        }

    parts = []
    if issue_cas:
        parts.append(f"issue: {', '.join(sorted(issue_cas))}")
    if issuewild_cas:
        parts.append(f"issuewild: {', '.join(sorted(issuewild_cas))}")
    if has_iodef:
        parts.append("iodef configured")

    return {
        "grade": "PASS",
        "reason": f"CAA configured — {'; '.join(parts)}",
        "records": records,
        "cf_compatible": cf_compatible,
    }


# ── Dangling CNAMEs ─────────────────────────────────────────────────────────

def _check_dangling_sync(domain: str, cname_records: List[dict]) -> dict:
    """Check for dangling CNAME records that resolve to NXDOMAIN."""
    dangling = []

    for record in cname_records:
        if record.get("type") != "CNAME":
            continue

        target = record.get("content", "").rstrip(".")
        name = record.get("name", "")

        if not target:
            continue

        # Try to resolve the CNAME target
        results = resolver.query(target, "A")
        if not results:
            # Also try AAAA
            results = resolver.query(target, "AAAA")

        if not results:
            dangling.append({
                "name": name,
                "target": target,
            })

    return grade_dangling(dangling)


def grade_dangling(dangling: List[dict]) -> dict:
    """Grade dangling CNAME results."""
    if not dangling:
        return {
            "grade": "PASS",
            "reason": "No dangling CNAME records detected",
            "dangling": [],
        }

    names = ", ".join(d["name"] for d in dangling[:5])
    suffix = f" (+{len(dangling) - 5} more)" if len(dangling) > 5 else ""

    return {
        "grade": "FAIL",
        "reason": f"Dangling CNAME(s) found — subdomain takeover risk: {names}{suffix}",
        "dangling": dangling,
    }


# ── Async wrappers ───────────────────────────────────────────────────────────

async def check_dnssec(domain: str) -> dict:
    """Async wrapper for DNSSEC check."""
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _check_dnssec_sync, domain)
    print(f"  [DNSSEC] {domain}: {result['grade']}")
    return result


async def check_caa(domain: str) -> dict:
    """Async wrapper for CAA check."""
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _check_caa_sync, domain)
    print(f"  [CAA] {domain}: {result['grade']}")
    return result


async def check_dangling(domain: str, cname_records: List[dict]) -> dict:
    """Async wrapper for dangling CNAME check."""
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _check_dangling_sync, domain, cname_records)
    count = len(result["dangling"])
    print(f"  [DANGLING] {domain}: {result['grade']}"
          + (f" ({count} dangling)" if count else ""))
    return result


async def check_domain(domain: str, dns_records: List[dict]) -> dict:
    """Run all DNS security checks for a domain."""
    cname_records = [r for r in dns_records if r.get("type") == "CNAME"]

    dnssec_task = asyncio.create_task(check_dnssec(domain))
    caa_task = asyncio.create_task(check_caa(domain))
    dangling_task = asyncio.create_task(check_dangling(domain, cname_records))

    dnssec, caa, dangling = await asyncio.gather(dnssec_task, caa_task, dangling_task)

    return {
        "domain": domain,
        "dnssec": dnssec,
        "caa": caa,
        "dangling": dangling,
    }


async def check_all(
    domains: List[str],
    dns_records: Dict[str, List[dict]],
) -> Dict[str, dict]:
    """Run DNS security checks for all domains concurrently."""
    tasks = {
        domain: asyncio.create_task(
            check_domain(domain, dns_records.get(domain, []))
        )
        for domain in domains
    }
    results = {}
    for domain, task in tasks.items():
        try:
            results[domain] = await task
        except Exception as e:
            print(f"  [ERROR] DNS security check failed for {domain}: {e}")
    return results
