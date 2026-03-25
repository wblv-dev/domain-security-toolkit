"""
dns_resolver.py — Live DNS validation via dnspython.

Queries the public resolver defined in config.DNS_RESOLVER so results
reflect what is actually published, independent of Cloudflare's API.
"""

from typing import List, Optional
import dns.resolver
import dns.exception

import config


def _make_resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [config.DNS_RESOLVER]
    r.timeout     = config.DNS_TIMEOUT
    r.lifetime    = config.DNS_TIMEOUT
    return r


_resolver = _make_resolver()


# ── Record fetchers ───────────────────────────────────────────────────────────

def query(name: str, rtype: str) -> List[str]:
    """
    Return a list of string-formatted records for (name, rtype).
    Returns an empty list on NXDOMAIN, NOERROR/empty, or timeout.
    """
    try:
        answers = _resolver.resolve(name, rtype)
        return [r.to_text() for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        return []
    except Exception:
        return []


def get_mx(domain: str) -> List[dict]:
    """Return MX records as [{priority, host}], sorted by priority."""
    raw = query(domain, "MX")
    records = []
    for r in raw:
        parts = r.strip().split(None, 1)
        if len(parts) == 2:
            records.append({
                "priority": int(parts[0]),
                "host":     parts[1].rstrip("."),
            })
    return sorted(records, key=lambda x: x["priority"])


def get_txt(domain: str) -> List[str]:
    """Return all TXT records for a domain, with quotes stripped."""
    raw = query(domain, "TXT")
    return [r.strip('"').replace('" "', '') for r in raw]


def get_spf(domain: str) -> Optional[str]:
    """Return the SPF record (v=spf1 ...) if present, else None."""
    for txt in get_txt(domain):
        if txt.startswith("v=spf1"):
            return txt
    return None


def get_dmarc(domain: str) -> Optional[str]:
    """Return the DMARC record from _dmarc.<domain> if present, else None."""
    for txt in get_txt(f"_dmarc.{domain}"):
        if txt.startswith("v=DMARC1"):
            return txt
    return None


def get_dkim(domain: str, selector: str = "default") -> Optional[str]:
    """
    Return the DKIM TXT record for <selector>._domainkey.<domain> if present.
    Common selectors: default, google, selector1, selector2, protonmail.
    """
    target = f"{selector}._domainkey.{domain}"
    records = get_txt(target)
    for r in records:
        if "v=DKIM1" in r or "k=rsa" in r:
            return r
    return None


# ── Parsers / graders ─────────────────────────────────────────────────────────

def grade_spf(spf: Optional[str]) -> dict:
    """
    Parse an SPF record and return a graded result dict.

    Grades:
        PASS  — -all (hard fail), strict
        WARN  — ~all (soft fail), permissive but functional
        FAIL  — +all (allow all, dangerous) or no record
        INFO  — ?all (neutral)
    """
    if not spf:
        return {"grade": "FAIL", "reason": "No SPF record found", "record": None}

    if "-all" in spf:
        grade  = "PASS"
        reason = "Hard fail (-all) — unauthorised senders rejected"
    elif "~all" in spf:
        grade  = "WARN"
        reason = "Soft fail (~all) — unauthorised senders marked, not rejected"
    elif "+all" in spf:
        grade  = "FAIL"
        reason = "+all permits any sender — effectively no SPF protection"
    elif "?all" in spf:
        grade  = "INFO"
        reason = "Neutral (?all) — no policy enforced"
    else:
        grade  = "WARN"
        reason = "No 'all' mechanism found — policy incomplete"

    return {"grade": grade, "reason": reason, "record": spf}


def grade_dmarc(dmarc: Optional[str]) -> dict:
    """
    Parse a DMARC record and return a graded result dict.

    Grades:
        PASS  — p=reject
        WARN  — p=quarantine
        INFO  — p=none (monitoring only)
        FAIL  — no record
    """
    if not dmarc:
        return {"grade": "FAIL", "reason": "No DMARC record found", "record": None,
                "policy": None, "rua": None}

    policy = None
    rua    = None

    for tag in dmarc.split(";"):
        tag = tag.strip()
        if tag.startswith("p="):
            policy = tag[2:].strip()
        if tag.startswith("rua="):
            rua = tag[4:].strip()

    if policy == "reject":
        grade  = "PASS"
        reason = "p=reject — failing messages rejected outright"
    elif policy == "quarantine":
        grade  = "WARN"
        reason = "p=quarantine — failing messages sent to spam"
    elif policy == "none":
        grade  = "INFO"
        reason = "p=none — monitoring only, no enforcement"
    else:
        grade  = "WARN"
        reason = f"Unrecognised policy value: {policy!r}"

    return {
        "grade":  grade,
        "reason": reason,
        "record": dmarc,
        "policy": policy,
        "rua":    rua,
    }
