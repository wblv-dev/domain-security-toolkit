"""
web_security.py — HTTP security headers, security.txt, and technology fingerprint.

Fetches the domain over HTTPS and analyses response headers for security
best practices. All checks are simple HTTP GET requests — no API keys needed.
"""

from typing import Dict, List, Optional

import aiohttp


# Expected security headers and their grading
SECURITY_HEADERS = [
    {
        "header": "x-frame-options",
        "label": "X-Frame-Options",
        "recommended": "DENY or SAMEORIGIN",
        "description": "Prevents your site from being embedded in iframes on other domains (clickjacking protection).",
        "grade_pass": lambda v: v.lower() in ("deny", "sameorigin"),
        "grade_warn": lambda v: False,
    },
    {
        "header": "content-security-policy",
        "label": "Content-Security-Policy",
        "recommended": "Defined",
        "description": "Controls which resources the browser can load, preventing XSS and data injection attacks.",
        "grade_pass": lambda v: len(v) > 10,
        "grade_warn": lambda v: False,
    },
    {
        "header": "x-content-type-options",
        "label": "X-Content-Type-Options",
        "recommended": "nosniff",
        "description": "Prevents the browser from MIME-sniffing the content type, reducing drive-by download attacks.",
        "grade_pass": lambda v: v.lower() == "nosniff",
        "grade_warn": lambda v: False,
    },
    {
        "header": "referrer-policy",
        "label": "Referrer-Policy",
        "recommended": "strict-origin-when-cross-origin",
        "description": "Controls how much referrer information is sent with requests, protecting user privacy.",
        "grade_pass": lambda v: v.lower() in (
            "no-referrer", "strict-origin", "strict-origin-when-cross-origin",
            "same-origin", "no-referrer-when-downgrade",
        ),
        "grade_warn": lambda v: v.lower() == "unsafe-url",
    },
    {
        "header": "permissions-policy",
        "label": "Permissions-Policy",
        "recommended": "Defined",
        "description": "Controls which browser features (camera, microphone, geolocation) can be used by the page.",
        "grade_pass": lambda v: len(v) > 5,
        "grade_warn": lambda v: False,
    },
    {
        "header": "strict-transport-security",
        "label": "HSTS (HTTP header)",
        "recommended": "max-age >= 31536000",
        "description": "Tells browsers to only connect via HTTPS. Checked here via actual HTTP response (complements Cloudflare API check).",
        "grade_pass": lambda v: "max-age=" in v.lower() and _parse_max_age(v) >= 31536000,
        "grade_warn": lambda v: "max-age=" in v.lower() and _parse_max_age(v) < 31536000,
    },
]


def _parse_max_age(v: str) -> int:
    try:
        for part in v.split(";"):
            part = part.strip().lower()
            if part.startswith("max-age="):
                return int(part.split("=")[1].strip())
    except (ValueError, IndexError):
        pass
    return 0


def grade_header(check: dict, value: Optional[str]) -> dict:
    """Grade a single security header."""
    if value is None:
        return {
            "header": check["header"],
            "label": check["label"],
            "recommended": check["recommended"],
            "actual": "Missing",
            "grade": "FAIL",
            "description": check["description"],
        }

    if check["grade_pass"](value):
        grade = "PASS"
    elif check["grade_warn"](value):
        grade = "WARN"
    else:
        grade = "WARN"  # Present but not optimal

    return {
        "header": check["header"],
        "label": check["label"],
        "recommended": check["recommended"],
        "actual": value[:200],  # Truncate long CSP headers
        "grade": grade,
        "description": check["description"],
    }


def grade_security_txt(content: Optional[str]) -> dict:
    """Grade security.txt presence and content."""
    if content is None:
        return {
            "grade": "WARN",
            "reason": "No security.txt found — no vulnerability disclosure policy published",
            "content": None,
            "has_contact": False,
        }

    has_contact = any(
        line.strip().lower().startswith("contact:")
        for line in content.splitlines()
        if not line.strip().startswith("#")
    )
    has_expires = any(
        line.strip().lower().startswith("expires:")
        for line in content.splitlines()
        if not line.strip().startswith("#")
    )

    if has_contact:
        grade = "PASS"
        reason = "security.txt found with contact information"
        if not has_expires:
            grade = "WARN"
            reason += " (missing Expires field — RFC 9116 requires it)"
    else:
        grade = "WARN"
        reason = "security.txt found but missing Contact field"

    return {
        "grade": grade,
        "reason": reason,
        "content": content[:1000],
        "has_contact": has_contact,
    }


def _extract_tech(headers: dict) -> List[dict]:
    """Extract technology information from HTTP response headers."""
    tech = []

    server = headers.get("server")
    if server:
        tech.append({"name": "Server", "value": server})

    powered = headers.get("x-powered-by")
    if powered:
        tech.append({"name": "X-Powered-By", "value": powered})

    via = headers.get("via")
    if via:
        tech.append({"name": "Via", "value": via})

    cf_ray = headers.get("cf-ray")
    if cf_ray:
        tech.append({"name": "Cloudflare", "value": f"Active (CF-Ray: {cf_ray[:20]})"})

    cf_cache = headers.get("cf-cache-status")
    if cf_cache:
        tech.append({"name": "CF Cache", "value": cf_cache})

    return tech


async def _fetch_domain(domain: str) -> Optional[dict]:
    """Fetch a domain over HTTPS and return headers + security.txt."""
    from domain_audit.lib.concurrency import sem

    result = {"headers": {}, "security_txt": None, "status": None, "error": None}

    try:
        async with sem.http:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Fetch main page headers
                try:
                    async with session.get(
                        f"https://{domain}/",
                        allow_redirects=True,
                        ssl=False,  # Don't fail on cert issues
                    ) as r:
                        result["status"] = r.status
                        result["headers"] = {k.lower(): v for k, v in r.headers.items()}
                except Exception as e:
                    result["error"] = str(e)
                    return result

                # Fetch security.txt
                try:
                    async with session.get(
                        f"https://{domain}/.well-known/security.txt",
                        allow_redirects=True,
                        ssl=False,
                    ) as r:
                        if r.status == 200:
                            text = await r.text()
                            if "contact:" in text.lower():
                                result["security_txt"] = text
                except Exception:
                    pass  # security.txt is optional

    except Exception as e:
        result["error"] = str(e)

    return result


async def check_domain(domain: str) -> dict:
    """Run all web security checks for a single domain."""
    fetch = await _fetch_domain(domain)

    if fetch is None or fetch.get("error"):
        error = (fetch or {}).get("error", "Unknown error")
        print(f"  [WEB] {domain}: ERROR ({error})")
        return {
            "domain": domain,
            "headers": [],
            "security_txt": grade_security_txt(None),
            "tech": [],
            "error": error,
        }

    # Grade each security header
    header_results = []
    for check in SECURITY_HEADERS:
        value = fetch["headers"].get(check["header"])
        header_results.append(grade_header(check, value))

    # Grade security.txt
    sec_txt = grade_security_txt(fetch.get("security_txt"))

    # Technology fingerprint
    tech = _extract_tech(fetch["headers"])

    passed = sum(1 for h in header_results if h["grade"] == "PASS")
    total = len(header_results)
    print(f"  [WEB] {domain}: {passed}/{total} headers, security.txt={sec_txt['grade']}")

    return {
        "domain": domain,
        "headers": header_results,
        "security_txt": sec_txt,
        "tech": tech,
        "score": (passed, total),
        "error": None,
    }


async def check_all(domains: List[str]) -> Dict[str, dict]:
    """Run web security checks for all domains, throttled."""
    from domain_audit.lib.concurrency import throttled_gather
    return await throttled_gather(
        {d: check_domain(d) for d in domains}, label="Web security check"
    )
