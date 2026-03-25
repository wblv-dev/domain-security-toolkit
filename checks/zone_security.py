"""
zone_security.py — Async zone security settings audit via the Cloudflare API.

Fetches all zone settings in a single bulk API call, then grades each
against recommended values. Checks SSL/TLS, HSTS, security level,
bot protection, and content protection settings. All read-only.

WAF managed ruleset checks require Pro+ plan and are not included here —
the output notes this clearly where relevant.
"""

import asyncio
from typing import Dict, List, Optional

import aiohttp

from lib.cf_client import cf_get


CHECKS = [
    {
        "setting":     "ssl",
        "label":       "SSL mode",
        "recommended": "full (strict)",
        "values_pass": {"full", "strict"},
        "values_warn": {"flexible"},
        "values_fail": {"off"},
        "explanation": (
            "'Full (strict)' validates the origin certificate. "
            "'Flexible' encrypts browser→Cloudflare only — the origin leg is plain HTTP."
        ),
    },
    {
        "setting":     "min_tls_version",
        "label":       "Minimum TLS version",
        "recommended": "1.2",
        "values_pass": {"1.2", "1.3"},
        "values_warn": {"1.1"},
        "values_fail": {"1.0"},
        "explanation":  "TLS 1.0 and 1.1 have known vulnerabilities. Minimum 1.2.",
    },
    {
        "setting":     "tls_1_3",
        "label":       "TLS 1.3",
        "recommended": "on",
        "values_pass": {"on", "zrt"},
        "values_warn": set(),
        "values_fail": {"off"},
        "explanation":  "TLS 1.3 offers improved performance and forward secrecy.",
    },
    {
        "setting":     "automatic_https_rewrites",
        "label":       "Automatic HTTPS rewrites",
        "recommended": "on",
        "values_pass": {"on"},
        "values_warn": set(),
        "values_fail": {"off"},
        "explanation":  "Upgrades mixed-content HTTP sub-resources to HTTPS automatically.",
    },
    {
        "setting":     "opportunistic_encryption",
        "label":       "Opportunistic encryption",
        "recommended": "on",
        "values_pass": {"on"},
        "values_warn": set(),
        "values_fail": {"off"},
        "explanation":  "Advertises HTTPS support via Alt-Svc for HTTP/2 upgrade.",
    },
    {
        "setting":     "always_use_https",
        "label":       "Always use HTTPS",
        "recommended": "on",
        "values_pass": {"on"},
        "values_warn": set(),
        "values_fail": {"off"},
        "explanation":  "Redirects all HTTP requests to HTTPS.",
    },
    {
        "setting":     "security_level",
        "label":       "Security level",
        "recommended": "medium",
        "values_pass": {"medium", "high", "under_attack"},
        "values_warn": {"low"},
        "values_fail": {"essentially_off", "off"},
        "explanation": (
            "Controls Cloudflare's challenge page sensitivity. "
            "'Medium' or higher is recommended to filter suspicious traffic."
        ),
    },
    {
        "setting":     "browser_check",
        "label":       "Browser Integrity Check",
        "recommended": "on",
        "values_pass": {"on"},
        "values_warn": set(),
        "values_fail": {"off"},
        "explanation": (
            "Evaluates HTTP headers for threats. Blocks requests with "
            "suspicious user agents or missing headers."
        ),
    },
    {
        "setting":     "email_obfuscation",
        "label":       "Email obfuscation",
        "recommended": "on",
        "values_pass": {"on"},
        "values_warn": set(),
        "values_fail": {"off"},
        "explanation":  "Hides email addresses on pages from email harvesters and bots.",
    },
    {
        "setting":     "hotlink_protection",
        "label":       "Hotlink protection",
        "recommended": "on",
        "values_pass": {"on"},
        "values_warn": set(),
        "values_fail": {"off"},
        "explanation":  "Prevents other sites from embedding your images and consuming bandwidth.",
    },
]


async def _get_all_settings(
    session: aiohttp.ClientSession,
    zone_id: str,
) -> Dict[str, str]:
    """Fetch all zone settings in a single API call and return as {id: value}."""
    try:
        payload = await cf_get(session, f"/zones/{zone_id}/settings")
        results = payload.get("result", [])
        settings = {}
        for item in results:
            setting_id = item.get("id", "")
            value = item.get("value", "")
            settings[setting_id] = value
        return settings
    except Exception:
        return {}


def _extract_setting(all_settings: Dict, setting: str) -> Optional[str]:
    """Extract and normalise a single setting value from the bulk response."""
    value = all_settings.get(setting)
    if value is None:
        return None
    return str(value).lower().strip()


def _extract_hsts(all_settings: Dict) -> dict:
    """Extract HSTS settings from the bulk security_header value."""
    sec_header = all_settings.get("security_header")
    if not sec_header or not isinstance(sec_header, dict):
        return {"enabled": None, "max_age": None, "include_subdomains": None, "preload": None}

    hsts = sec_header.get("strict_transport_security", {})
    return {
        "enabled":            hsts.get("enabled", False),
        "max_age":            hsts.get("max_age", 0),
        "include_subdomains": hsts.get("include_subdomains", False),
        "preload":            hsts.get("preload", False),
    }


def _grade(check: dict, actual: Optional[str]) -> dict:
    if actual is None:
        return {**check, "actual": "unavailable", "grade": "INFO",
                "note": "Setting unavailable — may require Pro plan"}

    val = actual.lower().strip()

    if val in check["values_pass"]:
        grade, note = "PASS", ""
    elif val in check["values_warn"]:
        grade, note = "WARN", f"Recommended: {check['recommended']}"
    elif val in check["values_fail"]:
        grade, note = "FAIL", f"Recommended: {check['recommended']}"
    else:
        grade, note = "INFO", f"Unrecognised value — expected {check['recommended']}"

    return {**check, "actual": actual, "grade": grade, "note": note}


def _grade_hsts(hsts: dict) -> dict:
    if hsts.get("enabled") is None:
        return {"label": "HSTS", "recommended": "enabled, max-age ≥ 1 year",
                "actual": "unavailable", "grade": "INFO",
                "note": "Could not fetch HSTS settings", "explanation": ""}

    if not hsts["enabled"]:
        grade = "WARN"
        note  = "HSTS is disabled"
    elif hsts["max_age"] and int(hsts["max_age"]) >= 31536000:
        parts = [f"max-age={hsts['max_age']}s"]
        if hsts["include_subdomains"]:
            parts.append("includeSubDomains")
        if hsts["preload"]:
            parts.append("preload")
        grade = "PASS"
        note  = ", ".join(parts)
    else:
        grade = "WARN"
        note  = f"max-age={hsts.get('max_age', 0)}s — recommend ≥31536000 (1 year)"

    return {
        "label":       "HSTS",
        "recommended": "enabled, max-age ≥ 1 year",
        "actual":      "enabled" if hsts["enabled"] else "disabled",
        "grade":       grade,
        "note":        note,
        "explanation": "HSTS tells browsers to always use HTTPS for this domain.",
    }


async def check_zone(
    session: aiohttp.ClientSession,
    domain: str,
    zone_id: str,
) -> dict:
    """Run all security checks for a single zone using a single bulk API call."""
    all_settings = await _get_all_settings(session, zone_id)

    results = []
    for check in CHECKS:
        value = _extract_setting(all_settings, check["setting"])
        results.append(_grade(check, value))

    hsts = _extract_hsts(all_settings)
    results.append(_grade_hsts(hsts))

    passed = sum(1 for r in results if r["grade"] == "PASS")

    print(f"  [SECURITY] {domain}: {passed}/{len(results)} checks passed")

    return {
        "domain":  domain,
        "zone_id": zone_id,
        "results": results,
        "score":   (passed, len(results)),
    }


async def check_all(
    session: aiohttp.ClientSession,
    zone_ids: Dict[str, str],
) -> Dict[str, dict]:
    """Run zone security checks for all domains, throttled."""
    from lib.concurrency import throttled_gather
    return await throttled_gather(
        {d: check_zone(session, d, zid) for d, zid in zone_ids.items()},
        label="Security check",
    )
