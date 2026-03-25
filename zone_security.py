"""
zone_security.py — Async zone security settings audit via the Cloudflare API.

Checks SSL/TLS mode, minimum TLS version, HSTS, automatic HTTPS rewrites,
TLS 1.3, and opportunistic encryption. All read-only.

WAF managed ruleset checks require Pro+ plan and are not included here —
the output notes this clearly where relevant.
"""

import asyncio
from typing import Dict, List, Optional

import aiohttp

from cf_client import cf_get


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
]


async def _get_setting(
    session: aiohttp.ClientSession,
    zone_id: str,
    setting: str,
) -> Optional[str]:
    try:
        payload = await cf_get(session, f"/zones/{zone_id}/settings/{setting}")
        return str(payload.get("result", {}).get("value", "")).lower()
    except Exception:
        return None


async def _get_hsts(session: aiohttp.ClientSession, zone_id: str) -> dict:
    try:
        payload = await cf_get(session, f"/zones/{zone_id}/settings/security_header")
        hsts    = (
            payload.get("result", {})
            .get("value", {})
            .get("strict_transport_security", {})
        )
        return {
            "enabled":            hsts.get("enabled", False),
            "max_age":            hsts.get("max_age", 0),
            "include_subdomains": hsts.get("include_subdomains", False),
            "preload":            hsts.get("preload", False),
        }
    except Exception:
        return {"enabled": None, "max_age": None, "include_subdomains": None, "preload": None}


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
    """Run all security checks for a single zone concurrently."""
    setting_tasks = [
        asyncio.create_task(_get_setting(session, zone_id, c["setting"]))
        for c in CHECKS
    ]
    hsts_task = asyncio.create_task(_get_hsts(session, zone_id))

    setting_values = await asyncio.gather(*setting_tasks)
    hsts            = await hsts_task

    results = [_grade(check, val) for check, val in zip(CHECKS, setting_values)]
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
    """Run zone security checks for all domains concurrently."""
    tasks = {
        domain: asyncio.create_task(check_zone(session, domain, zone_id))
        for domain, zone_id in zone_ids.items()
    }
    results = {}
    for domain, task in tasks.items():
        try:
            results[domain] = await task
        except Exception as e:
            print(f"  [ERROR] Security check failed for {domain}: {e}")
    return results
