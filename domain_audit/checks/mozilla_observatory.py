"""
mozilla_observatory.py — HTTP security grading via Mozilla Observatory.

Submits a domain for scanning and retrieves the grade (A+ to F) and
individual test results. Completely free, no API key needed.

https://github.com/mozilla/http-observatory
"""

from typing import Dict, List, Optional

import aiohttp


OBSERVATORY_API = "https://observatory-api.mdn.mozilla.net/api/v2"


async def _scan_domain(domain: str) -> Optional[dict]:
    """Submit a domain for scanning and retrieve results."""
    from domain_audit.lib.concurrency import sem

    try:
        async with sem.http:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Submit scan
                async with session.post(
                    f"{OBSERVATORY_API}/scan",
                    params={"host": domain},
                ) as r:
                    if r.status not in (200, 201):
                        return None
                    data = await r.json(content_type=None)

                # Get the scan ID and results
                scan_id = data.get("id")
                if not scan_id:
                    return data  # v2 may return results directly

                # Fetch detailed results
                async with session.get(
                    f"{OBSERVATORY_API}/scan",
                    params={"host": domain},
                ) as r2:
                    if r2.status != 200:
                        return data
                    return await r2.json(content_type=None)
    except Exception:
        return None


def grade_observatory(result: Optional[dict]) -> dict:
    """Grade based on Mozilla Observatory results."""
    if not result:
        return {
            "grade": "INFO",
            "reason": "Mozilla Observatory scan unavailable",
            "observatory_grade": None,
            "score": None,
            "tests": {},
        }

    obs_grade = result.get("grade") or result.get("scan", {}).get("grade")
    score = result.get("score") or result.get("scan", {}).get("score")
    tests = result.get("tests", {})

    if not obs_grade:
        return {
            "grade": "INFO",
            "reason": "Could not retrieve Observatory grade",
            "observatory_grade": None,
            "score": score,
            "tests": tests,
        }

    # Map Observatory grades to our grades
    if obs_grade in ("A+", "A"):
        grade = "PASS"
    elif obs_grade in ("A-", "B+", "B"):
        grade = "PASS"
    elif obs_grade in ("B-", "C+", "C"):
        grade = "WARN"
    else:  # C-, D+, D, D-, F
        grade = "FAIL"

    return {
        "grade": grade,
        "reason": f"Mozilla Observatory grade: {obs_grade} (score: {score}/100)",
        "observatory_grade": obs_grade,
        "score": score,
        "tests": tests,
    }


async def check_domain(domain: str) -> dict:
    """Scan a domain with Mozilla Observatory."""
    result = await _scan_domain(domain)
    graded = grade_observatory(result)

    g = graded.get("observatory_grade", "?")
    s = graded.get("score", "?")
    print(f"  [OBSERVATORY] {domain}: {g} (score: {s})")

    return {
        "domain": domain,
        **graded,
    }


async def check_all(domains: List[str]) -> Dict[str, dict]:
    """Run Mozilla Observatory scans for all domains, throttled."""
    from domain_audit.lib.concurrency import throttled_gather
    return await throttled_gather(
        {d: check_domain(d) for d in domains}, label="Mozilla Observatory"
    )
