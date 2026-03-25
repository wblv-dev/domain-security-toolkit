"""
diff.py — Compare audit runs to detect grade changes and DNS record differences.

Compares the current audit run against the previous run stored in the
SQLite database, identifying regressions, improvements, and DNS changes.
"""

from typing import Dict, List, Optional

from lib.database import Database

# Grade ordering from worst to best.
GRADE_ORDER = {"FAIL": 0, "WARN": 1, "INFO": 2, "PASS": 3}


def _grade_direction(old_grade: Optional[str], new_grade: Optional[str]) -> str:
    """Return 'regression', 'improvement', or 'unchanged' based on grade change."""
    if old_grade == new_grade:
        return "unchanged"
    old_rank = GRADE_ORDER.get(old_grade)
    new_rank = GRADE_ORDER.get(new_grade)
    # If either grade is unknown, treat any difference as a change worth noting.
    if old_rank is None or new_rank is None:
        if old_grade is None and new_grade is not None:
            return "improvement"  # went from no data to having a grade
        if old_grade is not None and new_grade is None:
            return "regression"  # lost data
        return "unchanged"
    if new_rank < old_rank:
        return "regression"
    if new_rank > old_rank:
        return "improvement"
    return "unchanged"


def _find_previous_run_id(db: Database, current_run_id: int) -> Optional[Dict]:
    """Find the most recent run before *current_run_id*. Returns dict or None."""
    row = db.conn.execute(
        "SELECT id, started_at FROM runs WHERE id < ? ORDER BY id DESC LIMIT 1",
        (current_run_id,),
    ).fetchone()
    if row is None:
        return None
    return dict(row)


def _get_current_run(db: Database, run_id: int) -> Optional[Dict]:
    """Fetch run metadata for *run_id*."""
    row = db.conn.execute(
        "SELECT id, started_at FROM runs WHERE id = ?", (run_id,)
    ).fetchone()
    if row is None:
        return None
    return dict(row)


# ---------------------------------------------------------------------------
# Grade extraction helpers — pull (domain, check_name, grade) tuples from
# each check table so we can compare them generically.
# ---------------------------------------------------------------------------

def _extract_zone_grades(rows: List[Dict]) -> Dict[tuple, str]:
    """Map (domain, 'zone_security', label) -> grade."""
    result = {}
    for r in rows:
        key = (r["domain"], "zone_security", r["label"])
        result[key] = r.get("grade")
    return result


def _extract_email_grades(rows: List[Dict]) -> Dict[tuple, str]:
    """Map (domain, 'email', check) -> grade for SPF and DMARC."""
    result = {}
    for r in rows:
        domain = r["domain"]
        if r.get("spf_grade") is not None:
            result[(domain, "email", "SPF")] = r["spf_grade"]
        if r.get("dmarc_grade") is not None:
            result[(domain, "email", "DMARC")] = r["dmarc_grade"]
    return result


def _extract_dns_security_grades(rows: List[Dict]) -> Dict[tuple, str]:
    result = {}
    for r in rows:
        domain = r["domain"]
        if r.get("dnssec_grade") is not None:
            result[(domain, "dns_security", "DNSSEC")] = r["dnssec_grade"]
        if r.get("caa_grade") is not None:
            result[(domain, "dns_security", "CAA")] = r["caa_grade"]
        if r.get("dangling_grade") is not None:
            result[(domain, "dns_security", "Dangling CNAME")] = r["dangling_grade"]
    return result


def _extract_registrar_grades(rows: List[Dict]) -> Dict[tuple, str]:
    result = {}
    for r in rows:
        domain = r["domain"]
        if r.get("expiry_grade") is not None:
            result[(domain, "registrar", "Domain expiry")] = r["expiry_grade"]
        if r.get("lock_grade") is not None:
            result[(domain, "registrar", "Domain lock")] = r["lock_grade"]
    return result


def _extract_blacklist_grades(rows: List[Dict]) -> Dict[tuple, str]:
    result = {}
    for r in rows:
        if r.get("grade") is not None:
            result[(r["domain"], "blacklist", "DNSBL")] = r["grade"]
    return result


def _extract_reverse_dns_grades(rows: List[Dict]) -> Dict[tuple, str]:
    result = {}
    for r in rows:
        if r.get("grade") is not None:
            result[(r["domain"], "reverse_dns", "Reverse DNS")] = r["grade"]
    return result


def _collect_all_grades(db: Database, run_id: int) -> Dict[tuple, str]:
    """Collect every (domain, category, check) -> grade mapping for a run."""
    grades: Dict[tuple, str] = {}
    grades.update(_extract_zone_grades(db.get_zone_settings(run_id)))
    grades.update(_extract_email_grades(db.get_email_checks(run_id)))
    grades.update(_extract_dns_security_grades(db.get_dns_security(run_id)))
    grades.update(_extract_registrar_grades(db.get_registrar_checks(run_id)))
    grades.update(_extract_blacklist_grades(db.get_blacklist_checks(run_id)))
    grades.update(_extract_reverse_dns_grades(db.get_reverse_dns(run_id)))
    return grades


# ---------------------------------------------------------------------------
# DNS record diffing
# ---------------------------------------------------------------------------

def _dns_record_key(rec: Dict) -> tuple:
    """A tuple that uniquely identifies a DNS record (ignoring row id / run_id)."""
    return (rec.get("domain"), rec.get("type"), rec.get("name"), rec.get("content"))


def _diff_dns_records(old_records: List[Dict], new_records: List[Dict]) -> List[Dict]:
    old_keys = {_dns_record_key(r) for r in old_records}
    new_keys = {_dns_record_key(r) for r in new_records}

    # Build lookup for content details
    old_by_key = {_dns_record_key(r): r for r in old_records}
    new_by_key = {_dns_record_key(r): r for r in new_records}

    changes: List[Dict] = []

    for key in sorted(new_keys - old_keys):
        rec = new_by_key[key]
        changes.append({
            "domain": rec.get("domain", ""),
            "action": "added",
            "type": rec.get("type", ""),
            "name": rec.get("name", ""),
            "content": rec.get("content", ""),
        })

    for key in sorted(old_keys - new_keys):
        rec = old_by_key[key]
        changes.append({
            "domain": rec.get("domain", ""),
            "action": "removed",
            "type": rec.get("type", ""),
            "name": rec.get("name", ""),
            "content": rec.get("content", ""),
        })

    return changes


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_diff(db: Database, current_run_id: int) -> Optional[Dict]:
    """Compare *current_run_id* against the previous run.

    Returns ``None`` when there is no previous run to compare against.
    """
    current_run = _get_current_run(db, current_run_id)
    if current_run is None:
        return None

    prev = _find_previous_run_id(db, current_run_id)
    if prev is None:
        return None

    prev_run_id = prev["id"]

    # Grade comparison
    old_grades = _collect_all_grades(db, prev_run_id)
    new_grades = _collect_all_grades(db, current_run_id)

    all_keys = sorted(set(old_grades.keys()) | set(new_grades.keys()))
    changes: List[Dict] = []
    for key in all_keys:
        domain, category, check = key
        old_g = old_grades.get(key)
        new_g = new_grades.get(key)
        direction = _grade_direction(old_g, new_g)
        if direction != "unchanged":
            changes.append({
                "domain": domain,
                "category": category,
                "check": check,
                "old_grade": old_g,
                "new_grade": new_g,
                "direction": direction,
            })

    # DNS record comparison
    old_dns = db.get_dns_records(prev_run_id)
    new_dns = db.get_dns_records(current_run_id)
    dns_changes = _diff_dns_records(old_dns, new_dns)

    regressions = sum(1 for c in changes if c["direction"] == "regression")
    improvements = sum(1 for c in changes if c["direction"] == "improvement")
    dns_added = sum(1 for c in dns_changes if c["action"] == "added")
    dns_removed = sum(1 for c in dns_changes if c["action"] == "removed")

    return {
        "previous_run_id": prev_run_id,
        "previous_run_date": prev["started_at"],
        "current_run_id": current_run_id,
        "current_run_date": current_run["started_at"],
        "changes": changes,
        "dns_changes": dns_changes,
        "summary": {
            "regressions": regressions,
            "improvements": improvements,
            "dns_added": dns_added,
            "dns_removed": dns_removed,
        },
    }


def format_diff_text(diff: Dict) -> str:
    """Return a human-readable text summary of the diff."""
    if diff is None:
        return "No previous run to compare against."

    lines: List[str] = []
    summary = diff["summary"]
    lines.append(
        f"Diff: run #{diff['previous_run_id']} ({diff['previous_run_date']}) "
        f"-> run #{diff['current_run_id']} ({diff['current_run_date']})"
    )
    lines.append(
        f"  {summary['regressions']} regression(s), "
        f"{summary['improvements']} improvement(s), "
        f"{summary['dns_added']} DNS record(s) added, "
        f"{summary['dns_removed']} DNS record(s) removed"
    )
    lines.append("")

    # --- Regressions (most important) ---
    regressions = [c for c in diff["changes"] if c["direction"] == "regression"]
    if regressions:
        lines.append("REGRESSIONS:")
        for c in regressions:
            lines.append(
                f"  [{c['domain']}] {c['category']}/{c['check']}: "
                f"{c['old_grade']} -> {c['new_grade']}"
            )
        lines.append("")

    # --- Improvements ---
    improvements = [c for c in diff["changes"] if c["direction"] == "improvement"]
    if improvements:
        lines.append("IMPROVEMENTS:")
        for c in improvements:
            lines.append(
                f"  [{c['domain']}] {c['category']}/{c['check']}: "
                f"{c['old_grade']} -> {c['new_grade']}"
            )
        lines.append("")

    # --- DNS changes ---
    dns_changes = diff["dns_changes"]
    if dns_changes:
        lines.append("DNS CHANGES:")
        for d in dns_changes:
            symbol = "+" if d["action"] == "added" else "-"
            lines.append(
                f"  {symbol} [{d['domain']}] {d['type']} {d['name']} -> {d['content']}"
            )
        lines.append("")

    if not regressions and not improvements and not dns_changes:
        lines.append("No changes detected.")

    return "\n".join(lines)
