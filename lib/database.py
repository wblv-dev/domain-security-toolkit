"""
database.py — SQLite persistence layer.

Uses a single connection per audit run (not one connection per write).
The Database class is used as a context manager to guarantee the
connection is committed and closed cleanly on exit.

Schema
------
runs              — one row per audit execution (timestamp, domains audited)
dns_records       — every DNS record per domain per run
email_checks      — SPF / DMARC / DKIM results per domain per run
zone_settings     — security setting check results per domain per run
registrar_checks  — WHOIS/RDAP domain registration checks per domain per run
dns_security      — DNSSEC, CAA, dangling CNAME checks per domain per run
blacklist_checks  — DNSBL results per domain per run
reverse_dns       — PTR/rDNS results per domain per run
"""

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


CREATE_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    domains     TEXT NOT NULL   -- JSON array of domain names
);

CREATE TABLE IF NOT EXISTS dns_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES runs(id),
    domain      TEXT NOT NULL,
    type        TEXT,
    name        TEXT,
    content     TEXT,
    ttl         INTEGER,
    proxied     INTEGER         -- 0 or 1
);

CREATE TABLE IF NOT EXISTS email_checks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL REFERENCES runs(id),
    domain          TEXT NOT NULL,
    has_mail        INTEGER,    -- 0 or 1
    mx_records      TEXT,       -- JSON array
    spf_record      TEXT,
    spf_grade       TEXT,
    spf_reason      TEXT,
    dmarc_record    TEXT,
    dmarc_grade     TEXT,
    dmarc_policy    TEXT,
    dmarc_rua       TEXT,
    dkim_found      TEXT        -- JSON array of {selector, record}
);

CREATE TABLE IF NOT EXISTS zone_settings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES runs(id),
    domain      TEXT NOT NULL,
    label       TEXT NOT NULL,
    recommended TEXT,
    actual      TEXT,
    grade       TEXT,
    note        TEXT,
    explanation TEXT
);

CREATE TABLE IF NOT EXISTS registrar_checks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL REFERENCES runs(id),
    domain          TEXT NOT NULL,
    registrar       TEXT,
    nameservers     TEXT,       -- JSON array
    expiry_date     TEXT,
    expiry_days     INTEGER,
    expiry_grade    TEXT,
    expiry_reason   TEXT,
    lock_grade      TEXT,
    lock_reason     TEXT,
    lock_statuses   TEXT        -- JSON array
);

CREATE TABLE IF NOT EXISTS dns_security (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL REFERENCES runs(id),
    domain          TEXT NOT NULL,
    dnssec_grade    TEXT,
    dnssec_reason   TEXT,
    dnssec_dnskey   INTEGER,    -- 0 or 1
    dnssec_ds       INTEGER,    -- 0 or 1
    caa_grade       TEXT,
    caa_reason      TEXT,
    caa_records     TEXT,       -- JSON array
    caa_cf_compat   INTEGER,    -- 0 or 1
    dangling_grade  TEXT,
    dangling_reason TEXT,
    dangling_records TEXT       -- JSON array
);

CREATE TABLE IF NOT EXISTS blacklist_checks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL REFERENCES runs(id),
    domain          TEXT NOT NULL,
    grade           TEXT,
    reason          TEXT,
    checked_ips     TEXT,       -- JSON array
    listings        TEXT        -- JSON array
);

CREATE TABLE IF NOT EXISTS reverse_dns (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL REFERENCES runs(id),
    domain          TEXT NOT NULL,
    grade           TEXT,
    reason          TEXT,
    results         TEXT        -- JSON array of PTR check results
);

CREATE TABLE IF NOT EXISTS email_standards (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL REFERENCES runs(id),
    domain          TEXT NOT NULL,
    mta_sts_grade   TEXT,
    mta_sts_reason  TEXT,
    mta_sts_mode    TEXT,
    tlsrpt_grade    TEXT,
    tlsrpt_reason   TEXT,
    tlsrpt_rua      TEXT,
    bimi_grade      TEXT,
    bimi_reason     TEXT,
    bimi_logo       TEXT
);
"""


class Database:
    """
    SQLite database for audit persistence.

    Use as a context manager:

        with Database() as db:
            run_id = db.start_run(domains)
            db.save_dns_records(run_id, domain, records)
            ...
    """

    def __init__(self, path: str = "audit_history.db"):
        self.path = path
        self._conn: Optional[sqlite3.Connection] = None

    def __enter__(self) -> "Database":
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(CREATE_SCHEMA)
        self._conn.commit()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._conn:
            if exc_type is None:
                self._conn.commit()
            else:
                self._conn.rollback()
            self._conn.close()
            self._conn = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("Database not open — use 'with Database() as db:'")
        return self._conn

    # ── Run management ────────────────────────────────────────────────────────

    def start_run(self, domains: List[str]) -> int:
        """Insert a new run row and return its ID."""
        cur = self.conn.execute(
            "INSERT INTO runs (started_at, domains) VALUES (?, ?)",
            (datetime.now(timezone.utc).isoformat(), json.dumps(domains)),
        )
        self.conn.commit()
        return cur.lastrowid

    def get_runs(self) -> List[Dict]:
        """Return all previous run summaries, newest first."""
        rows = self.conn.execute(
            "SELECT id, started_at, domains FROM runs ORDER BY id DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    # ── DNS records ───────────────────────────────────────────────────────────

    def save_dns_records(self, run_id: int, domain: str, records: List[Dict]) -> None:
        self.conn.executemany(
            """
            INSERT INTO dns_records (run_id, domain, type, name, content, ttl, proxied)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    run_id,
                    domain,
                    r.get("type"),
                    r.get("name"),
                    r.get("content"),
                    r.get("ttl"),
                    1 if r.get("proxied") else 0,
                )
                for r in records
            ],
        )

    def get_dns_records(self, run_id: int) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM dns_records WHERE run_id = ? ORDER BY domain, type, name",
            (run_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Email checks ──────────────────────────────────────────────────────────

    def save_email_check(self, run_id: int, result: Dict) -> None:
        self.conn.execute(
            """
            INSERT INTO email_checks (
                run_id, domain, has_mail,
                mx_records, spf_record, spf_grade, spf_reason,
                dmarc_record, dmarc_grade, dmarc_policy, dmarc_rua, dkim_found
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                result["domain"],
                1 if result["has_mail"] else 0,
                json.dumps(result["mx"]),
                result["spf"].get("record"),
                result["spf"].get("grade"),
                result["spf"].get("reason"),
                result["dmarc"].get("record"),
                result["dmarc"].get("grade"),
                result["dmarc"].get("policy"),
                result["dmarc"].get("rua"),
                json.dumps(result["dkim"]),
            ),
        )

    def get_email_checks(self, run_id: int) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM email_checks WHERE run_id = ? ORDER BY domain",
            (run_id,),
        ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["mx_records"] = json.loads(d["mx_records"] or "[]")
            d["dkim_found"] = json.loads(d["dkim_found"] or "[]")
            results.append(d)
        return results

    # ── Zone settings ─────────────────────────────────────────────────────────

    def save_zone_settings(self, run_id: int, domain: str, check_results: List[Dict]) -> None:
        self.conn.executemany(
            """
            INSERT INTO zone_settings (
                run_id, domain, label, recommended, actual, grade, note, explanation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    run_id,
                    domain,
                    r.get("label"),
                    r.get("recommended"),
                    r.get("actual"),
                    r.get("grade"),
                    r.get("note", ""),
                    r.get("explanation", ""),
                )
                for r in check_results
            ],
        )

    def get_zone_settings(self, run_id: int) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM zone_settings WHERE run_id = ? ORDER BY domain, label",
            (run_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Registrar checks ─────────────────────────────────────────────────────

    def save_registrar_check(self, run_id: int, result: Dict) -> None:
        self.conn.execute(
            """
            INSERT INTO registrar_checks (
                run_id, domain, registrar, nameservers,
                expiry_date, expiry_days, expiry_grade, expiry_reason,
                lock_grade, lock_reason, lock_statuses
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                result["domain"],
                result.get("registrar"),
                json.dumps(result.get("nameservers", [])),
                result["expiry"].get("expiry"),
                result["expiry"].get("days_remaining"),
                result["expiry"].get("grade"),
                result["expiry"].get("reason"),
                result["lock"].get("grade"),
                result["lock"].get("reason"),
                json.dumps(result["lock"].get("statuses", [])),
            ),
        )

    def get_registrar_checks(self, run_id: int) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM registrar_checks WHERE run_id = ? ORDER BY domain",
            (run_id,),
        ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["nameservers"] = json.loads(d["nameservers"] or "[]")
            d["lock_statuses"] = json.loads(d["lock_statuses"] or "[]")
            results.append(d)
        return results

    # ── DNS security ─────────────────────────────────────────────────────────

    def save_dns_security(self, run_id: int, result: Dict) -> None:
        self.conn.execute(
            """
            INSERT INTO dns_security (
                run_id, domain,
                dnssec_grade, dnssec_reason, dnssec_dnskey, dnssec_ds,
                caa_grade, caa_reason, caa_records, caa_cf_compat,
                dangling_grade, dangling_reason, dangling_records
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                result["domain"],
                result["dnssec"].get("grade"),
                result["dnssec"].get("reason"),
                1 if result["dnssec"].get("has_dnskey") else 0,
                1 if result["dnssec"].get("has_ds") else 0,
                result["caa"].get("grade"),
                result["caa"].get("reason"),
                json.dumps(result["caa"].get("records", [])),
                1 if result["caa"].get("cf_compatible") else 0,
                result["dangling"].get("grade"),
                result["dangling"].get("reason"),
                json.dumps(result["dangling"].get("dangling", [])),
            ),
        )

    def get_dns_security(self, run_id: int) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM dns_security WHERE run_id = ? ORDER BY domain",
            (run_id,),
        ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["caa_records"] = json.loads(d["caa_records"] or "[]")
            d["dangling_records"] = json.loads(d["dangling_records"] or "[]")
            results.append(d)
        return results

    # ── Blacklist checks ─────────────────────────────────────────────────────

    def save_blacklist_check(self, run_id: int, result: Dict) -> None:
        self.conn.execute(
            """
            INSERT INTO blacklist_checks (
                run_id, domain, grade, reason, checked_ips, listings
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                result["domain"],
                result.get("grade"),
                result.get("reason"),
                json.dumps(result.get("checked_ips", [])),
                json.dumps(result.get("listings", [])),
            ),
        )

    def get_blacklist_checks(self, run_id: int) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM blacklist_checks WHERE run_id = ? ORDER BY domain",
            (run_id,),
        ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["checked_ips"] = json.loads(d["checked_ips"] or "[]")
            d["listings"] = json.loads(d["listings"] or "[]")
            results.append(d)
        return results

    # ── Reverse DNS ──────────────────────────────────────────────────────────

    def save_reverse_dns(self, run_id: int, result: Dict) -> None:
        self.conn.execute(
            """
            INSERT INTO reverse_dns (
                run_id, domain, grade, reason, results
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                run_id,
                result["domain"],
                result.get("grade"),
                result.get("reason"),
                json.dumps(result.get("results", [])),
            ),
        )

    def get_reverse_dns(self, run_id: int) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM reverse_dns WHERE run_id = ? ORDER BY domain",
            (run_id,),
        ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["results"] = json.loads(d["results"] or "[]")
            results.append(d)
        return results

    # ── Email standards ───────────────────────────────────────────────────────

    def save_email_standards(self, run_id: int, result: Dict) -> None:
        self.conn.execute(
            """
            INSERT INTO email_standards (
                run_id, domain,
                mta_sts_grade, mta_sts_reason, mta_sts_mode,
                tlsrpt_grade, tlsrpt_reason, tlsrpt_rua,
                bimi_grade, bimi_reason, bimi_logo
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                result["domain"],
                result.get("mta_sts", {}).get("grade"),
                result.get("mta_sts", {}).get("reason"),
                result.get("mta_sts", {}).get("mode"),
                result.get("tlsrpt", {}).get("grade"),
                result.get("tlsrpt", {}).get("reason"),
                result.get("tlsrpt", {}).get("rua"),
                result.get("bimi", {}).get("grade"),
                result.get("bimi", {}).get("reason"),
                result.get("bimi", {}).get("logo"),
            ),
        )

    def get_email_standards(self, run_id: int) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM email_standards WHERE run_id = ? ORDER BY domain",
            (run_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── History helpers ───────────────────────────────────────────────────────

    def get_grade_history(self, domain: str, check_label: str, limit: int = 10) -> List[Dict]:
        """
        Return grade history for a specific domain + check combination,
        ordered newest first. Useful for trend analysis.
        """
        rows = self.conn.execute(
            """
            SELECT r.started_at, zs.grade, zs.actual
            FROM zone_settings zs
            JOIN runs r ON r.id = zs.run_id
            WHERE zs.domain = ? AND zs.label = ?
            ORDER BY r.id DESC
            LIMIT ?
            """,
            (domain, check_label, limit),
        ).fetchall()
        return [dict(r) for r in rows]
