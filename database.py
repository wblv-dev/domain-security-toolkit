"""
database.py — SQLite persistence layer.

Uses a single connection per audit run (not one connection per write).
The Database class is used as a context manager to guarantee the
connection is committed and closed cleanly on exit.

Schema
------
runs          — one row per audit execution (timestamp, domains audited)
dns_records   — every DNS record per domain per run
email_checks  — SPF / DMARC / DKIM results per domain per run
zone_settings — security setting check results per domain per run
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
