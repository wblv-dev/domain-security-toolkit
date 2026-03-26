#!/usr/bin/env python3
"""
domain-dashboard — Launch the Datasette dashboard for audit results.

Usage:
    domain-dashboard                     # Default: audit_history.db on port 8001
    domain-dashboard --db /path/to.db    # Custom database path
    domain-dashboard --port 9000         # Custom port
    domain-dashboard --host 0.0.0.0      # Listen on all interfaces
"""

import argparse
import os
import sys


def main():
    p = argparse.ArgumentParser(
        description="Launch the Datasette dashboard for domain audit results.",
    )
    p.add_argument(
        "--db", default="audit_history.db",
        help="Path to the audit SQLite database (default: audit_history.db)",
    )
    p.add_argument(
        "--port", type=int, default=8001,
        help="Port to listen on (default: 8001)",
    )
    p.add_argument(
        "--host", default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1)",
    )
    args = p.parse_args()

    if not os.path.exists(args.db):
        print(f"[ERROR] Database not found: {args.db}", file=sys.stderr)
        print("        Run 'domain-audit' first to generate audit data.", file=sys.stderr)
        return 1

    metadata = os.path.join(os.path.dirname(__file__), "datasette_metadata.json")
    if not os.path.exists(metadata):
        print(f"[ERROR] Metadata not found: {metadata}", file=sys.stderr)
        return 1

    try:
        import datasette  # noqa: F401
    except ImportError:
        print("[ERROR] Datasette is not installed.", file=sys.stderr)
        print("        pip install datasette datasette-vega", file=sys.stderr)
        return 1

    print(f"Starting dashboard at http://{args.host}:{args.port}")
    print(f"Database: {args.db}")
    print(f"Press Ctrl+C to stop.\n")

    os.execvp(
        sys.executable,
        [
            sys.executable, "-m", "datasette",
            args.db,
            "--metadata", metadata,
            "--host", args.host,
            "--port", str(args.port),
            "--setting", "default_page_size", "50",
            "--setting", "sql_time_limit_ms", "5000",
        ],
    )


if __name__ == "__main__":
    raise SystemExit(main())
