#!/usr/bin/env python3
"""
audit.py — Cloudflare DNS Audit Toolkit.

Audits DNS inventory, email security (MX/SPF/DMARC/DKIM), and zone security
settings for every domain in config.DOMAINS. Runs concurrently via asyncio
and persists results to SQLite.

Usage:
    export CF_API_TOKEN="your_cloudflare_api_token"
    python audit.py

Output:
    AUDIT_REPORT.md      Markdown report (Git-friendly)
    audit_report.html    HTML dashboard (open in browser)
    audit_history.db     SQLite history (queryable, grows each run)

Token requirements: Zone:Read, DNS:Read — read-only, no changes made.
"""

import asyncio
import sys

import config
import cf_client
import dns_inventory
import email_security
import zone_security
import reporter
from database import Database


async def _run_audit():
    if not config.CF_API_TOKEN:
        print(
            "[ERROR] CF_API_TOKEN is not set.\n"
            "        export CF_API_TOKEN='your_token_here'\n"
            "        Token needs: Zone:Read, DNS:Read",
            file=sys.stderr,
        )
        return 1

    async with cf_client.build_session() as session:

        # ── 1. Resolve zone IDs ───────────────────────────────────────────────
        if config.DOMAINS:
            print(f"\n[1/4] Resolving zone IDs for {len(config.DOMAINS)} domain(s) ...")
            zone_ids = await cf_client.get_zone_ids(session, config.DOMAINS)
        else:
            print("\n[1/4] Discovering all zones on this API token ...")
            zone_ids = await cf_client.list_all_zones(session)

        if not zone_ids:
            print("[ERROR] No zones resolved — check token scope and domain names.",
                  file=sys.stderr)
            return 1

        resolved = list(zone_ids.keys())

        # ── 2. Run all audits concurrently ────────────────────────────────────
        print(f"\n[2/4] Running audits concurrently ...")
        dns_task      = asyncio.create_task(dns_inventory.fetch_all(session, zone_ids))
        email_task    = asyncio.create_task(email_security.check_all(resolved))
        security_task = asyncio.create_task(zone_security.check_all(session, zone_ids))

        raw_dns, email_results, security_results = await asyncio.gather(
            dns_task, email_task, security_task
        )

        dns_summaries = {
            domain: dns_inventory.summarise(records)
            for domain, records in raw_dns.items()
        }

        # ── 3. Persist to SQLite ──────────────────────────────────────────────
        print(f"\n[3/4] Saving results to {config.DB_PATH} ...")
        with Database(config.DB_PATH) as db:
            run_id = db.start_run(resolved)

            for domain, records in raw_dns.items():
                db.save_dns_records(run_id, domain, records)

            for domain, result in email_results.items():
                db.save_email_check(run_id, result)

            for domain, result in security_results.items():
                db.save_zone_settings(run_id, domain, result["results"])

        print(f"       Run ID: {run_id}")

        # ── 4. Write reports ──────────────────────────────────────────────────
        print(f"\n[4/4] Writing reports ...")
        reporter.write_markdown(
            domains          = resolved,
            dns_results      = dns_summaries,
            email_results    = email_results,
            security_results = security_results,
            output_path      = config.OUTPUT_MD,
        )
        reporter.write_html(
            domains          = resolved,
            dns_results      = dns_summaries,
            email_results    = email_results,
            security_results = security_results,
            output_path      = config.OUTPUT_HTML,
        )

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 40)
    print("Audit complete.")
    for domain in resolved:
        sec     = security_results.get(domain, {})
        passed, total = sec.get("score", (0, 0))
        email   = email_results.get(domain, {})
        spf_g   = email.get("spf", {}).get("grade", "?")
        dmarc_g = email.get("dmarc", {}).get("grade", "?")
        print(f"  {domain:<25}  security {passed}/{total}  "
              f"SPF:{spf_g}  DMARC:{dmarc_g}")

    return 0


def main() -> int:
    return asyncio.run(_run_audit())


if __name__ == "__main__":
    raise SystemExit(main())
