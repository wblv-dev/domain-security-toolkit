#!/usr/bin/env python3
"""
audit.py — Cloudflare DNS Audit Toolkit.

Audits DNS inventory, email security (MX/SPF/DMARC/DKIM), zone security
settings, registrar status, DNSSEC, CAA, dangling CNAMEs, blacklists,
and reverse DNS for every zone accessible to the API token.

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
import registrar
import dns_security
import blacklist
import reverse_dns
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
            print(f"\n[1/6] Resolving zone IDs for {len(config.DOMAINS)} domain(s) ...")
            zone_ids = await cf_client.get_zone_ids(session, config.DOMAINS)
        else:
            print("\n[1/6] Discovering all zones on this API token ...")
            zone_ids = await cf_client.list_all_zones(session)

        if not zone_ids:
            print("[ERROR] No zones resolved — check token scope and domain names.",
                  file=sys.stderr)
            return 1

        resolved = list(zone_ids.keys())
        print(f"       Found {len(resolved)} zone(s): {', '.join(resolved)}")

        # ── 2. DNS inventory + API-based audits ────────────────────────────────
        print(f"\n[2/6] Fetching DNS inventory and zone settings ...")
        dns_task      = asyncio.create_task(dns_inventory.fetch_all(session, zone_ids))
        security_task = asyncio.create_task(zone_security.check_all(session, zone_ids))
        registrar_task = asyncio.create_task(registrar.check_all(session, resolved))

        raw_dns, security_results, registrar_results = await asyncio.gather(
            dns_task, security_task, registrar_task
        )

        dns_summaries = {
            domain: dns_inventory.summarise(records)
            for domain, records in raw_dns.items()
        }

        # ── 3. Live DNS checks (email, DNSSEC, CAA, dangling, blacklist, rDNS)
        print(f"\n[3/6] Running live DNS checks ...")
        email_task     = asyncio.create_task(email_security.check_all(resolved))
        dns_sec_task   = asyncio.create_task(dns_security.check_all(resolved, raw_dns))
        blacklist_task = asyncio.create_task(blacklist.check_all(resolved))
        rdns_task      = asyncio.create_task(reverse_dns.check_all(resolved))

        email_results, dns_sec_results, blacklist_results, rdns_results = (
            await asyncio.gather(email_task, dns_sec_task, blacklist_task, rdns_task)
        )

        # ── 4. Persist to SQLite ──────────────────────────────────────────────
        print(f"\n[4/6] Saving results to {config.DB_PATH} ...")
        with Database(config.DB_PATH) as db:
            run_id = db.start_run(resolved)

            for domain, records in raw_dns.items():
                db.save_dns_records(run_id, domain, records)

            for domain, result in email_results.items():
                db.save_email_check(run_id, result)

            for domain, result in security_results.items():
                db.save_zone_settings(run_id, domain, result["results"])

            for domain, result in registrar_results.items():
                db.save_registrar_check(run_id, result)

            for domain, result in dns_sec_results.items():
                db.save_dns_security(run_id, result)

            for domain, result in blacklist_results.items():
                db.save_blacklist_check(run_id, result)

            for domain, result in rdns_results.items():
                db.save_reverse_dns(run_id, result)

        print(f"       Run ID: {run_id}")

        # ── 5. Write reports ──────────────────────────────────────────────────
        print(f"\n[5/6] Writing reports ...")
        reporter.write_markdown(
            domains            = resolved,
            dns_results        = dns_summaries,
            email_results      = email_results,
            security_results   = security_results,
            registrar_results  = registrar_results,
            dns_sec_results    = dns_sec_results,
            blacklist_results  = blacklist_results,
            rdns_results       = rdns_results,
            output_path        = config.OUTPUT_MD,
        )
        reporter.write_html(
            domains            = resolved,
            dns_results        = dns_summaries,
            email_results      = email_results,
            security_results   = security_results,
            registrar_results  = registrar_results,
            dns_sec_results    = dns_sec_results,
            blacklist_results  = blacklist_results,
            rdns_results       = rdns_results,
            output_path        = config.OUTPUT_HTML,
        )

    # ── 6. Summary ─────────────────────────────────────────────────────────────
    print(f"\n[6/6] Summary")
    print("=" * 60)
    for domain in resolved:
        sec     = security_results.get(domain, {})
        passed, total = sec.get("score", (0, 0))
        email   = email_results.get(domain, {})
        spf_g   = email.get("spf", {}).get("grade", "?")
        dmarc_g = email.get("dmarc", {}).get("grade", "?")
        reg     = registrar_results.get(domain, {})
        exp_g   = reg.get("expiry", {}).get("grade", "?")
        dnssec  = dns_sec_results.get(domain, {})
        ds_g    = dnssec.get("dnssec", {}).get("grade", "?")
        bl      = blacklist_results.get(domain, {})
        bl_g    = bl.get("grade", "?")

        print(f"  {domain:<25}  zone:{passed}/{total}  SPF:{spf_g}  "
              f"DMARC:{dmarc_g}  expiry:{exp_g}  DNSSEC:{ds_g}  BL:{bl_g}")

    print(f"\n  Reports: {config.OUTPUT_MD}, {config.OUTPUT_HTML}")
    print(f"  History: {config.DB_PATH} (run {run_id})")
    return 0


def main() -> int:
    return asyncio.run(_run_audit())


if __name__ == "__main__":
    raise SystemExit(main())
