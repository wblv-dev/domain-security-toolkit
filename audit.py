#!/usr/bin/env python3
"""
audit.py — Cloudflare DNS Audit Toolkit.

Audits DNS inventory, email security, zone security settings, registrar
status, DNSSEC, CAA, dangling CNAMEs, blacklists, reverse DNS, MTA-STS,
TLSRPT, and BIMI for every zone accessible to the API token.

Usage:
    export CF_API_TOKEN="your_token_here"
    python audit.py
    python audit.py --domains example.com example.org
    python audit.py --output-dir /tmp/reports --verbose
    python audit.py --log-file audit.log

Token requirements: Zone:Read, DNS:Read — read-only, no changes made.
"""

import argparse
import asyncio
import os
import sys

import config
from lib.log import logger, setup_logging
from lib import cf_client
from lib import reporter
from lib.database import Database
from lib.diff import compute_diff, format_diff_text
from checks import dns_inventory
from checks import email_security
from checks import email_standards
from checks import zone_security
from checks import registrar
from checks import dns_security
from checks import blacklist
from checks import reverse_dns


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Cloudflare DNS security audit toolkit. "
                    "Read-only — no changes are made to any zone.",
        epilog="Set CF_API_TOKEN as an environment variable before running.",
    )
    p.add_argument(
        "--domains", nargs="+", metavar="DOMAIN",
        help="Specific domains to audit (default: auto-discover all zones on the token)",
    )
    p.add_argument(
        "--output-dir", metavar="DIR", default=".",
        help="Directory for output files (default: current directory)",
    )
    p.add_argument(
        "--format", nargs="+", choices=["html", "md", "csv"], default=["html", "md", "csv"],
        help="Output formats (default: all three)",
    )
    p.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging",
    )
    p.add_argument(
        "--log-file", metavar="FILE",
        help="Write detailed log to file",
    )
    p.add_argument(
        "--no-diff", action="store_true",
        help="Skip comparison with previous run",
    )
    return p.parse_args()


def _collect_all_grades(
    security_results, email_results, registrar_results,
    dns_sec_results, blacklist_results, rdns_results,
    email_std_results, domains,
) -> list:
    """Collect every grade from all check results for exit code calculation."""
    grades = []
    for d in domains:
        sec = security_results.get(d, {})
        for r in sec.get("results", []):
            grades.append(r.get("grade", "INFO"))

        email = email_results.get(d, {})
        grades.append(email.get("spf", {}).get("grade", "INFO"))
        grades.append(email.get("dmarc", {}).get("grade", "INFO"))

        reg = registrar_results.get(d, {})
        grades.append(reg.get("expiry", {}).get("grade", "INFO"))
        grades.append(reg.get("lock", {}).get("grade", "INFO"))

        ds = dns_sec_results.get(d, {})
        grades.append(ds.get("dnssec", {}).get("grade", "INFO"))
        grades.append(ds.get("caa", {}).get("grade", "INFO"))
        grades.append(ds.get("dangling", {}).get("grade", "INFO"))

        grades.append(blacklist_results.get(d, {}).get("grade", "INFO"))
        grades.append(rdns_results.get(d, {}).get("grade", "INFO"))

        es = email_std_results.get(d, {})
        grades.append(es.get("mta_sts", {}).get("grade", "INFO"))
        grades.append(es.get("tlsrpt", {}).get("grade", "INFO"))
        grades.append(es.get("bimi", {}).get("grade", "INFO"))

    return grades


async def _run_audit(args: argparse.Namespace) -> int:
    token = os.environ.get("CF_API_TOKEN", "") or config.CF_API_TOKEN
    if not token:
        logger.critical(
            "CF_API_TOKEN is not set. "
            "export CF_API_TOKEN='your_token_here' "
            "(token needs Zone:Read, DNS:Read)"
        )
        return 1

    # Allow CLI --domains to override config
    domains_filter = args.domains or config.DOMAINS

    # Resolve output paths
    out = args.output_dir
    if out != "." and not os.path.isdir(out):
        try:
            os.makedirs(out, exist_ok=True)
        except OSError as e:
            logger.critical("Cannot create output directory %s: %s", out, e)
            return 1

    path_md   = os.path.join(out, config.OUTPUT_MD)
    path_html = os.path.join(out, config.OUTPUT_HTML)
    path_csv  = os.path.join(out, config.OUTPUT_CSV)
    path_db   = os.path.join(out, config.DB_PATH)

    # Temporarily override config token for cf_client
    config.CF_API_TOKEN = token

    async with cf_client.build_session() as session:

        # ── 1. Resolve zone IDs ───────────────────────────────────────────
        if domains_filter:
            logger.info("[1/7] Resolving zone IDs for %d domain(s) ...", len(domains_filter))
            zone_ids = await cf_client.get_zone_ids(session, domains_filter)
        else:
            logger.info("[1/7] Discovering all zones on this API token ...")
            zone_ids = await cf_client.list_all_zones(session)

        if not zone_ids:
            logger.critical("No zones resolved — check token scope and domain names.")
            return 1

        resolved = list(zone_ids.keys())
        logger.info("       Found %d zone(s): %s", len(resolved), ", ".join(resolved))

        # ── 2. API-based audits ───────────────────────────────────────────
        logger.info("[2/7] Fetching DNS inventory and zone settings ...")
        dns_task      = asyncio.create_task(dns_inventory.fetch_all(session, zone_ids))
        security_task = asyncio.create_task(zone_security.check_all(session, zone_ids))
        registrar_task = asyncio.create_task(registrar.check_all(resolved))

        raw_dns, security_results, registrar_results = await asyncio.gather(
            dns_task, security_task, registrar_task
        )

        dns_summaries = {
            domain: dns_inventory.summarise(records)
            for domain, records in raw_dns.items()
        }

        # ── 3. Live DNS checks ────────────────────────────────────────────
        logger.info("[3/7] Running live DNS checks ...")
        email_task      = asyncio.create_task(email_security.check_all(resolved))
        dns_sec_task    = asyncio.create_task(dns_security.check_all(resolved, raw_dns))
        blacklist_task  = asyncio.create_task(blacklist.check_all(resolved))
        rdns_task       = asyncio.create_task(reverse_dns.check_all(resolved))
        email_std_task  = asyncio.create_task(email_standards.check_all(resolved))

        (email_results, dns_sec_results, blacklist_results,
         rdns_results, email_std_results) = await asyncio.gather(
            email_task, dns_sec_task, blacklist_task, rdns_task, email_std_task
        )

        # ── 4. Persist to SQLite ──────────────────────────────────────────
        logger.info("[4/7] Saving results to %s ...", path_db)
        diff_result = None
        with Database(path_db) as db:
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

            for domain, result in email_std_results.items():
                db.save_email_standards(run_id, result)

            # ── 5. Diff against previous run ──────────────────────────────
            if not args.no_diff:
                logger.info("[5/7] Comparing with previous run ...")
                try:
                    diff_result = compute_diff(db, run_id)
                except Exception as e:
                    logger.warning("Could not compute diff: %s", e)
            else:
                logger.info("[5/7] Diff skipped (--no-diff)")

        logger.info("       Run ID: %d", run_id)

        # ── 6. Write reports ──────────────────────────────────────────────
        logger.info("[6/7] Writing reports ...")
        report_kwargs = dict(
            domains            = resolved,
            dns_results        = dns_summaries,
            email_results      = email_results,
            security_results   = security_results,
            registrar_results  = registrar_results,
            dns_sec_results    = dns_sec_results,
            blacklist_results  = blacklist_results,
            rdns_results       = rdns_results,
            email_std_results  = email_std_results,
        )

        if "md" in args.format:
            reporter.write_markdown(**report_kwargs, output_path=path_md)
        if "html" in args.format:
            reporter.write_html(**report_kwargs, output_path=path_html)
        if "csv" in args.format:
            reporter.write_csv(**report_kwargs, output_path=path_csv)

    # ── 7. Summary ────────────────────────────────────────────────────────
    logger.info("[7/7] Summary")
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

    # Show diff summary if available
    if diff_result and diff_result["summary"]["regressions"] > 0:
        print()
        print(format_diff_text(diff_result))
    elif diff_result:
        s = diff_result["summary"]
        if s["improvements"] or s["dns_added"] or s["dns_removed"]:
            print()
            print(format_diff_text(diff_result))
        else:
            print("\n  No changes since previous run.")

    formats_written = [f for f in args.format]
    paths = []
    if "md" in formats_written:
        paths.append(path_md)
    if "html" in formats_written:
        paths.append(path_html)
    if "csv" in formats_written:
        paths.append(path_csv)

    print(f"\n  Reports: {', '.join(paths)}")
    print(f"  History: {path_db} (run {run_id})")

    # ── Exit code ─────────────────────────────────────────────────────────
    all_grades = _collect_all_grades(
        security_results, email_results, registrar_results,
        dns_sec_results, blacklist_results, rdns_results,
        email_std_results, resolved,
    )
    has_fail = any(g == "FAIL" for g in all_grades)
    has_warn = any(g == "WARN" for g in all_grades)

    if has_fail:
        return 2  # At least one FAIL
    elif has_warn:
        return 0  # WARNs are not failures
    return 0


def main() -> int:
    args = parse_args()
    setup_logging(verbose=args.verbose, log_file=args.log_file)
    try:
        return asyncio.run(_run_audit(args))
    except KeyboardInterrupt:
        logger.info("Interrupted.")
        return 130
    except Exception as e:
        logger.critical("Unexpected error: %s", e, exc_info=args.verbose)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
