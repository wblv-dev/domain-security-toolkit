#!/usr/bin/env python3
"""
domain-audit — Domain Security Audit Toolkit.

Runs 35+ security checks against any domain: TLS, email auth, HTTP headers,
DNSSEC, certificates, OSINT, and optionally Cloudflare zone settings.
Produces customer-ready HTML reports with remediation guidance aligned
with published recommendations from NIST, OWASP, NCSC, CISA, and GDPR.

Usage:
    domain-audit --domains example.com example.org
    domain-audit --domains example.com --cloudflare-token YOUR_TOKEN
    domain-audit --output-dir /tmp/reports --verbose

Cloudflare integration is optional. Without a token, all DNS, HTTP, and
OSINT checks still run. With a token, zone security settings are included.
"""

import argparse
import asyncio
import os
import sys

from domain_audit import config
from domain_audit.lib.log import logger, setup_logging
from domain_audit.lib import cf_client
from domain_audit.lib import reporter
from domain_audit.lib.database import Database
from domain_audit.lib.diff import compute_diff, format_diff_text
from domain_audit.checks import dns_inventory
from domain_audit.checks import email_security
from domain_audit.checks import email_standards
from domain_audit.checks import zone_security
from domain_audit.checks import registrar
from domain_audit.checks import dns_security
from domain_audit.checks import blacklist
from domain_audit.checks import reverse_dns
from domain_audit.checks import web_security
from domain_audit.checks import cert_transparency
from domain_audit.checks import shodan_internetdb
from domain_audit.checks import mozilla_observatory
from domain_audit.checks import optional as optional_checks


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="domain-audit",
        description=(
            "Domain security audit toolkit.\n\n"
            "Runs 35+ checks against any domain, covering TLS, email auth,\n"
            "HTTP headers, DNSSEC, certificates, OSINT, and optionally\n"
            "Cloudflare zone settings. Produces customer-ready HTML reports\n"
            "with remediation guidance aligned with NIST, OWASP, NCSC, and GDPR.\n\n"
            "Checks performed:\n"
            "  Email security   SPF, DMARC, DKIM, MTA-STS, TLSRPT, BIMI\n"
            "  DNS security     DNSSEC, CAA, dangling CNAMEs, blacklists, rDNS\n"
            "  Web security     HTTP headers, security.txt, Mozilla Observatory\n"
            "  Certificates     Certificate Transparency (crt.sh)\n"
            "  Infrastructure   Domain expiry (RDAP), transfer lock, open ports (Shodan)\n"
            "  Cloudflare       Zone settings (optional, requires --cloudflare-token)\n"
        ),
        epilog=(
            "environment variables:\n"
            "  CF_API_TOKEN     Cloudflare API token (optional)\n"
            "  SHODAN_API_KEY   Shodan full API (optional)\n"
            "  VIRUSTOTAL_KEY   VirusTotal domain reputation (optional)\n"
            "  OTX_KEY          AlienVault OTX threat intel (optional)\n"
            "  ABUSEIPDB_KEY    IP abuse scoring (optional)\n\n"
            "exit codes:\n"
            "  0                All checks passed or warned\n"
            "  1                Configuration or runtime error\n"
            "  2                At least one check graded FAIL\n"
            "  130              Interrupted (Ctrl+C)\n\n"
            "examples:\n"
            "  %(prog)s --domains example.com                    Audit a domain\n"
            "  %(prog)s --domains example.com --cloudflare-token TOKEN   With CF\n"
            "  %(prog)s --output-dir /tmp/reports --verbose      Debug logging\n\n"
            "documentation: https://github.com/wblv-dev/domain-security-toolkit"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--domains", nargs="+", metavar="DOMAIN",
        help="domains to audit (required unless using --domains-file or --cloudflare-token)",
    )
    p.add_argument(
        "--domains-file", metavar="FILE",
        help="file containing domains to audit, one per line",
    )
    p.add_argument(
        "--cloudflare-token", metavar="TOKEN",
        help="Cloudflare API token for zone settings audit (optional — all other checks work without it)",
    )
    p.add_argument(
        "--output-dir", metavar="DIR", default=".",
        help="directory for output files (default: current directory)",
    )
    p.add_argument(
        "--format", nargs="+", choices=["html", "md", "csv"], default=["html", "md", "csv"],
        help="output formats to generate (default: all three)",
    )
    p.add_argument(
        "--verbose", "-v", action="store_true",
        help="enable debug logging to stderr",
    )
    p.add_argument(
        "--log-file", metavar="FILE",
        help="write detailed log to file (always verbose)",
    )
    p.add_argument(
        "--no-diff", action="store_true",
        help="skip comparison with previous run",
    )
    p.add_argument(
        "--concurrency", type=int, metavar="N", default=20,
        help="max domains to process concurrently (default: 20)",
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


def normalise_domain(raw: str) -> str:
    """Clean a domain input: strip whitespace, protocol, path, trailing dot."""
    d = raw.strip().lower()
    # Strip protocol
    for prefix in ("https://", "http://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
    # Strip path, query, fragment
    d = d.split("/")[0].split("?")[0].split("#")[0]
    # Strip port
    if ":" in d:
        d = d.split(":")[0]
    # Strip trailing dot (FQDN notation)
    d = d.rstrip(".")
    return d


def _load_domains_file(path: str) -> list:
    """Load domains from a file, one per line. Skips blanks and comments."""
    domains = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                domains.append(line)
    return domains


async def _run_audit(args: argparse.Namespace) -> int:
    # Configure concurrency limits
    from domain_audit.lib.concurrency import sem
    sem.set_limits(domain=args.concurrency)
    logger.debug(
        "Concurrency: %d domains, %d CF API, %d DNS, %d RDAP, %d HTTP",
        sem.limit_domain, sem.limit_cf_api, sem.limit_dns,
        sem.limit_rdap, sem.limit_http,
    )

    # Cloudflare token is optional
    token = args.cloudflare_token or os.environ.get("CF_API_TOKEN", "") or config.CF_API_TOKEN
    has_cf = bool(token)

    # Collect domains from all sources
    raw_domains = []
    if args.domains:
        raw_domains.extend(args.domains)
    if args.domains_file:
        try:
            raw_domains.extend(_load_domains_file(args.domains_file))
        except FileNotFoundError:
            logger.critical("Domains file not found: %s", args.domains_file)
            return 1
        except Exception as e:
            logger.critical("Error reading domains file: %s", e)
            return 1
    if not raw_domains:
        raw_domains.extend(config.DOMAINS)

    # Normalise all domains (strip URLs, trailing dots, whitespace)
    domains_filter = list(dict.fromkeys(
        normalise_domain(d) for d in raw_domains if normalise_domain(d)
    ))

    if not domains_filter and not has_cf:
        logger.critical(
            "No domains specified. Use --domains, --domains-file, or --cloudflare-token.\n"
            "  domain-audit --domains example.com\n"
            "  domain-audit --domains-file domains.txt\n"
            "  domain-audit --cloudflare-token YOUR_TOKEN"
        )
        return 1

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

    # ── 1. Resolve domains ────────────────────────────────────────────
    raw_dns = {}
    security_results = {}
    zone_ids = {}

    if has_cf:
        config.CF_API_TOKEN = token
        async with cf_client.build_session() as session:
            if domains_filter:
                logger.info("[1/7] Resolving zone IDs for %d domain(s) ...", len(domains_filter))
                zone_ids = await cf_client.get_zone_ids(session, domains_filter)
            else:
                logger.info("[1/7] Discovering all zones on this API token ...")
                zone_ids = await cf_client.list_all_zones(session)

            resolved = list(zone_ids.keys()) if zone_ids else list(domains_filter or [])
            if zone_ids:
                logger.info("       Found %d zone(s): %s", len(resolved), ", ".join(resolved))

                # ── 2. Cloudflare API checks ──────────────────────────────
                logger.info("[2/7] Fetching DNS inventory and zone settings ...")
                dns_task      = asyncio.create_task(dns_inventory.fetch_all(session, zone_ids))
                security_task = asyncio.create_task(zone_security.check_all(session, zone_ids))

                raw_dns, security_results = await asyncio.gather(dns_task, security_task)
            else:
                logger.warning("No zones found on Cloudflare — running DNS/HTTP checks only.")
    else:
        resolved = list(domains_filter)
        logger.info("[1/7] Auditing %d domain(s) (no Cloudflare token) ...", len(resolved))
        logger.info("[2/7] Skipping Cloudflare API checks (no token provided)")

    if not resolved:
        logger.critical("No domains to audit.")
        return 1

    dns_summaries = {
        domain: dns_inventory.summarise(records)
        for domain, records in raw_dns.items()
    }

    # Registrar checks (always run, doesn't need CF)
    registrar_results = await registrar.check_all(resolved)

    # ── 3. Live DNS + HTTP checks (no Cloudflare needed) ────────────
    logger.info("[3/7] Running live DNS and HTTP checks for %d domain(s) ...", len(resolved))
    email_task      = asyncio.create_task(email_security.check_all(resolved))
    dns_sec_task    = asyncio.create_task(dns_security.check_all(resolved, raw_dns))
    blacklist_task  = asyncio.create_task(blacklist.check_all(resolved))
    rdns_task       = asyncio.create_task(reverse_dns.check_all(resolved))
    email_std_task  = asyncio.create_task(email_standards.check_all(resolved))
    web_sec_task    = asyncio.create_task(web_security.check_all(resolved))
    ct_task         = asyncio.create_task(cert_transparency.check_all(resolved))
    internetdb_task = asyncio.create_task(shodan_internetdb.check_all(resolved))
    obs_task        = asyncio.create_task(mozilla_observatory.check_all(resolved))
    osint_task      = asyncio.create_task(optional_checks.check_all(resolved))

    (email_results, dns_sec_results, blacklist_results,
     rdns_results, email_std_results, web_sec_results,
     ct_results, internetdb_results, obs_results,
     osint_results) = await asyncio.gather(
        email_task, dns_sec_task, blacklist_task, rdns_task,
        email_std_task, web_sec_task, ct_task, internetdb_task,
        obs_task, osint_task,
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
        web_sec_results    = web_sec_results,
        ct_results         = ct_results,
        internetdb_results = internetdb_results,
        obs_results        = obs_results,
        osint_results      = osint_results,
    )

    if "md" in args.format:
        reporter.write_markdown(**report_kwargs, output_path=path_md)
    if "html" in args.format:
        reporter.write_html(**report_kwargs, output_path=path_html, diff_result=diff_result)
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

    paths = []
    if "md" in args.format:
        paths.append(path_md)
    if "html" in args.format:
        paths.append(path_html)
    if "csv" in args.format:
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

    if has_fail:
        return 2  # At least one FAIL
    return 0


ERROR_LOG = "domain-audit-error.log"


def _write_error_log(error_type: str, error: Exception = None):
    """Write a crash/error log that users can attach to GitHub issues."""
    import traceback
    import platform
    from domain_audit import __version__

    try:
        with open(ERROR_LOG, "w", encoding="utf-8") as f:
            f.write(f"Domain Security Toolkit v{__version__}\n")
            f.write(f"Python {platform.python_version()} on {platform.system()} {platform.release()}\n")
            f.write(f"Error type: {error_type}\n")
            f.write(f"Timestamp: {__import__('datetime').datetime.now().isoformat()}\n")
            f.write("=" * 60 + "\n\n")
            if error:
                traceback.print_exc(file=f)
            else:
                f.write("Interrupted by user (Ctrl+C)\n")
            f.write("\n\nPlease attach this file when opening an issue:\n")
            f.write("https://github.com/wblv-dev/domain-security-toolkit/issues\n")
        print(f"\n  Error details saved to {ERROR_LOG}", file=sys.stderr)
    except Exception:
        pass  # Don't fail on failure to write error log


def main() -> int:
    args = parse_args()
    setup_logging(verbose=args.verbose, log_file=args.log_file)

    import time
    start = time.time()

    try:
        result = asyncio.run(_run_audit(args))
        elapsed = time.time() - start
        print(f"\n  Completed in {elapsed:.1f}s")
        return result
    except KeyboardInterrupt:
        elapsed = time.time() - start
        _write_error_log("KeyboardInterrupt")
        print(f"\n  Interrupted after {elapsed:.1f}s", file=sys.stderr)
        return 130
    except Exception as e:
        elapsed = time.time() - start
        _write_error_log("Unhandled exception", e)
        logger.critical("Unexpected error: %s", e, exc_info=args.verbose)
        print(f"\n  Failed after {elapsed:.1f}s", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
