"""Command-line interface for UEFISCAN.

Examples
--------
  # Friendly red/green verdict for a firmware dump
  uefiscan scan firmware.bin

  # Machine-readable output for CI / piping
  uefiscan scan firmware.bin --format json | jq .verdict

  # Exit code is non-zero when the audit FAILS (use it as a CI gate)
  uefiscan scan firmware.bin && echo OK || echo "Secure Boot problems"
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import audit_image, AuditResult

_GREEN = "\033[32m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_DIM = "\033[2m"
_RESET = "\033[0m"


def _color(text: str, code: str, enable: bool) -> str:
    return "{}{}{}".format(code, text, _RESET) if enable else text


def _render_table(result: AuditResult, use_color: bool) -> str:
    lines: List[str] = []
    lines.append("UEFISCAN report for {}".format(result.path))
    lines.append("  size               : {:,} bytes".format(result.size))
    lines.append("  firmware volumes   : {}".format(result.firmware_volumes))

    sb = result.secureboot_vars
    sb_line = "  Secure Boot keys   : " + ", ".join(
        "{}={}".format(
            k,
            _color("yes", _GREEN, use_color) if v else _color("NO", _RED, use_color),
        )
        for k, v in sb.items()
    )
    lines.append(sb_line)
    lines.append(
        "  modules            : {} total, {} signed, {} unsigned".format(
            result.total_modules, result.signed_modules, result.unsigned_modules
        )
    )

    if result.findings:
        lines.append("  findings:")
        for f in result.findings:
            if f.code in ("unsigned-module",):
                # Per-module info lines: keep them dim and indented.
                loc = " @ 0x{:X}".format(f.offset) if f.offset is not None else ""
                lines.append(
                    _color("      - {}{}".format(f.message, loc), _DIM, use_color)
                )
                continue
            if f.level == "error":
                tag = _color("[FAIL]", _RED, use_color)
            elif f.level == "warn":
                tag = _color("[WARN]", _YELLOW, use_color)
            else:
                tag = "[INFO]"
            loc = " @ 0x{:X}".format(f.offset) if f.offset is not None else ""
            lines.append("    {} {}{}".format(tag, f.message, loc))

    verdict_color = _GREEN if result.ok else _RED
    lines.append("")
    lines.append(
        "VERDICT: "
        + _color(result.verdict, verdict_color, use_color)
        + ("  (Secure Boot looks healthy)" if result.ok else "  (action needed)")
    )
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Audit a UEFI firmware dump for missing Secure Boot keys and "
            "unsigned modules. A friendly red/green verdict instead of raw "
            "CHIPSEC output."
        ),
        epilog=(
            "examples:\n"
            "  uefiscan scan firmware.bin\n"
            "  uefiscan scan firmware.bin --format json | jq .verdict\n"
            "  uefiscan scan dump.rom && echo SAFE || echo PROBLEM\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version="{} {}".format(TOOL_NAME, TOOL_VERSION)
    )

    sub = parser.add_subparsers(dest="command")
    scan = sub.add_parser(
        "scan",
        help="scan a firmware image and print a Secure Boot verdict",
        description="Scan a UEFI firmware dump and report a red/green verdict.",
    )
    scan.add_argument("image", help="path to the firmware dump (e.g. firmware.bin)")
    scan.add_argument(
        "--format",
        choices=("table", "json", "sarif"),
        default="table",
        help="output format (default: table)",
    )
    scan.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="write the report to FILE instead of stdout",
    )
    scan.add_argument(
        "--no-color", action="store_true", help="disable ANSI colors in table output"
    )

    # ---- data-feed enrichment (CISA KEV) --------------------------------- #
    feeds = sub.add_parser(
        "feeds",
        help="CISA KEV threat-intel feed: list / update cache / cross-reference CVEs",
        description=(
            "Edge/air-gap data-feed layer. Ingests the CISA Known Exploited "
            "Vulnerabilities (KEV) catalog over HTTPS, caches it to disk, and "
            "re-serves it offline. Use it to flag which firmware/platform CVEs "
            "are being actively exploited and carry a federal patch deadline."
        ),
    )
    fsub = feeds.add_subparsers(dest="feeds_cmd")

    fsub.add_parser("list", help="list the feed(s) this tool consumes and cache freshness")

    fu = fsub.add_parser("update", help="fetch + cache the KEV catalog (online)")
    fu.add_argument("id", nargs="?", default="cisa-kev", help="feed id (default: cisa-kev)")

    fg = fsub.add_parser("get", help="cross-reference CVEs against KEV (or dump the catalog)")
    fg.add_argument("id", nargs="?", default="cisa-kev", help="feed id (default: cisa-kev)")
    fg.add_argument(
        "--cve",
        action="append",
        default=[],
        metavar="CVE-ID",
        help="component CVE to check against KEV (repeatable)",
    )
    fg.add_argument(
        "--offline",
        action="store_true",
        help="serve from the on-disk cache only; never touch the network",
    )
    fg.add_argument("--format", choices=("table", "json"), default="table")

    return parser


def _run_feeds(args, parser) -> int:
    """Handle the `uefiscan feeds ...` data-feed enrichment subcommand."""
    from . import datafeeds, feeds as feedlib

    cmd = getattr(args, "feeds_cmd", None)

    if cmd == "list":
        for f in datafeeds.list_feeds():
            if f["id"] not in feedlib.RELEVANT_FEEDS:
                continue
            age = datafeeds.cached_age_hours(f["id"])
            fresh = "uncached" if age is None else "{:.1f}h old".format(age)
            print("  {:10} [{}]  {}".format(f["id"], fresh, f["name"]))
            print("       source: {}".format(f["url"]))
        return 0

    if cmd == "update":
        fid = args.id
        if fid not in feedlib.RELEVANT_FEEDS:
            print("error: uefiscan only consumes {}".format(", ".join(feedlib.RELEVANT_FEEDS)),
                  file=sys.stderr)
            return 2
        try:
            path = datafeeds.update(fid)
        except (KeyError, ConnectionError) as exc:
            print("error: {}".format(exc), file=sys.stderr)
            return 2
        print("updated {} -> {} ({:,} bytes)".format(fid, path, path.stat().st_size))
        return 0

    if cmd == "get":
        fid = args.id
        if fid not in feedlib.RELEVANT_FEEDS:
            print("error: uefiscan only consumes {}".format(", ".join(feedlib.RELEVANT_FEEDS)),
                  file=sys.stderr)
            return 2
        try:
            if args.cve:
                report = feedlib.enrich_cves(args.cve, offline=args.offline)
            else:
                cat = feedlib.load_kev(offline=args.offline)
                report = {
                    "kev_catalog_size": len(cat.get("vulnerabilities", [])),
                    "catalogVersion": cat.get("catalogVersion", ""),
                    "dateReleased": cat.get("dateReleased", ""),
                }
        except FileNotFoundError as exc:
            print("error: {} (run `uefiscan feeds update` while online, or import a snapshot)".format(exc),
                  file=sys.stderr)
            return 2
        except ConnectionError as exc:
            print("error: {}".format(exc), file=sys.stderr)
            return 2

        if args.format == "json":
            print(json.dumps(report, indent=2))
            return 0

        if args.cve:
            print("KEV cross-reference  (catalog: {} CVEs)".format(report["kev_catalog_size"]))
            print("  checked {}, {} known-exploited, {} ransomware-linked".format(
                report["total"], report["known_exploited"], report["ransomware_linked"]))
            for it in report["items"]:
                if it["known_exploited"]:
                    tag = "[KEV]"
                    extra = "  {} {}  due {}{}".format(
                        it["vendor"], it["product"], it["due_date"],
                        "  RANSOMWARE" if it["ransomware"] else "")
                else:
                    tag = "[ -- ]"
                    extra = "  not in KEV"
                print("  {} {}{}".format(tag, it["cve"], extra))
            if report["patch_now"]:
                print("\nPATCH NOW (prioritised): {}".format(", ".join(report["patch_now"])))
            return 0

        print("CISA KEV catalog: {} known-exploited CVEs (version {}, released {})".format(
            report["kev_catalog_size"], report.get("catalogVersion", "?"),
            report.get("dateReleased", "?")))
        return 0

    # `feeds` with no subcommand
    parser.parse_args(["feeds", "--help"])
    return 2


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "feeds":
        return _run_feeds(args, parser)

    if args.command != "scan":
        parser.print_help()
        return 2

    try:
        result = audit_image(args.image)
    except FileNotFoundError:
        print("error: file not found: {}".format(args.image), file=sys.stderr)
        return 2
    except OSError as exc:
        print("error: could not read {}: {}".format(args.image, exc), file=sys.stderr)
        return 2

    if args.format == "json":
        rendered = json.dumps(result.to_dict(), indent=2)
    elif args.format == "sarif":
        rendered = json.dumps(result.to_sarif(TOOL_VERSION), indent=2)
    else:
        # Never emit ANSI colors when writing to a file.
        use_color = sys.stdout.isatty() and not args.no_color and not args.output
        rendered = _render_table(result, use_color)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(rendered + "\n")
        except OSError as exc:
            print("error: could not write {}: {}".format(args.output, exc), file=sys.stderr)
            return 2
    else:
        print(rendered)

    # Non-zero exit when the audit fails -> usable as a CI gate.
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
