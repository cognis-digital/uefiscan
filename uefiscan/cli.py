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
        choices=("table", "json"),
        default="table",
        help="output format (default: table)",
    )
    scan.add_argument(
        "--no-color", action="store_true", help="disable ANSI colors in table output"
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

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
        print(json.dumps(result.to_dict(), indent=2))
    else:
        use_color = sys.stdout.isatty() and not args.no_color
        print(_render_table(result, use_color))

    # Non-zero exit when the audit fails -> usable as a CI gate.
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
