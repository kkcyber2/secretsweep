"""Command line entry point."""
from __future__ import annotations

import argparse
import json
import sys

from .findings import ORDER, Severity
from .scanner import scan_path

MARK = {"critical": "!!", "high": "! ", "medium": "~ ", "low": ". "}


def render(result) -> str:
    lines = [
        f"Scanned {result.files_scanned} file(s) under {result.root}",
        f"Findings: {result.counts() or 'none'}",
        "",
    ]
    for finding in result.sorted_findings():
        lines.append(
            f"{MARK[finding.severity.value]} [{finding.severity.value.upper()}] "
            f"{finding.description}"
        )
        lines.append(f"     {finding.path}:{finding.line}:{finding.column}")
        lines.append(f"     {finding.match}")
        lines.append("")
    if not result.findings:
        lines.append("No secrets found.")
    return "\n".join(lines).rstrip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secretsweep", description="Scan a tree for committed secrets")
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--json", metavar="PATH")
    parser.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        help="exit non-zero when a finding at this severity or above is present",
    )
    args = parser.parse_args(argv)

    result = scan_path(args.path)
    print(render(result))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(result.public(), handle, indent=2)
        print(f"\nJSON report written to {args.json}")

    if args.fail_on:
        threshold = ORDER[Severity(args.fail_on)]
        if any(ORDER[f.severity] <= threshold for f in result.findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
