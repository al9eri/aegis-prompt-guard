"""Command-line interface for AEGIS untrusted document & evidence scanning."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scanner import ScanReport, scan_file


def _collect_targets(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    return sorted(
        p for p in target.rglob("*")
        if p.is_file() and ".git" not in p.parts and "__pycache__" not in p.parts
    )


def _print_human(reports: list[ScanReport]) -> None:
    for r in reports:
        badge = {
            "CLEAN": "[OK]",
            "FLAGGED": "[WARN]",
            "QUARANTINE": "[BLOCK]",
        }[r.verdict]
        print(f"{badge} {r.source}  (risk={r.risk_score:.2f}, sha256={r.sha256[:12]}...)")
        for f in r.findings:
            print(
                f"    -> {f.rule_id} [{f.severity.value}] line {f.line}: "
                f"{f.description} ({f.snippet})"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="AEGIS — Untrusted Evidence & Indirect Prompt-Injection Firewall",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    scan_p = sub.add_parser("scan", help="Scan a file or directory for prompt-injection vectors")
    scan_p.add_argument("path", type=Path, help="Target file or directory path")
    scan_p.add_argument("--json", action="store_true", help="Emit structured JSON report")
    scan_p.add_argument(
        "--strict",
        action="store_true",
        help="Return non-zero exit code on any finding (including FLAGGED)",
    )

    args = parser.parse_args(argv)
    targets = _collect_targets(args.path)
    reports = [scan_file(t) for t in targets]

    if args.json:
        print(json.dumps([r.to_dict() for r in reports], indent=2))
    else:
        _print_human(reports)

    if any(r.verdict == "QUARANTINE" for r in reports):
        return 2
    if args.strict and any(r.verdict != "CLEAN" for r in reports):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
