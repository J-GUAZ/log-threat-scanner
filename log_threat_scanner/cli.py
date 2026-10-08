"""Command-line interface: parse log files, run the detectors, print a report."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .detectors import Finding, run_all
from .parser import parse_files

# Exit codes, so the scanner can be used in scripts and cron jobs.
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-threat-scanner",
        description="Scan web access logs and SSH auth logs for signs of attack.",
    )
    parser.add_argument("logs", nargs="+", type=Path, help="log files to scan (access and/or auth format)")
    parser.add_argument("--json", action="store_true", help="print findings as JSON")
    parser.add_argument("--failures", type=int, default=5, help="failed logins that count as brute force (default: 5)")
    parser.add_argument("--failure-window", type=int, default=5, metavar="MIN", help="brute-force window in minutes (default: 5)")
    parser.add_argument("--spike", type=int, default=60, help="requests from one IP that count as a spike (default: 60)")
    parser.add_argument("--spike-window", type=int, default=60, metavar="SEC", help="spike window in seconds (default: 60)")
    parser.add_argument(
        "--year",
        type=int,
        default=datetime.now(timezone.utc).year,
        help="year for auth-log timestamps, which don't include one (default: current year)",
    )
    return parser


def format_report(findings: list[Finding], files: int, events: int, ignored: int) -> str:
    lines = [f"Scanned {files} file(s): {events} events, {ignored} lines ignored", ""]
    if not findings:
        lines.append("No threats found.")
        return "\n".join(lines)

    lines.append(f"{'SEVERITY':<9} {'RULE':<16} {'IP':<16} {'COUNT':>5}  {'FIRST SEEN (UTC)':<19}  DETAIL")
    for f in findings:
        first_seen = f.first_seen.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        lines.append(f"{f.severity:<9} {f.rule:<16} {f.ip:<16} {f.count:>5}  {first_seen:<19}  {f.detail}")

    by_severity = Counter(f.severity for f in findings)
    summary = ", ".join(f"{by_severity[s]} {s}" for s in ("high", "medium", "low") if by_severity[s])
    lines += ["", f"{len(findings)} finding(s): {summary}"]
    return "\n".join(lines)


def findings_to_json(findings: list[Finding]) -> str:
    rows = [{**asdict(f), "first_seen": f.first_seen.isoformat(), "last_seen": f.last_seen.isoformat()} for f in findings]
    return json.dumps(rows, indent=2)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        events, ignored = parse_files(args.logs, year=args.year)
    except OSError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR

    findings = run_all(
        events,
        failure_threshold=args.failures,
        failure_window=timedelta(minutes=args.failure_window),
        spike_threshold=args.spike,
        spike_window=timedelta(seconds=args.spike_window),
    )
    if args.json:
        print(findings_to_json(findings))
    else:
        print(format_report(findings, len(args.logs), len(events), ignored))
    return EXIT_FINDINGS if findings else EXIT_CLEAN
