"""Detection rules. Each rule takes parsed events and returns a list of findings."""

from __future__ import annotations

import re
from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import unquote_plus

from .parser import LogEvent


@dataclass(frozen=True)
class Finding:
    rule: str  # "brute-force", "suspicious-path" or "request-spike"
    severity: str  # "high", "medium" or "low"
    ip: str
    count: int
    first_seen: datetime
    last_seen: datetime
    detail: str


# Checked in order; a request gets the first (most severe) label that matches.
SUSPICIOUS_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("path traversal", "high", re.compile(r"\.\.[/\\]")),
    (
        "SQL injection",
        "high",
        re.compile(
            r"union\s+(all\s+)?select"  # UNION SELECT ...
            r"|'\s*or\s+'?\d+'?\s*=\s*'?\d+"  # ' OR 1=1 / ' OR '1'='1
            r"|;\s*drop\s+table"  # ; DROP TABLE
            r"|\bsleep\s*\(\s*\d",  # time-based blind: SLEEP(5)
            re.IGNORECASE,
        ),
    ),
    ("sensitive file probe", "medium", re.compile(r"/\.(env|git|htpasswd)\b", re.IGNORECASE)),
    ("WordPress admin probe", "medium", re.compile(r"/wp-(admin|login\.php)", re.IGNORECASE)),
]

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def busiest_window(times: list[datetime], window: timedelta) -> tuple[int, datetime, datetime]:
    """Return (count, start, end) for the span of length `window` containing the most timestamps.

    `times` must be sorted and non-empty. Sliding window: add each timestamp on the right and
    drop timestamps from the left once they are more than `window` older than the newest one.
    """
    best = (0, times[0], times[0])
    current: deque[datetime] = deque()
    for time in times:
        current.append(time)
        while time - current[0] > window:
            current.popleft()
        if len(current) > best[0]:
            best = (len(current), current[0], time)
    return best


def times_by_ip(events: Iterable[LogEvent]) -> dict[str, list[datetime]]:
    grouped: dict[str, list[datetime]] = defaultdict(list)
    for event in events:
        grouped[event.ip].append(event.timestamp)
    return {ip: sorted(times) for ip, times in grouped.items()}


def describe(window: timedelta) -> str:
    seconds = int(window.total_seconds())
    return f"{seconds // 60} min" if seconds % 60 == 0 else f"{seconds} s"


def detect_brute_force(
    events: Iterable[LogEvent], threshold: int = 5, window: timedelta = timedelta(minutes=5)
) -> list[Finding]:
    """Flag IPs with at least `threshold` failed logins inside any `window`."""
    findings = []
    for ip, times in times_by_ip(e for e in events if e.failed_login).items():
        count, start, end = busiest_window(times, window)
        if count >= threshold:
            detail = f"{count} failed logins within {describe(window)}"
            findings.append(Finding("brute-force", "high", ip, count, start, end, detail))
    return findings


def detect_request_spikes(
    events: Iterable[LogEvent], threshold: int = 60, window: timedelta = timedelta(minutes=1)
) -> list[Finding]:
    """Flag IPs that sent at least `threshold` web requests inside any `window`."""
    findings = []
    for ip, times in times_by_ip(e for e in events if e.source == "access").items():
        count, start, end = busiest_window(times, window)
        if count >= threshold:
            detail = f"{count} requests within {describe(window)}"
            findings.append(Finding("request-spike", "medium", ip, count, start, end, detail))
    return findings


def classify_path(path: str) -> tuple[str, str] | None:
    """Return (label, severity) for a suspicious request path, or None if it looks normal."""
    # Decode twice so double-encoded payloads like %252e%252e%252f ("../") are caught too.
    decoded = unquote_plus(unquote_plus(path))
    for label, severity, pattern in SUSPICIOUS_PATTERNS:
        if pattern.search(decoded):
            return label, severity
    return None


def detect_suspicious_paths(events: Iterable[LogEvent]) -> list[Finding]:
    """Flag requests for attack paths, grouped into one finding per (IP, attack type)."""
    hits: dict[tuple[str, str, str], list[LogEvent]] = defaultdict(list)
    for event in events:
        if event.source != "access":
            continue
        match = classify_path(event.path)
        if match:
            label, severity = match
            hits[(event.ip, label, severity)].append(event)

    findings = []
    for (ip, label, severity), matched in hits.items():
        times = [event.timestamp for event in matched]
        detail = f"{label}: {matched[0].path}"
        findings.append(Finding("suspicious-path", severity, ip, len(matched), min(times), max(times), detail))
    return findings


def run_all(
    events: list[LogEvent],
    failure_threshold: int = 5,
    failure_window: timedelta = timedelta(minutes=5),
    spike_threshold: int = 60,
    spike_window: timedelta = timedelta(minutes=1),
) -> list[Finding]:
    """Run every rule and return findings, most severe first, then by time."""
    findings = (
        detect_brute_force(events, failure_threshold, failure_window)
        + detect_suspicious_paths(events)
        + detect_request_spikes(events, spike_threshold, spike_window)
    )
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.first_seen, f.ip))
