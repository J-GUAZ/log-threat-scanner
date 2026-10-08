"""Parse web access logs and SSH auth logs into one common event shape."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# Combined Log Format (nginx / Apache), e.g.
# 203.0.113.5 - - [08/Oct/2026:14:00:01 +0000] "GET /about HTTP/1.1" 200 512 "-" "Mozilla/5.0"
ACCESS_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{3})'
)

# OpenSSH lines from syslog (/var/log/auth.log), e.g.
# Oct  8 14:02:11 web01 sshd[4121]: Failed password for invalid user admin from 198.51.100.7 port 52344 ssh2
AUTH_LINE = re.compile(r"^(?P<time>[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}) \S+ sshd\[\d+\]: (?P<message>.*)$")
AUTH_RESULT = re.compile(r"^(?P<result>Failed|Accepted) \S+ for (?:invalid user )?\S+ from (?P<ip>\S+)")

# A POST answered with one of these is treated as a failed web login.
LOGIN_FAILURE_STATUSES = {401, 403}


@dataclass(frozen=True)
class LogEvent:
    timestamp: datetime
    ip: str
    source: str  # "access" or "auth"
    path: str = ""  # request path; access logs only
    failed_login: bool = False


def parse_access_line(line: str) -> LogEvent | None:
    match = ACCESS_LINE.match(line)
    if not match:
        return None
    try:
        timestamp = datetime.strptime(match["time"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None
    return LogEvent(
        timestamp=timestamp,
        ip=match["ip"],
        source="access",
        path=match["path"],
        failed_login=match["method"] == "POST" and int(match["status"]) in LOGIN_FAILURE_STATUSES,
    )


def parse_auth_line(line: str, year: int) -> LogEvent | None:
    match = AUTH_LINE.match(line)
    if not match:
        return None
    result = AUTH_RESULT.match(match["message"])
    if not result:
        return None  # sshd noise like "Connection closed by ..."
    # Syslog timestamps carry no year or timezone, so assume the given year and UTC.
    try:
        timestamp = datetime.strptime(f"{year} {match['time']}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    return LogEvent(
        timestamp=timestamp.replace(tzinfo=timezone.utc),
        ip=result["ip"],
        source="auth",
        failed_login=result["result"] == "Failed",
    )


def parse_line(line: str, year: int) -> LogEvent | None:
    """Try each known format; return None if the line isn't a recognized event."""
    return parse_access_line(line) or parse_auth_line(line, year)


def parse_files(paths: list[Path], year: int) -> tuple[list[LogEvent], int]:
    """Parse every file and return (events sorted by time, number of ignored lines)."""
    events: list[LogEvent] = []
    ignored = 0
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as log_file:
            for line in log_file:
                if not line.strip():
                    continue
                event = parse_line(line.rstrip("\n"), year)
                if event is None:
                    ignored += 1
                else:
                    events.append(event)
    events.sort(key=lambda event: event.timestamp)
    return events, ignored
