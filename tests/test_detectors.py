from datetime import datetime, timedelta, timezone

import pytest

from log_threat_scanner.detectors import (
    busiest_window,
    classify_path,
    detect_brute_force,
    detect_request_spikes,
    detect_suspicious_paths,
    run_all,
)
from log_threat_scanner.parser import LogEvent

START = datetime(2026, 10, 8, 14, 0, 0, tzinfo=timezone.utc)


def at(seconds: int) -> datetime:
    return START + timedelta(seconds=seconds)


def failed_login(ip: str, seconds: int) -> LogEvent:
    return LogEvent(timestamp=at(seconds), ip=ip, source="auth", failed_login=True)


def request(ip: str, seconds: int, path: str = "/") -> LogEvent:
    return LogEvent(timestamp=at(seconds), ip=ip, source="access", path=path)


# --- busiest_window ---


def test_busiest_window_finds_densest_cluster():
    times = [at(0), at(100), at(101), at(102), at(500)]
    assert busiest_window(times, timedelta(seconds=10)) == (3, at(100), at(102))


def test_busiest_window_includes_events_exactly_window_apart():
    assert busiest_window([at(0), at(60)], timedelta(seconds=60))[0] == 2


# --- brute force ---


def test_brute_force_flags_failures_at_threshold():
    events = [failed_login("198.51.100.7", s) for s in range(0, 50, 10)]  # 5 failures in 40 s
    [finding] = detect_brute_force(events, threshold=5, window=timedelta(minutes=5))
    assert finding.ip == "198.51.100.7"
    assert finding.count == 5
    assert finding.severity == "high"


def test_brute_force_ignores_failures_below_threshold():
    events = [failed_login("203.0.113.12", s) for s in range(0, 40, 10)]  # only 4
    assert detect_brute_force(events, threshold=5) == []


def test_brute_force_ignores_failures_spread_beyond_the_window():
    events = [failed_login("203.0.113.12", s) for s in range(0, 3000, 600)]  # 5 failures, 10 min apart
    assert detect_brute_force(events, threshold=5, window=timedelta(minutes=5)) == []


def test_brute_force_counts_each_ip_separately():
    events = [failed_login(f"192.0.2.{n}", s) for n in range(5) for s in range(2)]  # 5 IPs x 2 failures
    assert detect_brute_force(events, threshold=5) == []


# --- suspicious paths ---


@pytest.mark.parametrize(
    "path, label",
    [
        ("/../../etc/passwd", "path traversal"),
        ("/static/..%2F..%2Fetc%2Fpasswd", "path traversal"),
        ("/files/%252e%252e%252fsecret", "path traversal"),  # double-encoded
        ("/products?id=1%27%20OR%201%3D1--", "SQL injection"),
        ("/login?user=admin' or '1'='1", "SQL injection"),
        ("/search?q=a+UNION+SELECT+password+FROM+users", "SQL injection"),
        ("/item?id=1;DROP TABLE users", "SQL injection"),
        ("/item?id=1 AND SLEEP(5)", "SQL injection"),
        ("/.env", "sensitive file probe"),
        ("/.git/config", "sensitive file probe"),
        ("/wp-admin/", "WordPress admin probe"),
        ("/wp-login.php", "WordPress admin probe"),
    ],
)
def test_classify_path_detects_attacks(path, label):
    assert classify_path(path)[0] == label


@pytest.mark.parametrize(
    "path",
    ["/", "/about", "/blog/union-station-tour", "/search?q=select+a+venue", "/static/app.js", "/environment"],
)
def test_classify_path_ignores_normal_requests(path):
    assert classify_path(path) is None


def test_suspicious_paths_grouped_per_ip_and_attack_type():
    events = [
        request("198.51.100.23", 0, "/wp-admin/"),
        request("198.51.100.23", 5, "/wp-login.php"),
        request("198.51.100.23", 9, "/.env"),
        request("203.0.113.10", 10, "/about"),
    ]
    findings = sorted(detect_suspicious_paths(events), key=lambda f: f.detail)
    assert [(f.ip, f.count, f.severity) for f in findings] == [
        ("198.51.100.23", 2, "medium"),  # WordPress probes
        ("198.51.100.23", 1, "medium"),  # .env probe
    ]
    assert findings[0].first_seen == at(0) and findings[0].last_seen == at(5)


# --- request spikes ---


def test_request_spike_flags_burst_from_one_ip():
    events = [request("203.0.113.99", s // 2) for s in range(80)]  # 80 requests in 40 s
    [finding] = detect_request_spikes(events, threshold=60, window=timedelta(minutes=1))
    assert finding.ip == "203.0.113.99"
    assert finding.count == 80


def test_request_spike_ignores_steady_traffic():
    events = [request("203.0.113.10", s * 5) for s in range(200)]  # 1 request every 5 s
    assert detect_request_spikes(events, threshold=60) == []


def test_auth_events_do_not_count_toward_request_spikes():
    events = [failed_login("198.51.100.7", s) for s in range(100)]
    assert detect_request_spikes(events, threshold=60) == []


# --- run_all ---


def test_run_all_orders_findings_by_severity_then_time():
    events = sorted(
        [request("203.0.113.99", s // 3) for s in range(90)]  # spike (medium) at t=0
        + [failed_login("198.51.100.7", 100 + s) for s in range(5)],  # brute force (high) at t=100
        key=lambda e: e.timestamp,
    )
    assert [f.rule for f in run_all(events)] == ["brute-force", "request-spike"]
