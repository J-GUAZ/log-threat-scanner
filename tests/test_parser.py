from datetime import datetime, timezone

from log_threat_scanner.parser import parse_access_line, parse_auth_line, parse_line


def test_parses_access_log_line():
    line = '203.0.113.5 - - [08/Oct/2026:14:00:01 +0000] "GET /about HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
    event = parse_access_line(line)
    assert event is not None
    assert event.ip == "203.0.113.5"
    assert event.path == "/about"
    assert event.source == "access"
    assert event.timestamp == datetime(2026, 10, 8, 14, 0, 1, tzinfo=timezone.utc)
    assert not event.failed_login


def test_post_with_401_is_a_failed_web_login():
    line = '192.0.2.44 - - [08/Oct/2026:14:07:00 +0000] "POST /login HTTP/1.1" 401 64 "-" "curl/8.0"'
    assert parse_access_line(line).failed_login


def test_get_with_401_is_not_a_login_attempt():
    line = '192.0.2.44 - - [08/Oct/2026:14:07:00 +0000] "GET /account HTTP/1.1" 401 64 "-" "curl/8.0"'
    assert not parse_access_line(line).failed_login


def test_parses_failed_ssh_login_for_invalid_user():
    line = "Oct  8 14:08:20 web01 sshd[4121]: Failed password for invalid user admin from 198.51.100.7 port 40001 ssh2"
    event = parse_auth_line(line, year=2026)
    assert event.ip == "198.51.100.7"
    assert event.failed_login
    assert event.timestamp == datetime(2026, 10, 8, 14, 8, 20, tzinfo=timezone.utc)


def test_parses_accepted_ssh_login():
    line = "Oct 18 09:00:00 web01 sshd[77]: Accepted publickey for deploy from 203.0.113.10 port 50122 ssh2"
    event = parse_auth_line(line, year=2026)
    assert event.ip == "203.0.113.10"
    assert not event.failed_login


def test_ignores_unrelated_and_malformed_lines():
    assert parse_line("Oct  8 14:11:40 web01 sshd[9]: Connection closed by 198.51.100.7 port 40008 [preauth]", 2026) is None
    assert parse_line("Oct  8 14:15:00 web01 CRON[12]: (root) CMD (/usr/local/bin/backup.sh)", 2026) is None
    assert parse_line("not a log line at all", 2026) is None
    assert parse_line('1.2.3.4 - - [99/Nope/2026:99:99:99 +0000] "GET / HTTP/1.1" 200 1', 2026) is None
