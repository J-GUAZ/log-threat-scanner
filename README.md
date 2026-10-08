# log-threat-scanner

A small Python CLI that scans web server access logs and SSH auth logs for signs of attack:

- **Brute-force logins**: many failed logins from one IP within a time window (SSH and web `POST` logins)
- **Suspicious request paths**: path traversal (`../`), SQL injection, `.env` / `.git` probes, WordPress admin probes, including URL-encoded and double-encoded payloads
- **Request spikes**: one IP sending an unusual burst of requests (scrapers, floods)

Standard library only (Python 3.10+), about 300 lines, fully type-hinted, and covered by 40 pytest tests.

## Quick start

```bash
git clone https://github.com/J-GUAZ/log-threat-scanner.git
cd log-threat-scanner
python3 -m log_threat_scanner samples/access.log samples/auth.log --year 2026
```

Or install it as a command:

```bash
pip install .
log-threat-scanner /var/log/nginx/access.log /var/log/auth.log
```

## Sample output

Run against the included sample logs (fake data, using documentation-only IP ranges from RFC 5737):

```
Scanned 2 file(s): 136 events, 3 lines ignored

SEVERITY  RULE             IP               COUNT  FIRST SEEN (UTC)     DETAIL
high      brute-force      192.0.2.44          12  2026-10-08 14:07:00  12 failed logins within 5 min
high      brute-force      198.51.100.7         8  2026-10-08 14:08:20  8 failed logins within 5 min
high      suspicious-path  198.51.100.23        1  2026-10-08 14:10:12  path traversal: /static/..%2F..%2F..%2Fetc%2Fpasswd
high      suspicious-path  198.51.100.23        2  2026-10-08 14:10:15  SQL injection: /products?id=1%27%20OR%201%3D1--
medium    suspicious-path  198.51.100.23        2  2026-10-08 14:10:00  WordPress admin probe: /wp-admin/
medium    suspicious-path  198.51.100.23        2  2026-10-08 14:10:06  sensitive file probe: /.env
medium    request-spike    203.0.113.99        75  2026-10-08 14:12:00  75 requests within 1 min

7 finding(s): 4 high, 3 medium
```

The sample logs also contain normal traffic and two users who mistype their password once or
twice. They are correctly **not** flagged.

Use `--json` for machine-readable output:

```json
[
  {
    "rule": "brute-force",
    "severity": "high",
    "ip": "192.0.2.44",
    "count": 12,
    "first_seen": "2026-10-08T14:07:00+00:00",
    "last_seen": "2026-10-08T14:08:50+00:00",
    "detail": "12 failed logins within 5 min"
  }
]
```

## Options

| Option | Default | Meaning |
|---|---|---|
| `--failures N` | 5 | Failed logins from one IP that count as brute force |
| `--failure-window MIN` | 5 | Brute-force time window, in minutes |
| `--spike N` | 60 | Requests from one IP that count as a spike |
| `--spike-window SEC` | 60 | Spike time window, in seconds |
| `--year YYYY` | current year | Year for auth-log timestamps (syslog lines don't include one) |
| `--json` | off | Print findings as JSON |

**Exit codes:** `0` no findings, `1` findings, `2` error (e.g. file not found). That makes it easy
to use from cron or CI: `log-threat-scanner access.log || alert-me`.

## Supported log formats

The format is detected per line, so access and auth logs can be passed together.

**Web access logs** (nginx / Apache Combined Log Format):
```
203.0.113.5 - - [08/Oct/2026:14:00:01 +0000] "GET /about HTTP/1.1" 200 512 "-" "Mozilla/5.0"
```
A `POST` answered with `401` or `403` counts as a failed web login.

**SSH auth logs** (OpenSSH via syslog, e.g. `/var/log/auth.log`):
```
Oct  8 14:08:20 web01 sshd[4121]: Failed password for invalid user admin from 198.51.100.7 port 40001 ssh2
```
Syslog timestamps have no year or timezone, so they're read as the `--year` you pass, in UTC.

Lines that don't match either format (or aren't security-relevant, like `Connection closed`)
are counted as "ignored".

## How it works

```
log files ──► parser.py ──► LogEvent(timestamp, ip, source, path, failed_login)
                                   │
                                   ▼
                            detectors.py
             ┌─────────────────────┼─────────────────────┐
     brute force           suspicious paths         request spikes
  (failed logins per IP,   (decode URL, match      (requests per IP,
   sliding time window)     attack regexes)         sliding time window)
             └─────────────────────┼─────────────────────┘
                                   ▼
                       cli.py ──► text table or JSON
```

- **`parser.py`** turns each line into a `LogEvent`, so the detectors don't care which log it came from.
- **`detectors.py`**: brute force and spikes share one sliding-window helper (`busiest_window`),
  which finds the most events from one IP inside any window of the given length in a single pass.
  Path checks URL-decode twice (to catch double-encoding like `%252e%252e%252f`), then match a
  short list of regexes ordered from most to least severe.
- **`cli.py`** handles arguments, output formatting, and exit codes.

## Limitations

This is a learning-sized tool, not a replacement for a SIEM or fail2ban:

- Fixed thresholds, not a learned per-site baseline. Tune `--failures` and `--spike` for your traffic.
- Regex path matching catches common, noisy attacks. A determined attacker can obfuscate around it.
- Reads whole files in one go (no streaming / tailing), so it's suited to batch review, not live monitoring.
- Behind a proxy or CDN, the IP in the log may be the proxy's unless it logs the real client IP.

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## License

MIT
