import json
from pathlib import Path

from log_threat_scanner.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, main

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
SAMPLE_ARGS = [str(SAMPLES / "access.log"), str(SAMPLES / "auth.log"), "--year", "2026"]


def test_sample_logs_produce_expected_findings(capsys):
    assert main(SAMPLE_ARGS + ["--json"]) == EXIT_FINDINGS
    findings = json.loads(capsys.readouterr().out)
    found = {(f["rule"], f["ip"]) for f in findings}
    assert found == {
        ("brute-force", "192.0.2.44"),  # web login stuffing
        ("brute-force", "198.51.100.7"),  # SSH brute force
        ("suspicious-path", "198.51.100.23"),  # scanner
        ("request-spike", "203.0.113.99"),  # scraper
    }
    # The user who mistyped their password once or twice must not be flagged.
    assert not any(f["ip"] in ("203.0.113.11", "203.0.113.12") for f in findings)


def test_text_report_has_summary_line(capsys):
    main(SAMPLE_ARGS)
    out = capsys.readouterr().out
    assert "Scanned 2 file(s)" in out
    assert "7 finding(s): 4 high, 3 medium" in out


def test_clean_log_exits_zero(tmp_path, capsys):
    log = tmp_path / "access.log"
    log.write_text('203.0.113.5 - - [08/Oct/2026:14:00:01 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n')
    assert main([str(log)]) == EXIT_CLEAN
    assert "No threats found." in capsys.readouterr().out


def test_thresholds_are_configurable(capsys):
    # Raising the brute-force threshold above 12 hides both brute-force findings.
    main(SAMPLE_ARGS + ["--json", "--failures", "13"])
    rules = {f["rule"] for f in json.loads(capsys.readouterr().out)}
    assert "brute-force" not in rules


def test_missing_file_exits_with_error(tmp_path, capsys):
    assert main([str(tmp_path / "nope.log")]) == EXIT_ERROR
    assert "error:" in capsys.readouterr().err
