"""
Tests for scanner.py

What this covers:
- run_scan() correctly maps Semgrep's raw JSON into our internal finding shape
- run_scan() returns [] when Semgrep's stdout isn't valid JSON (e.g. it crashed/timed out)
- run_scan() returns [] when there are no results
- run_scan() falls back to "" when a finding has no `lines` field
- run_scan() invokes semgrep with the exact expected command/config/timeout

We never invoke real Semgrep — subprocess.run is mocked in every test.
"""
import subprocess
import json
import scanner


SAMPLE_SEMGREP_OUTPUT = {
    "results": [
        {
            "path": "app.py",
            "start": {"line": 42},
            "check_id": "python.lang.security.audit.sql-injection",
            "extra": {
                "severity": "ERROR",
                "message": "Possible SQL injection",
                "lines": "cursor.execute(query)"
            }
        },
        {
            "path": "utils.py",
            "start": {"line": 7},
            "check_id": "python.lang.security.audit.hardcoded-secret",
            "extra": {
                "severity": "WARNING",
                "message": "Hardcoded secret detected"
                # no "lines" key here on purpose
            }
        }
    ]
}


def _completed(stdout: str):
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")


def test_run_scan_parses_findings_correctly(mocker):
    mock_run = mocker.patch("scanner.subprocess.run")
    mock_run.return_value = _completed(json.dumps(SAMPLE_SEMGREP_OUTPUT))

    findings = scanner.run_scan("/tmp/some_repo")

    assert len(findings) == 2

    first = findings[0]
    assert first["file"] == "app.py"
    assert first["line"] == 42
    assert first["rule_id"] == "python.lang.security.audit.sql-injection"
    assert first["severity"] == "ERROR"
    assert first["message"] == "Possible SQL injection"
    assert first["code_snippet"] == "cursor.execute(query)"


def test_run_scan_defaults_code_snippet_when_lines_missing(mocker):
    mock_run = mocker.patch("scanner.subprocess.run")
    mock_run.return_value = _completed(json.dumps(SAMPLE_SEMGREP_OUTPUT))

    findings = scanner.run_scan("/tmp/some_repo")

    second = findings[1]
    assert second["file"] == "utils.py"
    assert second["code_snippet"] == ""  # .get() fallback


def test_run_scan_returns_empty_list_on_malformed_json(mocker):
    mock_run = mocker.patch("scanner.subprocess.run")
    mock_run.return_value = _completed("not valid json output {{{")

    findings = scanner.run_scan("/tmp/some_repo")

    assert findings == []


def test_run_scan_returns_empty_list_when_no_results(mocker):
    mock_run = mocker.patch("scanner.subprocess.run")
    mock_run.return_value = _completed(json.dumps({"results": []}))

    findings = scanner.run_scan("/tmp/some_repo")

    assert findings == []


def test_run_scan_invokes_semgrep_with_expected_command(mocker):
    mock_run = mocker.patch("scanner.subprocess.run")
    mock_run.return_value = _completed(json.dumps({"results": []}))

    scanner.run_scan("/tmp/some_repo")

    assert mock_run.call_count == 1
    call = mock_run.call_args
    cmd = call.args[0]
    assert cmd == [
        "semgrep",
        "--config", "p/python",
        "--config", "p/secrets",
        "--json",
        "--timeout", "30",
        "/tmp/some_repo"
    ]
    assert call.kwargs["capture_output"] is True
    assert call.kwargs["text"] is True
    assert call.kwargs["timeout"] == 60
