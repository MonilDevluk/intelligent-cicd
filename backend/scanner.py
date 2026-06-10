import subprocess
import json

def run_scan(repo_path: str) -> list:
    result = subprocess.run(
        [
            "semgrep",
            "--config", "auto",
            "--json",
            repo_path
        ],
        capture_output=True,
        text=True
    )

    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    findings = []
    for r in output.get("results", []):
        findings.append({
            "file": r["path"],
            "line": r["start"]["line"],
            "rule_id": r["check_id"],
            "severity": r["extra"]["severity"],
            "message": r["extra"]["message"],
            "code_snippet": r["extra"].get("lines", "")
        })

    return findings
