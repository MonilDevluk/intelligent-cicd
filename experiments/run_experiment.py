import sys
import os
import csv
import subprocess
import tempfile
import shutil

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '..', 'backend', '.env'))

from scanner import run_scan
from patcher import generate_patch
from sandbox import run_sandbox_test

RESULTS_FILE = os.path.join(os.path.dirname(__file__), 'results.csv')

def run_experiment(experiment_id: str, vuln_type: str, file_path: str, notes: str = ""):
    print(f"\n[EXP {experiment_id}] {vuln_type}")

    for condition in ["minimal", "enriched"]:
        print(f"  Running condition: {condition}")

        tmp_dir = tempfile.mkdtemp(prefix="exp_")
        try:
            shutil.copy(file_path, os.path.join(tmp_dir, os.path.basename(file_path)))

            findings = run_scan(tmp_dir)
            detected = len(findings) > 0
            print(f"  Semgrep detected: {detected} ({len(findings)} findings)")

            if not detected:
                append_result(experiment_id, vuln_type, condition, False, False, False, False, "NO_FINDING", notes)
                continue

            finding = findings[0]
            with open(finding["file"], "r") as f:
                file_content = f.read()

            try:
                patch = generate_patch(finding, file_content, condition)
                compiled = True
            except Exception as e:
                print(f"  Patch generation failed: {e}")
                append_result(experiment_id, vuln_type, condition, True, False, False, False, "PATCH_FAILED", notes)
                continue

            patch_file = os.path.join(tmp_dir, os.path.basename(file_path))
            with open(patch_file, "w") as f:
                f.write(patch)

            re_scan = run_scan(tmp_dir)
            semgrep_clean = len(re_scan) == 0
            print(f"  Semgrep clean after patch: {semgrep_clean}")

            test_result = run_sandbox_test(tmp_dir, finding["file"], patch)
            print(f"  Sandbox status: {test_result['status']}")

            append_result(
                experiment_id, vuln_type, condition,
                detected, compiled, semgrep_clean,
                test_result["passed"], test_result["status"], notes
            )

        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

def append_result(exp_id, vuln_type, condition, detected, compiled, semgrep_clean, tests_passed, status, notes):
    with open(RESULTS_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([exp_id, "", vuln_type, condition, detected, compiled, semgrep_clean, tests_passed, status, notes])
    print(f"  Saved: {condition} → {status}")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python run_experiment.py <experiment_id> <vuln_type> <file_path>")
        sys.exit(1)
    run_experiment(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else "")
