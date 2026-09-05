from pathlib import Path
import ast
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
VULNS = ROOT / "experiments" / "vulns"
GT_TESTS = ROOT / "research" / "datasets" / "tests"
RESULTS = ROOT / "research" / "results"
RUNS = RESULTS / "one_pass_runs"

sys.path.insert(0, str(BACKEND))

from dotenv import load_dotenv
load_dotenv(BACKEND / ".env")

from context_builder import build_context
from patcher import generate_refined_patch
from validator import validate_patch
from refinement import refine_patch


# ============================================================
# Configuration
# ============================================================

MODEL = os.getenv("GROQ_MODEL", "qwen/qwen3.6-27b")

# Keep individual calls small during the controlled run.
# Change only if the smoke test proves the output contract works.
MAX_TOKENS = 450
TEMPERATURE = 0.0

# Initial research pass.
CONDITIONS = ["C0", "C1", "C2", "C3"]

# Start with the complete CMDi family if available.
VULNERABILITIES = sorted(VULNS.glob("cmdi_*.py"))

# Two attempts maximum.
MAX_ATTEMPTS = 2

# Set to False only if you explicitly want to bypass the gate.
RUN_FULL_AFTER_SMOKE = True


# ============================================================
# Utilities
# ============================================================

def clean_output(text):
    if not text:
        return ""

    text = text.strip()

    # Remove Qwen reasoning blocks.
    text = re.sub(
        r"<think>.*?</think>",
        "",
        text,
        flags=re.DOTALL | re.IGNORECASE,
    )

    # Remove markdown fences.
    text = re.sub(
        r"```(?:python|py)?",
        "",
        text,
        flags=re.IGNORECASE,
    )
    text = text.replace("```", "")

    return text.strip()


def is_python(text):
    try:
        ast.parse(text)
        return True
    except Exception:
        return False


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


def result_dict(obj):
    if hasattr(obj, "__dataclass_fields__"):
        from dataclasses import asdict
        return asdict(obj)

    if isinstance(obj, dict):
        return obj

    return {
        k: getattr(obj, k)
        for k in dir(obj)
        if not k.startswith("_")
        and not callable(getattr(obj, k))
    }


# ============================================================
# Benchmark isolation
# ============================================================

def clean_benchmark_pollution():
    print("\n" + "=" * 70)
    print("1. BENCHMARK ISOLATION")
    print("=" * 70)

    polluted = ROOT / "cmdi_01.py"

    if polluted.exists():
        print("Removing accidental root-level benchmark copy:")
        print(polluted)
        polluted.unlink()

    # Remove pilot-generated root artifacts if present.
    for pattern in ["cmdi_*.py"]:
        for f in ROOT.glob(pattern):
            if f.is_file():
                print("Removing:", f)
                f.unlink()

    fixture = VULNS / "cmdi_01.py"

    if not fixture.exists():
        raise RuntimeError(
            f"Missing benchmark fixture: {fixture}"
        )

    print("Benchmark fixture:", fixture)
    print("Isolation: PASS")


# ============================================================
# Ground truth
# ============================================================

def verify_ground_truth():
    print("\n" + "=" * 70)
    print("2. GROUND-TRUTH VERIFICATION")
    print("=" * 70)

    test = GT_TESTS / "test_cmdi_01_security.py"

    p = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            str(test),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )

    print(p.stdout[-5000:])

    if p.returncode != 0:
        print(p.stderr[-5000:])
        raise RuntimeError(
            "Ground-truth benchmark is not healthy."
        )

    print("Ground truth: PASS")


# ============================================================
# Semgrep finding
# ============================================================

def detect(vuln):
    p = subprocess.run(
        [
            "semgrep",
            "scan",
            "--config",
            "p/python",
            "--config",
            "p/secrets",
            "--json",
            "--quiet",
            str(vuln),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=60,
    )

    if p.returncode not in (0, 1):
        raise RuntimeError(p.stderr)

    data = json.loads(p.stdout)

    if not data.get("results"):
        return None

    r = data["results"][0]

    return {
        "rule_id": r.get("check_id", ""),
        "severity": r.get("extra", {}).get("severity", ""),
        "message": r.get("extra", {}).get("message", ""),
        "line": r.get("start", {}).get("line"),
        "end_line": r.get("end", {}).get("line"),
        "snippet": r.get("extra", {}).get("lines", ""),
        "file": str(vuln),
    }


# ============================================================
# Security context
# ============================================================

def security_context(vuln, finding):
    name = vuln.stem.lower()

    if name.startswith("cmdi"):
        return {
            "cwe": "CWE-78",
            "attack_mechanism":
                "Untrusted input reaches an operating-system command.",
            "repair_guidance":
                "Avoid shell interpretation. Prefer subprocess "
                "argument lists with shell=False.",
            "constraints": [
                "Preserve intended functionality.",
                "Do not suppress security findings.",
                "Do not disable security checks.",
                "Return complete Python source.",
            ],
        }

    return {
        "cwe": "",
        "attack_mechanism": finding.get("message", ""),
        "repair_guidance":
            "Apply the smallest secure correction while preserving behavior.",
        "constraints": [
            "Preserve intended functionality.",
            "Do not suppress security findings.",
            "Return complete Python source.",
        ],
    }


# ============================================================
# Context
# ============================================================

def make_context(level, finding, source, vuln):
    sec = security_context(vuln, finding)

    try:
        return build_context(
            finding=finding,
            file_content=source,
            level=level,
            security_context=sec,
        )
    except TypeError:
        return build_context(
            finding,
            source,
            level,
        )


# ============================================================
# Prompt
# ============================================================

def base_prompt(level, finding, context, source):
    return f"""
/no_think

You are an autonomous secure-code repair system.

CONTEXT LEVEL: {level}

VULNERABILITY:
{json.dumps(finding, indent=2)}

SECURITY CONTEXT:
{json.dumps(context, indent=2) if isinstance(context, dict) else context}

CURRENT SOURCE:
{source}

STRICT OUTPUT REQUIREMENTS:
1. Return ONLY complete valid Python source code.
2. Do NOT output <think>.
3. Do NOT output reasoning.
4. Do NOT use Markdown.
5. Do NOT use code fences.
6. Do NOT explain the patch.
7. Preserve intended functionality.
8. Fix the identified security vulnerability.
9. Do not suppress the scanner.
10. Return the COMPLETE replacement file.
""".strip()


# ============================================================
# Validation
# ============================================================

def validate(vuln, source, patch):
    return validate_patch(
        repo_path=str(ROOT),
        file_path=str(vuln),
        original_content=source,
        patched_content=patch,
        generated_test=None,
    )


# ============================================================
# One experiment
# ============================================================

def experiment_one(level, vuln, run_number):
    source = vuln.read_text()

    finding = detect(vuln)

    if not finding:
        return {
            "status": "NO_FINDING",
            "benchmark": vuln.stem,
            "condition": level,
            "run": run_number,
        }

    context = make_context(
        level,
        finding,
        source,
        vuln,
    )

    initial = base_prompt(
        level,
        finding,
        context,
        source,
    )

    attempts = []
    prompt = initial

    for attempt_no in range(1, MAX_ATTEMPTS + 1):

        print(
            f"\n[{level}] {vuln.stem} "
            f"run={run_number} attempt={attempt_no}"
        )

        raw = generate_refined_patch(
            finding=finding,
            file_content=source,
            context=context,
            validation_feedback=prompt,
        )

        patch = clean_output(raw)

        if not patch:
            validation = None
            status = "EMPTY_OUTPUT"

            attempts.append({
                "attempt": attempt_no,
                "status": status,
                "patch": patch,
            })

            break

        if not is_python(patch):
            attempts.append({
                "attempt": attempt_no,
                "status": "SYNTAX_FAIL_BEFORE_VALIDATOR",
                "patch": patch,
            })

            prompt = initial + """

PREVIOUS ATTEMPT FAILED.

The previous response was not valid Python.

Return ONLY the complete Python source file.
Do not reason.
Do not use <think>.
Do not use Markdown.
"""

            continue

        validation = validate(
            vuln,
            source,
            patch,
        )

        vd = result_dict(validation)

        attempts.append({
            "attempt": attempt_no,
            "status": vd.get("status"),
            "security_ok": vd.get("security_ok"),
            "functional_ok": vd.get("functional_ok"),
            "ground_truth_available":
                vd.get("ground_truth_available"),
            "ground_truth_ok":
                vd.get("ground_truth_ok"),
            "semgrep_ok": vd.get("semgrep_ok"),
            "bandit_ok": vd.get("bandit_ok"),
            "tests_ok": vd.get("tests_ok"),
            "changed_lines": vd.get("changed_lines"),
            "changed_files": vd.get("changed_files"),
            "patch_hash": sha(patch),
            "patch": patch,
            "validation": vd,
        })

        security_ok = vd.get("security_ok", False)
        functional_ok = vd.get("functional_ok", False)

        if security_ok and functional_ok:
            break

        feedback = []

        if not vd.get("syntax_ok", True):
            feedback.append(
                "SYNTAX FAILURE: generated source is invalid Python."
            )

        if vd.get("ground_truth_available") and not vd.get("ground_truth_ok"):
            feedback.append(
                "SECURITY FAILURE: ground-truth security test failed."
            )

        if vd.get("semgrep_findings"):
            feedback.append(
                "Semgrep still reports findings:\n"
                + json.dumps(vd["semgrep_findings"], indent=2)
            )

        if vd.get("bandit_findings"):
            feedback.append(
                "Bandit still reports findings:\n"
                + json.dumps(vd["bandit_findings"], indent=2)
            )

        if not vd.get("functional_ok", False):
            feedback.append(
                "FUNCTIONAL FAILURE: required tests did not pass."
            )

        prompt = initial + """

VALIDATION FEEDBACK FROM PREVIOUS ATTEMPT:

""" + "\n".join(feedback) + """

REPAIR THE PREVIOUS PATCH.

Return ONLY the complete corrected Python source.
Do not output reasoning.
Do not output <think>.
Do not use Markdown.
"""

    final = attempts[-1] if attempts else {}

    artifact = {
        "timestamp": now(),
        "model": MODEL,
        "temperature": TEMPERATURE,
        "max_tokens": MAX_TOKENS,
        "benchmark": vuln.stem,
        "condition": level,
        "run": run_number,
        "finding": finding,
        "attempts": attempts,
    }

    RUNS.mkdir(parents=True, exist_ok=True)

    out = RUNS / f"{vuln.stem}_{level}_run{run_number}.json"

    out.write_text(
        json.dumps(
            artifact,
            indent=2,
            default=str,
        )
    )

    return artifact


# ============================================================
# Smoke test
# ============================================================

def smoke_test():
    print("\n" + "=" * 70)
    print("3. REAL LLM SMOKE TEST")
    print("=" * 70)

    vuln = VULNS / "cmdi_01.py"

    os.environ["GROQ_MAX_TOKENS"] = str(MAX_TOKENS)
    os.environ["GROQ_TEMPERATURE"] = str(TEMPERATURE)

    result = experiment_one(
        "C3",
        vuln,
        0,
    )

    attempts = result.get("attempts", [])

    if not attempts:
        raise RuntimeError("Smoke test produced no attempt.")

    first = attempts[0]

    patch = first.get("patch", "")

    if not patch or not is_python(patch):
        print("\nSMOKE TEST: FAILED")
        print("The LLM did not return valid Python.")
        print(
            "\nFull experiment will NOT run. "
            "No large API expenditure will occur."
        )
        return False

    print("\nSMOKE TEST: PASS")
    print("LLM returned valid Python.")

    return True


# ============================================================
# Full experiment
# ============================================================

def run_full():
    print("\n" + "=" * 70)
    print("4. FULL CONTROLLED EXPERIMENT")
    print("=" * 70)

    print("Model:", MODEL)
    print("Conditions:", CONDITIONS)
    print("Vulnerabilities:", len(VULNERABILITIES))
    print("Runs:", 3)
    print("Maximum attempts:", MAX_ATTEMPTS)

    all_results = []

    for level in CONDITIONS:
        for vuln in VULNERABILITIES:

            # Three repeated runs.
            for run_number in range(1, 4):

                result = experiment_one(
                    level,
                    vuln,
                    run_number,
                )

                all_results.append(result)

                # Avoid hammering the provider.
                time.sleep(3)

    output = RESULTS / "one_pass_results.json"

    output.write_text(
        json.dumps(
            all_results,
            indent=2,
            default=str,
        )
    )

    # --------------------------------------------------------
    # Aggregate CSV
    # --------------------------------------------------------

    rows = []

    for result in all_results:

        attempts = result.get("attempts", [])

        if not attempts:
            continue

        final = attempts[-1]

        rows.append({
            "benchmark": result.get("benchmark"),
            "condition": result.get("condition"),
            "run": result.get("run"),
            "status": final.get("status"),
            "security_ok": final.get("security_ok"),
            "functional_ok": final.get("functional_ok"),
            "ground_truth_ok": final.get("ground_truth_ok"),
            "semgrep_ok": final.get("semgrep_ok"),
            "bandit_ok": final.get("bandit_ok"),
            "tests_ok": final.get("tests_ok"),
            "changed_lines": final.get("changed_lines"),
            "changed_files": final.get("changed_files"),
            "attempts": len(attempts),
        })

    csv_file = RESULTS / "one_pass_results.csv"

    if rows:
        with csv_file.open("w", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=list(rows[0].keys()),
            )
            writer.writeheader()
            writer.writerows(rows)

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    summary = {}

    for condition in CONDITIONS:

        subset = [
            r for r in rows
            if r["condition"] == condition
        ]

        if not subset:
            continue

        n = len(subset)

        def rate(field):
            vals = [
                r[field]
                for r in subset
                if r[field] is not None
            ]

            if not vals:
                return 0.0

            return sum(bool(x) for x in vals) / len(vals)

        summary[condition] = {
            "n": n,
            "security_rate":
                rate("security_ok"),
            "functional_rate":
                rate("functional_ok"),
            "ground_truth_rate":
                rate("ground_truth_ok"),
            "semgrep_rate":
                rate("semgrep_ok"),
            "bandit_rate":
                rate("bandit_ok"),
            "test_rate":
                rate("tests_ok"),
            "average_attempts":
                sum(r["attempts"] for r in subset) / n,
        }

    summary_file = RESULTS / "one_pass_summary.json"

    summary_file.write_text(
        json.dumps(
            summary,
            indent=2,
        )
    )

    print("\n" + "=" * 70)
    print("EXPERIMENT COMPLETE")
    print("=" * 70)

    print(json.dumps(summary, indent=2))

    print("\nArtifacts:")
    print(output)
    print(csv_file)
    print(summary_file)
    print(RUNS)


# ============================================================
# Main
# ============================================================

def main():

    print("\n" + "#" * 70)
    print("# ONE-PASS RESEARCH PIPELINE")
    print("#" * 70)

    RESULTS.mkdir(parents=True, exist_ok=True)

    clean_benchmark_pollution()
    verify_ground_truth()

    smoke_ok = smoke_test()

    if not smoke_ok:
        print("\nSTOPPED SAFELY.")
        print(
            "Fix LLM output generation before running "
            "the expensive experiment."
        )
        return

    if RUN_FULL_AFTER_SMOKE:
        run_full()
    else:
        print("\nSmoke test passed.")
        print("Full experiment disabled by configuration.")


if __name__ == "__main__":
    main()
