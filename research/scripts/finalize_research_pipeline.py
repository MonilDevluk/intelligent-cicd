from pathlib import Path
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import hashlib
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
RESULTS = ROOT / "research" / "results"
LOGS = ROOT / "research" / "logs"

sys.path.insert(0, str(BACKEND))

from dotenv import load_dotenv
load_dotenv(BACKEND / ".env")


# ============================================================
# Helpers
# ============================================================

def run(cmd, cwd=ROOT, timeout=120):
    print("\n$", " ".join(map(str, cmd)))
    p = subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    if p.stdout:
        print(p.stdout[-5000:])
    if p.returncode != 0 and p.stderr:
        print(p.stderr[-5000:])
    return p


def clean_llm_output(text):
    if not text:
        return ""

    text = text.strip()

    # Remove reasoning blocks.
    text = re.sub(
        r"<think>.*?</think>",
        "",
        text,
        flags=re.DOTALL | re.IGNORECASE,
    )

    # Remove markdown fences.
    text = re.sub(r"^```(?:python|py)?\s*", "", text, flags=re.I)
    text = re.sub(r"\s*```$", "", text)

    text = text.strip()

    # If the model still returned explanatory text before the code,
    # prefer the first Python-looking import/statement.
    lines = text.splitlines()

    starts = (
        "import ",
        "from ",
        "def ",
        "class ",
        "#",
    )

    for i, line in enumerate(lines):
        if line.strip().startswith(starts):
            text = "\n".join(lines[i:])
            break

    return text.strip()


def valid_python(source):
    try:
        ast.parse(source)
        return True
    except SyntaxError:
        return False


def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()


# ============================================================
# Patch output contract
# ============================================================

def patch_output_contract():
    return """
OUTPUT CONTRACT — STRICT

Return ONLY the complete corrected Python source file.

DO NOT:
- output <think>
- output reasoning
- explain the solution
- use markdown
- use ```python
- describe the patch
- truncate the file

The response must begin directly with valid Python code and contain
the COMPLETE replacement source file.
"""


# ============================================================
# Self checks
# ============================================================

def self_check():
    print("\n" + "=" * 70)
    print("PHASE 1 — STATIC SELF CHECK")
    print("=" * 70)

    files = [
        BACKEND / "context_builder.py",
        BACKEND / "validator.py",
        BACKEND / "refinement.py",
        BACKEND / "patcher.py",
        ROOT / "research" / "scripts" / "run_ablation.py",
    ]

    for f in files:
        if not f.exists():
            raise RuntimeError(f"Missing required file: {f}")

        try:
            ast.parse(f.read_text())
        except SyntaxError as e:
            raise RuntimeError(f"Syntax error in {f}: {e}")

        print("OK:", f.relative_to(ROOT))

    # Import test.
    import context_builder
    import validator
    import refinement
    import patcher

    print("OK: research modules import successfully")

    # Validator constructor consistency.
    from validator import ValidationResult

    fields = ValidationResult.__dataclass_fields__

    required = [
        "ground_truth_available",
        "ground_truth_ok",
    ]

    for name in required:
        if name not in fields:
            raise RuntimeError(
                f"ValidationResult missing field: {name}"
            )

    print("OK: ValidationResult ground-truth fields exist")

    # Refinement interface.
    from refinement import refine_patch

    print("OK: refinement engine imported")

    return True


# ============================================================
# Ground truth
# ============================================================

def ground_truth_check():
    print("\n" + "=" * 70)
    print("PHASE 2 — SECURITY GROUND TRUTH")
    print("=" * 70)

    test = ROOT / "research" / "datasets" / "tests" / "test_cmdi_01_security.py"

    if not test.exists():
        raise RuntimeError(f"Missing ground-truth test: {test}")

    p = run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            str(test),
        ],
        timeout=120,
    )

    if p.returncode != 0:
        raise RuntimeError(
            "Ground-truth security tests failed."
        )

    print("GROUND TRUTH: PASS")
    return True


# ============================================================
# LLM smoke test
# ============================================================

def llm_smoke_test():
    print("\n" + "=" * 70)
    print("PHASE 3 — REAL LLM SMOKE TEST")
    print("=" * 70)

    from patcher import generate_refined_patch

    vuln = ROOT / "experiments" / "vulns" / "cmdi_01.py"

    if not vuln.exists():
        raise RuntimeError(f"Missing benchmark: {vuln}")

    source = vuln.read_text()

    finding = {
        "rule_id":
            "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
        "severity": "ERROR",
        "message":
            "subprocess.check_output uses shell=True with "
            "attacker-controlled input.",
        "line": 8,
        "end_line": 8,
        "snippet":
            'output = subprocess.check_output("ls " + directory, shell=True)',
        "file": str(vuln),
    }

    context = {
        "level": "C3",
        "vulnerability": "CWE-78 Command Injection",
        "attack_mechanism":
            "Untrusted input is interpreted by an operating-system shell.",
        "repair_guidance":
            "Use subprocess argument lists and shell=False.",
        "constraints": [
            "Preserve intended functionality.",
            "Do not suppress the vulnerability.",
            "Return complete Python source.",
        ],
    }

    # Keep smoke test inexpensive.
    os.environ["GROQ_MAX_TOKENS"] = "450"
    os.environ["GROQ_TEMPERATURE"] = "0.0"

    prompt = patch_output_contract() + """

Fix the identified CWE-78 command injection vulnerability.

Return the COMPLETE corrected Python source.
"""

    patch = generate_refined_patch(
        finding=finding,
        file_content=source,
        context=context,
        validation_feedback=prompt,
    )

    patch = clean_llm_output(patch)

    print("\nGenerated output:")
    print("-" * 60)
    print(patch)
    print("-" * 60)

    if not patch:
        raise RuntimeError("LLM returned empty output.")

    if not valid_python(patch):
        raise RuntimeError(
            "LLM smoke test failed: output is not valid Python."
        )

    print("LLM OUTPUT: VALID PYTHON")

    # Save smoke artifact.
    RESULTS.mkdir(parents=True, exist_ok=True)

    smoke = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model": os.getenv("GROQ_MODEL"),
        "max_tokens": 450,
        "temperature": 0.0,
        "benchmark": "cmdi_01",
        "valid_python": True,
        "patch_hash": hash_text(patch),
        "patch": patch,
    }

    (RESULTS / "smoke_test.json").write_text(
        json.dumps(smoke, indent=2)
    )

    return patch


# ============================================================
# Refinement smoke test
# ============================================================

def refinement_smoke_test():
    print("\n" + "=" * 70)
    print("PHASE 4 — REFINEMENT ENGINE SMOKE TEST")
    print("=" * 70)

    from refinement import refine_patch

    attempts = {"count": 0}

    def generate(prompt):
        attempts["count"] += 1

        # Deterministic local simulation.
        if attempts["count"] == 1:
            return "this is invalid python"

        return """
import subprocess

def ping_host(hostname):
    return subprocess.run(
        ["ping", "-c", "1", hostname],
        check=False
    )

def list_files(directory):
    return subprocess.check_output(
        ["ls", directory],
        shell=False
    ).decode()

def get_file_info(filename):
    return subprocess.run(
        ["file", filename],
        capture_output=True,
        text=True,
        check=False
    ).stdout
"""

    class V:
        syntax_ok = False
        security_ok = False
        functional_ok = False
        ground_truth_available = True
        ground_truth_ok = False
        semgrep_findings = ["shell=True"]
        bandit_findings = []
        changed_lines = 10
        changed_files = 1

    class V2:
        syntax_ok = True
        security_ok = True
        functional_ok = True
        ground_truth_available = True
        ground_truth_ok = True
        semgrep_findings = []
        bandit_findings = []
        changed_lines = 8
        changed_files = 1

    def validate(patch):
        if attempts["count"] == 1:
            return V()
        return V2()

    result = refine_patch(
        generate_fn=generate,
        validate_fn=validate,
        initial_prompt=patch_output_contract(),
        max_attempts=2,
    )

    if not result.success:
        raise RuntimeError(
            "Refinement engine smoke test failed."
        )

    if len(result.attempts) != 2:
        raise RuntimeError(
            "Expected exactly two refinement attempts."
        )

    print("REFINEMENT ENGINE: PASS")
    print("Attempt 1:", result.attempts[0].status)
    print("Attempt 2:", result.attempts[1].status)

    return True


# ============================================================
# Final readiness
# ============================================================

def main():
    print("\n" + "#" * 70)
    print("# RESEARCH PIPELINE FINALIZATION")
    print("#" * 70)

    self_check()
    ground_truth_check()
    refinement_smoke_test()

    # Real API call is deliberately LAST.
    patch = llm_smoke_test()

    print("\n" + "#" * 70)
    print("# PIPELINE STATUS")
    print("#" * 70)

    print("""
STATIC CODE CHECK       : PASS
GROUND TRUTH            : PASS
REFINEMENT ENGINE       : PASS
REAL LLM OUTPUT         : PASS
""")

    print("The pipeline is ready for the full ablation experiment.")
    print("\nSmoke-test artifact:")
    print(RESULTS / "smoke_test.json")

    print("\nIMPORTANT:")
    print("Full C0-C3 experiments have NOT been launched automatically.")
    print("We first need to verify the smoke-test output above.")


if __name__ == "__main__":
    main()
