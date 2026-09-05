import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
VULN = ROOT / "experiments" / "vulns" / "cmdi_01.py"
RESULT_DIR = ROOT / "research" / "results"

sys.path.insert(0, str(BACKEND))

from dotenv import load_dotenv
load_dotenv(BACKEND / ".env")

from context_builder import build_context
from patcher import generate_refined_patch
from validator import validate_patch
from refinement import refine_patch


def run_semgrep():
    cmd = [
        "semgrep", "scan",
        "--config", "p/python",
        "--config", "p/secrets",
        "--json",
        "--quiet",
        str(VULN),
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=60,
    )

    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"Semgrep failed:\n{result.stderr}"
        )

    data = json.loads(result.stdout)

    if not data.get("results"):
        raise RuntimeError("Semgrep returned zero findings.")

    r = data["results"][0]

    return {
        "rule_id": r.get("check_id", ""),
        "severity": r.get("extra", {}).get("severity", ""),
        "message": r.get("extra", {}).get("message", ""),
        "line": r.get("start", {}).get("line"),
        "end_line": r.get("end", {}).get("line"),
        "snippet": r.get("extra", {}).get("lines", ""),
        "file": str(VULN),
    }


def validation_to_dict(result):
    if hasattr(result, "__dataclass_fields__"):
        from dataclasses import asdict
        return asdict(result)

    if isinstance(result, dict):
        return result

    return {
        k: getattr(result, k)
        for k in dir(result)
        if not k.startswith("_")
        and not callable(getattr(result, k))
    }


def main():
    print("=" * 70)
    print("REAL LLM REFINEMENT PILOT")
    print("=" * 70)

    # IMPORTANT:
    # Two 450-token patch generations stay within the
    # approximately 1000 output-token/minute budget.
    os.environ["GROQ_MAX_TOKENS"] = "450"
    os.environ["GROQ_TEMPERATURE"] = "0.0"

    source = VULN.read_text()

    # ------------------------------------------------------------
    # 1. Detect vulnerability
    # ------------------------------------------------------------
    print("\n[1] Running Semgrep...")

    finding = run_semgrep()

    print(json.dumps(finding, indent=2))

    # ------------------------------------------------------------
    # 2. Build C3 context
    # ------------------------------------------------------------
    print("\n[2] Building C3 context...")

    security_context = {
        "cwe": "CWE-78",
        "attack_mechanism":
            "Untrusted user input reaches an OS command.",
        "repair_guidance":
            "Avoid shell interpretation. Prefer subprocess "
            "argument lists with shell=False.",
        "constraints": [
            "Preserve existing function behavior.",
            "Do not disable security checks.",
            "Do not merely suppress the Semgrep warning.",
        ],
    }

    try:
        context = build_context(
            finding=finding,
            file_content=source,
            level="C3",
            security_context=security_context,
        )
    except TypeError:
        context = build_context(
            finding,
            source,
            "C3",
        )

    print("C3 context successfully built.")

    # ------------------------------------------------------------
    # 3. Validation adapter
    # ------------------------------------------------------------
    def validate(patch):
        """
        Adapter for the actual validator signature:

        validate_patch(
            repo_path,
            file_path,
            original_content,
            patched_content,
            generated_test=None
        )
        """
        import tempfile

        with tempfile.TemporaryDirectory(prefix="avr_pilot_") as tmp:
            tmp = Path(tmp)

            # Validator expects a repository/workspace path and a
            # relative file path. Keep original and patched content
            # separate; do NOT overwrite the original fixture.
            repo_path = tmp
            file_path = VULN.name

            result = validate_patch(
                repo_path=str(repo_path),
                file_path=file_path,
                original_content=source,
                patched_content=patch,
                generated_test=None,
            )

            # refinement.py expects the actual ValidationResult
            # object because it accesses attributes such as
            # validation.syntax_ok and validation.security_ok.
            return result

    # ------------------------------------------------------------
    # 4. Generator
    # ------------------------------------------------------------
    def generate(prompt):
        return generate_refined_patch(
            finding=finding,
            file_content=source,
            context=context,
            validation_feedback=prompt,
        )

    # ------------------------------------------------------------
    # 5. Validation-guided refinement
    # ------------------------------------------------------------
    print("\n[3] Starting validation-guided refinement...")
    print("Maximum attempts: 2")
    print("Maximum output tokens per call: 450")

    initial_prompt = """
Generate a secure complete replacement for the vulnerable
Python source file.

Vulnerability: CWE-78 command injection.

Requirements:
- Preserve intended functionality.
- Remove command injection.
- Do not suppress or ignore the vulnerability.
- Prefer subprocess argument lists with shell=False.
- Return ONLY the complete corrected Python source.
"""

    result = refine_patch(
        generate_fn=generate,
        validate_fn=validate,
        initial_prompt=initial_prompt,
        max_attempts=2,
    )

    # ------------------------------------------------------------
    # 6. Report
    # ------------------------------------------------------------
    print("\n" + "=" * 70)
    print("REFINEMENT RESULT")
    print("=" * 70)

    print(f"Success:  {result.success}")
    print(f"Attempts: {len(result.attempts)}")

    for attempt in result.attempts:
        print("\n" + "-" * 60)
        print(f"ATTEMPT {attempt.attempt}")
        print("-" * 60)

        print(f"Status:          {attempt.status}")
        print(f"Security OK:     {attempt.security_ok}")
        print(f"Functional OK:   {attempt.functional_ok}")
        print(f"Ground Truth OK: {attempt.ground_truth_ok}")

        print("\nFeedback:")
        print(attempt.feedback)

        print("\nPatch:")
        print(attempt.patch)

    if result.final_patch:
        print("\n" + "=" * 70)
        print("FINAL PATCH")
        print("=" * 70)
        print(result.final_patch)

    # ------------------------------------------------------------
    # 7. Save reproducible artifact
    # ------------------------------------------------------------
    RESULT_DIR.mkdir(parents=True, exist_ok=True)

    output = {
        "benchmark": "cmdi_01",
        "condition": "C3",
        "model": os.getenv("GROQ_MODEL"),
        "max_tokens": 450,
        "temperature": 0.0,
        "max_attempts": 2,
        "success": result.success,
        "attempts": [
            {
                "attempt": a.attempt,
                "status": a.status,
                "security_ok": a.security_ok,
                "functional_ok": a.functional_ok,
                "ground_truth_ok": a.ground_truth_ok,
                "feedback": a.feedback,
                "patch": a.patch,
            }
            for a in result.attempts
        ],
        "final_patch": result.final_patch,
    }

    output_file = RESULT_DIR / "refinement_pilot_cmdi_01_C3.json"

    output_file.write_text(
        json.dumps(output, indent=2)
    )

    print("\nSaved:")
    print(output_file)


if __name__ == "__main__":
    main()
