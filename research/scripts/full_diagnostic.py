from pathlib import Path
import ast
import importlib
import inspect
import json
import os
import subprocess
import sys
import tempfile
import traceback
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
VULNS = ROOT / "experiments" / "vulns"
GT = ROOT / "research" / "datasets" / "tests"
REPORT_DIR = ROOT / "research" / "results"
REPORT = REPORT_DIR / "full_diagnostic_report.json"

sys.path.insert(0, str(BACKEND))

results = []


def check(name, fn):
    print("\n" + "=" * 72)
    print(name)
    print("=" * 72)

    try:
        value = fn()
        results.append({
            "name": name,
            "status": "PASS",
            "detail": str(value) if value is not None else ""
        })
        print("PASS")
        if value:
            print(value)
        return value

    except Exception as e:
        detail = traceback.format_exc()
        results.append({
            "name": name,
            "status": "FAIL",
            "detail": detail
        })
        print("FAIL")
        print(detail)
        return None


def command(cmd, timeout=120, cwd=ROOT):
    p = subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=timeout,
    )

    output = (p.stdout or "") + (p.stderr or "")

    if p.returncode != 0:
        raise RuntimeError(
            f"Exit code {p.returncode}\n{output[-8000:]}"
        )

    return output[-8000:]


# ------------------------------------------------------------
# 1. Repository / files
# ------------------------------------------------------------

def repository_check():
    required = [
        BACKEND / "context_builder.py",
        BACKEND / "validator.py",
        BACKEND / "refinement.py",
        BACKEND / "patcher.py",
        BACKEND / "scanner.py",
        ROOT / "research" / "config.yaml",
        ROOT / "research" / "scripts" / "run_ablation.py",
        VULNS / "cmdi_01.py",
        GT / "test_cmdi_01_security.py",
    ]

    missing = [str(x) for x in required if not x.exists()]

    if missing:
        raise RuntimeError(
            "Missing files:\n" + "\n".join(missing)
        )

    # Detect accidental root benchmark pollution.
    polluted = list(ROOT.glob("cmdi_*.py"))

    return {
        "required_files": len(required),
        "root_benchmark_pollution": [str(x) for x in polluted],
    }


check("1. REPOSITORY / FILE STRUCTURE", repository_check)


# ------------------------------------------------------------
# 2. Python syntax
# ------------------------------------------------------------

def syntax_check():
    targets = [
        BACKEND / "context_builder.py",
        BACKEND / "validator.py",
        BACKEND / "refinement.py",
        BACKEND / "patcher.py",
        BACKEND / "scanner.py",
        ROOT / "research" / "scripts" / "run_ablation.py",
        ROOT / "research" / "scripts" / "run_refinement_pilot.py",
        ROOT / "research" / "scripts" / "one_pass_research.py",
    ]

    errors = []

    for f in targets:
        if not f.exists():
            continue

        try:
            ast.parse(f.read_text())
        except SyntaxError as e:
            errors.append(f"{f}: {e}")

    if errors:
        raise RuntimeError("\n".join(errors))

    return f"{len(targets)} Python files parsed successfully."


check("2. PYTHON SYNTAX", syntax_check)


# ------------------------------------------------------------
# 3. Module imports
# ------------------------------------------------------------

def import_check():
    modules = [
        "context_builder",
        "validator",
        "refinement",
        "patcher",
        "scanner",
    ]

    imported = []

    for module in modules:
        importlib.import_module(module)
        imported.append(module)

    return imported


check("3. BACKEND IMPORTS", import_check)


# ------------------------------------------------------------
# 4. API signatures
# ------------------------------------------------------------

def signature_check():
    from context_builder import build_context
    from validator import validate_patch
    from refinement import refine_patch
    from patcher import generate_refined_patch

    return {
        "build_context": str(inspect.signature(build_context)),
        "validate_patch": str(inspect.signature(validate_patch)),
        "refine_patch": str(inspect.signature(refine_patch)),
        "generate_refined_patch":
            str(inspect.signature(generate_refined_patch)),
    }


check("4. ACTUAL FUNCTION SIGNATURES", signature_check)


# ------------------------------------------------------------
# 5. ValidationResult
# ------------------------------------------------------------

def validation_model_check():
    from validator import ValidationResult

    fields = list(ValidationResult.__dataclass_fields__)

    required = [
        "status",
        "syntax_ok",
        "security_ok",
        "functional_ok",
        "regression_ok",
        "semgrep_ok",
        "bandit_ok",
        "tests_ok",
        "ground_truth_available",
        "ground_truth_ok",
        "changed_lines",
        "changed_files",
    ]

    missing = [x for x in required if x not in fields]

    if missing:
        raise RuntimeError(
            "Missing ValidationResult fields: "
            + ", ".join(missing)
        )

    return fields


check("5. VALIDATION RESULT MODEL", validation_model_check)


# ------------------------------------------------------------
# 6. Ground truth
# ------------------------------------------------------------

def ground_truth_check():
    from validator import run_ground_truth_security_test

    vuln = VULNS / "cmdi_01.py"
    source = vuln.read_text()

    # Original vulnerable fixture must FAIL.
    vulnerable = run_ground_truth_security_test(
        repo_path=str(ROOT),
        file_path=str(vuln),
        patched_content=source,
    )

    if not vulnerable["available"]:
        raise RuntimeError("Ground-truth test unavailable.")

    if vulnerable["passed"]:
        raise RuntimeError(
            "Vulnerable fixture unexpectedly passed."
        )

    # Known-good implementation must PASS.
    known_good = """import os
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
""".strip()

    fixed = run_ground_truth_security_test(
        repo_path=str(ROOT),
        file_path=str(vuln),
        patched_content=known_good,
    )

    if not fixed["available"]:
        raise RuntimeError(
            "Ground-truth test unavailable for known-good patch."
        )

    if not fixed["passed"]:
        raise RuntimeError(
            "Known-good patch failed ground-truth tests.\n"
            + fixed["stdout"]
            + "\n"
            + fixed["stderr"]
        )

    return {
        "vulnerable_fixture_passed": vulnerable["passed"],
        "known_good_passed": fixed["passed"],
        "original_returncode": vulnerable["returncode"],
        "known_good_returncode": fixed["returncode"],
    }

check("6. CMDI-01 GROUND TRUTH", ground_truth_check)


# ------------------------------------------------------------
# 7. Semgrep detection
# ------------------------------------------------------------

def semgrep_check():
    output = command([
        "semgrep",
        "scan",
        "--config", "p/python",
        "--config", "p/secrets",
        "--json",
        "--quiet",
        str(VULNS / "cmdi_01.py"),
    ])

    data = json.loads(output)

    if not data.get("results"):
        raise RuntimeError("Semgrep detected zero findings.")

    return {
        "count": len(data["results"]),
        "first_rule":
            data["results"][0].get("check_id"),
        "first_line":
            data["results"][0].get("start", {}).get("line"),
    }


check("7. SEMGREP DETECTION", semgrep_check)


# ------------------------------------------------------------
# 8. Bandit
# ------------------------------------------------------------

def bandit_check():
    p = subprocess.run(
        [
            "bandit",
            "-q",
            "-f",
            "json",
            str(VULNS / "cmdi_01.py"),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )

    # Bandit returns non-zero when findings exist.
    if not p.stdout:
        raise RuntimeError(
            "Bandit produced no JSON output.\n"
            + p.stderr
        )

    data = json.loads(p.stdout)

    return {
        "high": len(data.get("results", [])),
        "metrics_present":
            bool(data.get("metrics")),
    }


check("8. BANDIT", bandit_check)


# ------------------------------------------------------------
# 9. Context levels
# ------------------------------------------------------------

def context_check():
    from context_builder import build_context

    finding = {
        "rule_id":
            "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
        "severity": "ERROR",
        "message":
            "subprocess.check_output uses shell=True",
        "line": 8,
        "end_line": 8,
        "snippet":
            'output = subprocess.check_output("ls " + directory, shell=True)',
        "file": str(VULNS / "cmdi_01.py"),
    }

    source = (VULNS / "cmdi_01.py").read_text()

    output = {}

    for level in ["C0", "C1", "C2", "C3"]:
        try:
            ctx = build_context(
                finding=finding,
                file_content=source,
                level=level,
                security_context={
                    "cwe": "CWE-78",
                    "attack_mechanism":
                        "Untrusted input reaches an OS command.",
                    "repair_guidance":
                        "Use subprocess argument lists with shell=False.",
                },
            )
        except TypeError:
            ctx = build_context(
                finding,
                source,
                level,
            )

        output[level] = {
            "type": type(ctx).__name__,
            "length": len(str(ctx)),
            "preview": str(ctx)[:500],
        }

    return output


check("9. C0-C3 CONTEXT BUILDER", context_check)


# ------------------------------------------------------------
# 10. Validator on original vulnerable code
# ------------------------------------------------------------

def validator_original_check():
    from validator import validate_patch

    vuln = VULNS / "cmdi_01.py"
    source = vuln.read_text()

    result = validate_patch(
        repo_path=str(ROOT),
        file_path=str(vuln),
        original_content=source,
        patched_content=source,
        generated_test=None,
    )

    data = {
        "status": result.status,
        "syntax_ok": result.syntax_ok,
        "security_ok": result.security_ok,
        "functional_ok": result.functional_ok,
        "ground_truth_available":
            result.ground_truth_available,
        "ground_truth_ok":
            result.ground_truth_ok,
        "semgrep_ok": result.semgrep_ok,
        "bandit_ok": result.bandit_ok,
    }

    # Original vulnerable fixture MUST NOT pass security.
    if result.security_ok:
        raise RuntimeError(
            "Validator incorrectly considers original code secure."
        )

    return data


check("10. VALIDATOR — ORIGINAL VULNERABLE CODE",
      validator_original_check)


# ------------------------------------------------------------
# 11. Known-good patch validation
# ------------------------------------------------------------

def known_good_check():
    from validator import validate_patch

    vuln = VULNS / "cmdi_01.py"
    source = vuln.read_text()

    known_good = '''
import os
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
'''.strip()

    result = validate_patch(
        repo_path=str(ROOT),
        file_path=str(vuln),
        original_content=source,
        patched_content=known_good,
        generated_test=None,
    )

    data = {
        "status": result.status,
        "syntax_ok": result.syntax_ok,
        "security_ok": result.security_ok,
        "functional_ok": result.functional_ok,
        "ground_truth_available":
            result.ground_truth_available,
        "ground_truth_ok":
            result.ground_truth_ok,
        "semgrep_ok": result.semgrep_ok,
        "bandit_ok": result.bandit_ok,
    }

    if not result.ground_truth_ok:
        raise RuntimeError(
            "Known-good patch failed ground-truth security."
        )

    return data


check("11. VALIDATOR — KNOWN GOOD PATCH",
      known_good_check)


# ------------------------------------------------------------
# 12. Refinement unit test
# ------------------------------------------------------------

def refinement_check():
    from refinement import refine_patch
    from validator import ValidationResult

    state = {"n": 0}

    def make_validation(ok):
        if ok:
            return ValidationResult(
                status="VALIDATED",
                syntax_ok=True,
                security_ok=True,
                functional_ok=True,
                regression_ok=True,
                semgrep_ok=True,
                bandit_ok=True,
                tests_ok=True,
                ground_truth_available=True,
                ground_truth_ok=True,
                changed_lines=3,
                changed_files=1,
                semgrep_findings=[],
                bandit_findings=[],
                stdout="",
                stderr="",
                details="",
            )

        return ValidationResult(
            status="VALIDATION_FAILED",
            syntax_ok=False,
            security_ok=False,
            functional_ok=False,
            regression_ok=False,
            semgrep_ok=False,
            bandit_ok=False,
            tests_ok=False,
            ground_truth_available=True,
            ground_truth_ok=False,
            changed_lines=5,
            changed_files=1,
            semgrep_findings=["finding"],
            bandit_findings=[],
            stdout="",
            stderr="",
            details="",
        )

    def generate(prompt):
        state["n"] += 1

        return (
            "bad patch"
            if state["n"] == 1
            else "print('secure')"
        )

    def validate(patch):
        return make_validation(state["n"] >= 2)

    result = refine_patch(
        generate_fn=generate,
        validate_fn=validate,
        initial_prompt="fix vulnerability",
        max_attempts=2,
    )

    if not result.success:
        raise RuntimeError(
            "Refinement engine did not recover."
        )

    if len(result.attempts) != 2:
        raise RuntimeError(
            f"Expected 2 refinement attempts, got {len(result.attempts)}."
        )

    return {
        "success": result.success,
        "attempts": len(result.attempts),
        "final_patch": result.final_patch,
    }


check("12. REFINEMENT ENGINE", refinement_check)


# ------------------------------------------------------------
# 13. Experiment configuration
# ------------------------------------------------------------

def config_check():
    import yaml

    cfg = yaml.safe_load(
        (ROOT / "research" / "config.yaml").read_text()
    )

    exp = cfg.get("experiment", {})
    model = cfg.get("model", {})

    return {
        "conditions": exp.get("conditions"),
        "runs_per_condition":
            exp.get("runs_per_condition"),
        "model": model.get("name"),
        "max_tokens":
            model.get("max_tokens"),
        "max_attempts":
            cfg.get("patch", {}).get("max_attempts"),
    }


check("13. RESEARCH CONFIGURATION", config_check)


# ------------------------------------------------------------
# 14. Existing ablation runner imports
# ------------------------------------------------------------

def ablation_check():
    path = ROOT / "research" / "scripts" / "run_ablation.py"

    ast.parse(path.read_text())

    # Import using importlib without executing CLI main.
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "run_ablation_diagnostic",
        path,
    )

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return {
        "imported": True,
        "functions": [
            x for x in dir(module)
            if callable(getattr(module, x))
            and not x.startswith("_")
        ],
    }


check("14. ABLATION RUNNER", ablation_check)


# ------------------------------------------------------------
# 15. Check research dataset
# ------------------------------------------------------------

def dataset_check():
    files = sorted(VULNS.glob("cmdi_*.py"))

    if not files:
        raise RuntimeError("No CMDi benchmark files found.")

    invalid = []

    for f in files:
        try:
            ast.parse(f.read_text())
        except SyntaxError as e:
            invalid.append(f"{f}: {e}")

    if invalid:
        raise RuntimeError("\n".join(invalid))

    return {
        "cmdi_benchmarks": len(files),
        "files": [x.name for x in files],
    }


check("15. CMDI DATASET", dataset_check)


# ------------------------------------------------------------
# 16. Git state
# ------------------------------------------------------------

def git_check():
    p = subprocess.run(
        ["git", "status", "--short", "--branch"],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )

    return p.stdout


check("16. GIT STATE", git_check)


# ------------------------------------------------------------
# Final report
# ------------------------------------------------------------

def main():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    passed = sum(
        x["status"] == "PASS"
        for x in results
    )

    failed = sum(
        x["status"] == "FAIL"
        for x in results
    )

    report = {
        "timestamp":
            datetime.now(timezone.utc).isoformat(),
        "passed": passed,
        "failed": failed,
        "total": len(results),
        "results": results,
    }

    REPORT.write_text(
        json.dumps(
            report,
            indent=2,
            default=str,
        )
    )

    print("\n\n" + "#" * 72)
    print("# FINAL DIAGNOSTIC SUMMARY")
    print("#" * 72)

    for r in results:
        symbol = "PASS" if r["status"] == "PASS" else "FAIL"
        print(f"[{symbol}] {r['name']}")

    print("\nTOTAL :", len(results))
    print("PASS  :", passed)
    print("FAIL  :", failed)

    print("\nReport:")
    print(REPORT)

    if failed:
        print(
            "\nDIAGNOSTIC COMPLETE — failures collected."
        )
        print(
            "DO NOT run the full LLM experiment yet."
        )
    else:
        print(
            "\nALL DIAGNOSTICS PASSED."
        )
        print(
            "The system is ready for the experimental pass."
        )


if __name__ == "__main__":
    main()
