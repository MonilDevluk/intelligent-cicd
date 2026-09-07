"""
Research-Grade Patch Validation Engine
======================================

Validation dimensions:

S = Security validity
F = Functional validity
R = Regression validity
M = Patch minimality

The validator intentionally treats scanner/test execution errors as
validation failures or unknown states, never as "clean".
"""

from __future__ import annotations

import ast
import difflib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class ValidationResult:
    status: str

    syntax_ok: bool
    security_ok: bool
    functional_ok: bool
    regression_ok: bool

    semgrep_ok: bool
    bandit_ok: bool
    tests_ok: bool

    ground_truth_available: bool
    ground_truth_ok: bool

    changed_lines: int
    changed_files: int

    semgrep_findings: int
    bandit_findings: int

    stdout: str
    stderr: str

    details: dict


def _run(
    command: list[str],
    cwd: str,
    timeout: int = 60,
) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr

    except subprocess.TimeoutExpired as exc:
        return (
            -1,
            exc.stdout or "",
            f"TIMEOUT after {timeout}s",
        )

    except Exception as exc:
        return (
            -2,
            "",
            f"EXECUTION ERROR: {exc}",
        )


def check_syntax(file_path: str) -> dict:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()

        ast.parse(source)

        return {
            "ok": True,
            "error": "",
        }

    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
        }


def run_semgrep(file_path: str) -> dict:
    command = [
        "semgrep",
        "--config",
        "p/python",
        "--config",
        "p/secrets",
        "--json",
        "--timeout",
        "30",
        file_path,
    ]

    code, stdout, stderr = _run(
        command,
        cwd=os.path.dirname(file_path),
        timeout=60,
    )

    if code != 0:
        return {
            "ok": False,
            "count": -1,
            "findings": [],
            "error": stderr or stdout or f"Semgrep exit code {code}",
        }

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        return {
            "ok": False,
            "count": -1,
            "findings": [],
            "error": f"Invalid Semgrep JSON: {exc}",
        }

    findings = data.get("results", [])

    return {
        "ok": len(findings) == 0,
        "count": len(findings),
        "findings": findings,
        "error": "",
    }


def run_bandit(file_path: str) -> dict:
    command = [
        "bandit",
        "-r",
        file_path,
        "-f",
        "json",
        "-q",
    ]

    code, stdout, stderr = _run(
        command,
        cwd=os.path.dirname(file_path),
        timeout=60,
    )

    # Bandit commonly returns non-zero when findings exist.
    # Therefore exit code alone does NOT mean execution failure.
    if not stdout.strip():
        return {
            "ok": False,
            "count": -1,
            "findings": [],
            "error": stderr or f"Bandit produced no JSON output (exit {code})",
        }

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        return {
            "ok": False,
            "count": -1,
            "findings": [],
            "error": f"Invalid Bandit JSON: {exc}",
        }

    findings = data.get("results", [])

    return {
        "ok": len(findings) == 0,
        "count": len(findings),
        "findings": findings,
        "error": "",
    }


def run_tests(
    repo_path: str,
    test_file: Optional[str] = None,
) -> dict:
    if test_file:
        command = [
            "python",
            "-m",
            "pytest",
            test_file,
            "--tb=short",
            "-q",
        ]
    else:
        command = [
            "python",
            "-m",
            "pytest",
            "--tb=short",
            "-q",
        ]

    code, stdout, stderr = _run(
        command,
        cwd=repo_path,
        timeout=120,
    )

    no_tests = (
        "no tests ran" in stdout.lower()
        or code == 5
    )

    return {
        "ok": code == 0 and not no_tests,
        "no_tests": no_tests,
        "exit_code": code,
        "stdout": stdout,
        "stderr": stderr,
    }


def calculate_patch_metrics(
    original_content: str,
    patched_content: str,
) -> dict:
    original_lines = original_content.splitlines()
    patched_lines = patched_content.splitlines()

    diff = list(
        difflib.unified_diff(
            original_lines,
            patched_lines,
            lineterm="",
        )
    )

    changed_lines = 0

    for line in diff:
        if line.startswith("+++") or line.startswith("---"):
            continue

        if line.startswith("+") or line.startswith("-"):
            changed_lines += 1

    changed_files = 0 if original_content == patched_content else 1

    return {
        "changed_lines": changed_lines,
        "changed_files": changed_files,
        "diff": "\n".join(diff),
    }


def run_ground_truth_security_test(
    repo_path: str,
    file_path: str,
    patched_content: str,
) -> dict:
    """
    Run the benchmark's independent ground-truth security test against
    the patched module in an isolated temporary repository structure.

    The repository layout is preserved because benchmark tests may use
    paths relative to their location.
    """
    repo_root = Path(repo_path).resolve()
    target_file = Path(file_path).resolve()

    benchmark_name = target_file.name
    benchmark_stem = target_file.stem

    test_path = (
        repo_root
        / "research"
        / "datasets"
        / "tests"
        / f"test_{benchmark_stem}_security.py"
    )

    result = {
        "available": False,
        "passed": False,
        "stdout": "",
        "stderr": "",
        "returncode": None,
        "test_path": str(test_path),
    }

    if not test_path.exists():
        result["error"] = f"Ground-truth test not found: {test_path}"
        return result

    result["available"] = True

    try:
        with tempfile.TemporaryDirectory(prefix="avr_ground_truth_") as tmp:
            sandbox_root = Path(tmp) / "repo"

            # Reproduce only the directory structure needed by the test.
            sandbox_target = (
                sandbox_root
                / "experiments"
                / "vulns"
                / benchmark_name
            )

            sandbox_test = (
                sandbox_root
                / "research"
                / "datasets"
                / "tests"
                / test_path.name
            )

            sandbox_target.parent.mkdir(parents=True, exist_ok=True)
            sandbox_test.parent.mkdir(parents=True, exist_ok=True)

            # Install patched benchmark.
            sandbox_target.write_text(patched_content)

            # Keep the ground-truth test byte-for-byte unchanged.
            shutil.copy2(test_path, sandbox_test)

            env = os.environ.copy()
            env["PYTHONPATH"] = str(sandbox_target.parent)

            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-q",
                    str(sandbox_test),
                ],
                cwd=str(sandbox_root),
                env=env,
                capture_output=True,
                text=True,
                timeout=120,
            )

            result["returncode"] = proc.returncode
            result["stdout"] = proc.stdout
            result["stderr"] = proc.stderr
            result["passed"] = proc.returncode == 0

    except subprocess.TimeoutExpired as exc:
        result["error"] = "Ground-truth security test timed out."
        result["stdout"] = exc.stdout or ""
        result["stderr"] = exc.stderr or ""

    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    return result

def validate_patch(
    repo_path: str,
    file_path: str,
    original_content: str,
    patched_content: str,
    generated_test: Optional[str] = None,
) -> ValidationResult:

    sandbox_dir = tempfile.mkdtemp(prefix="avr_validation_")

    try:
        shutil.copytree(
            repo_path,
            sandbox_dir,
            dirs_exist_ok=True,
        )

        relative_path = os.path.relpath(
            file_path,
            repo_path,
        )

        sandbox_file = os.path.join(
            sandbox_dir,
            relative_path,
        )

        os.makedirs(
            os.path.dirname(sandbox_file),
            exist_ok=True,
        )

        with open(
            sandbox_file,
            "w",
            encoding="utf-8",
        ) as f:
            f.write(patched_content)

        generated_test_path = None

        if generated_test:
            generated_test_path = os.path.join(
                sandbox_dir,
                "test_auto_generated.py",
            )

            with open(
                generated_test_path,
                "w",
                encoding="utf-8",
            ) as f:
                f.write(generated_test)

        syntax = check_syntax(sandbox_file)

        if not syntax["ok"]:
            metrics = calculate_patch_metrics(
                original_content,
                patched_content,
            )

            return ValidationResult(
                       ground_truth_available=False,
ground_truth_ok=False,
                status="SYNTAX_FAIL",
                syntax_ok=False,
                security_ok=False,
                functional_ok=False,
                regression_ok=False,
                semgrep_ok=False,
                bandit_ok=False,
                tests_ok=False,
                changed_lines=metrics["changed_lines"],
                changed_files=metrics["changed_files"],
                semgrep_findings=-1,
                bandit_findings=-1,
                stdout="",
                stderr=syntax["error"],
                details={
                    "syntax": syntax,
                    "metrics": metrics,
                },
            )

        semgrep = run_semgrep(sandbox_file)
        bandit = run_bandit(sandbox_file)

        tests = run_tests(
            sandbox_dir,
            generated_test_path,
        )

        benchmark_name = Path(file_path).stem

        ground_truth = run_ground_truth_security_test(
            sandbox_dir,
            sandbox_file,
            patched_content,
        )

        metrics = calculate_patch_metrics(
            original_content,
            patched_content,
        )

        semgrep_ok = semgrep["ok"]
        bandit_ok = bandit["ok"]

        scanner_security_ok = (
            semgrep_ok
            and bandit_ok
        )

        # Ground-truth benchmark tests are the primary security oracle.
        # Static-analysis results remain recorded as independent evidence.
        if ground_truth["available"]:
            security_ok = ground_truth["passed"]
        else:
            security_ok = scanner_security_ok

        functional_ok = tests["ok"]

        regression_ok = tests["ok"]

        if security_ok and functional_ok:
            status = "FULLY_VALIDATED"

        elif security_ok and not functional_ok:
            if tests["no_tests"]:
                status = "SECURITY_FIXED_UNVERIFIED"
            else:
                status = "SECURITY_FIXED_FUNCTIONAL_FAIL"

        elif not security_ok and functional_ok:
            status = "FUNCTIONAL_ONLY"

        else:
            status = "VALIDATION_FAILED"

        return ValidationResult(
            status=status,
            syntax_ok=True,
            security_ok=security_ok,
            functional_ok=functional_ok,
            regression_ok=regression_ok,
            semgrep_ok=semgrep_ok,
            bandit_ok=bandit_ok,
            tests_ok=tests["ok"],
            ground_truth_available=ground_truth["available"],
            ground_truth_ok=ground_truth["passed"],
            changed_lines=metrics["changed_lines"],
            changed_files=metrics["changed_files"],
            semgrep_findings=semgrep["count"],
            bandit_findings=bandit["count"],
            stdout=tests["stdout"],
            stderr=tests["stderr"],
            details={
                "syntax": syntax,
                "semgrep": semgrep,
                "bandit": bandit,
                "tests": tests,
                "ground_truth": ground_truth,
                "metrics": metrics,
            },
        )

    finally:
        shutil.rmtree(
            sandbox_dir,
            ignore_errors=True,
        )


def result_to_dict(result: ValidationResult) -> dict:
    return asdict(result)
