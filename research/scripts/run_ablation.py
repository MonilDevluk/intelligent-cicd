"""
Research Ablation Runner
========================

Context conditions:
    C0 = Minimal
    C1 = SAST
    C2 = Structural
    C3 = Security-grounded

Every LLM interaction is recorded so experiments are reproducible.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
CONFIG_FILE = ROOT / "research" / "config.yaml"
RESULT_DIR = ROOT / "research" / "results"
ARTIFACT_DIR = ROOT / "research" / "logs"
VULN_DIR = ROOT / "experiments" / "vulns"

sys.path.insert(0, str(BACKEND))

from dotenv import load_dotenv
import yaml

load_dotenv(BACKEND / ".env")

from context_builder import build_context, context_metadata
from patcher import call_groq, generate_test
from scanner import run_scan
from validator import validate_patch, result_to_dict


CSV_FIELDS = [
    "experiment_id",
    "vulnerability",
    "condition",
    "run",
    "timestamp_utc",
    "model",
    "temperature",
    "max_tokens",
    "detected",
    "patch_generation_ok",
    "test_generation_ok",
    "syntax_ok",
    "security_ok",
    "functional_ok",
    "regression_ok",
    "semgrep_ok",
    "bandit_ok",
    "tests_ok",
    "status",
    "changed_lines",
    "changed_files",
    "semgrep_findings",
    "bandit_findings",
    "context_characters",
    "context_lines",
    "generation_seconds",
    "test_generation_seconds",
    "total_seconds",
    "prompt_sha256",
    "patch_sha256",
    "error",
]


def load_config() -> dict:
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


CONFIG = load_config()

MODEL_CONFIG = CONFIG["model"]

MODEL = MODEL_CONFIG["name"]
TEMPERATURE = float(MODEL_CONFIG["temperature"])
MAX_TOKENS = int(MODEL_CONFIG["max_tokens"])


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_text(text: str) -> str:
    return hashlib.sha256(
        text.encode("utf-8")
    ).hexdigest()


def save_artifact(
    experiment_id: str,
    name: str,
    content: str,
) -> None:

    if not CONFIG["output"].get(
        "save_raw_artifacts",
        True,
    ):
        return

    directory = ARTIFACT_DIR / experiment_id
    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    path = directory / name

    path.write_text(
        content,
        encoding="utf-8",
    )


def make_prompt(
    finding: dict,
    context: str,
) -> str:

    return f"""You are a security engineer performing autonomous vulnerability remediation.

Use the supplied vulnerability context to repair the vulnerability.

{context}

Requirements:

1. Fix ONLY the reported security vulnerability.
2. Preserve existing functionality.
3. Do not rewrite unrelated code.
4. Do not introduce unnecessary dependencies.
5. Prefer the smallest correct security fix.
6. Return ONLY the complete fixed file content.
7. Do not use markdown fences.
8. Do not provide explanations.
"""


def generate_patch_with_context(
    finding: dict,
    context: str,
) -> str:

    api_key = os.getenv("GROQ_API_KEY")

    if not api_key:
        raise ValueError(
            "GROQ_API_KEY is not set"
        )

    prompt = make_prompt(
        finding,
        context,
    )

    return call_groq(
        prompt,
        api_key,
    )


def load_security_context(
    vuln_path: Path,
    finding: dict,
) -> dict:
    """
    Load controlled security metadata for C3.

    Metadata is selected using:
        1. explicit benchmark filename prefix
        2. Semgrep rule/message fallback

    Unknown vulnerability types receive explicit empty metadata.
    We never fabricate CWE/CVE information.
    """

    metadata_file = (
        ROOT
        / "research"
        / "datasets"
        / "vulnerability_metadata.yaml"
    )

    if not metadata_file.exists():
        raise FileNotFoundError(
            f"Security metadata file not found: {metadata_file}"
        )

    with open(
        metadata_file,
        "r",
        encoding="utf-8",
    ) as f:
        metadata = yaml.safe_load(f) or {}

    filename = vuln_path.stem.lower()

    # Explicit benchmark naming takes priority.
    if filename.startswith("cmdi_"):
        key = "cmdi"

    elif filename.startswith("sqli_"):
        key = "sqli"

    elif filename.startswith("xss_"):
        key = "xss"

    elif filename.startswith("path_traversal_"):
        key = "path_traversal"

    elif filename.startswith("hardcoded_"):
        key = "hardcoded"

    elif filename.startswith("secret_"):
        key = "secrets"

    else:
        # Fallback to finding information.
        text = (
            str(finding.get("rule_id", ""))
            + " "
            + str(finding.get("message", ""))
        ).lower()

        if "command" in text or "subprocess" in text:
            key = "cmdi"

        elif "sql" in text:
            key = "sqli"

        elif "xss" in text or "cross-site" in text:
            key = "xss"

        elif "path" in text or "traversal" in text:
            key = "path_traversal"

        elif "hardcoded" in text:
            key = "hardcoded"

        elif "secret" in text:
            key = "secrets"

        else:
            key = None

    if key is None or key not in metadata:
        return {
            "cwe": "",
            "cve": "",
            "attack_mechanism": "",
            "repair_guidance": "",
            "constraints": "",
        }

    return metadata[key]


def detect_vulnerability(
    vuln_path: Path,
) -> tuple[bool, dict | None]:

    temp_dir = tempfile.mkdtemp(
        prefix="avr_detect_"
    )

    try:

        target = Path(temp_dir) / vuln_path.name

        shutil.copy2(
            vuln_path,
            target,
        )

        findings = run_scan(
            temp_dir
        )

        if not findings:
            return False, None

        finding = findings[0]

        finding["file"] = str(target)

        return True, finding

    finally:
        shutil.rmtree(
            temp_dir,
            ignore_errors=True,
        )


def run_single(
    vuln_path: Path,
    condition: str,
    run_number: int,
) -> dict:

    experiment_id = (
        f"{vuln_path.stem}_{condition}_R{run_number}"
    )

    started = time.perf_counter()

    result = {
        "experiment_id": experiment_id,
        "vulnerability": vuln_path.name,
        "condition": condition,
        "run": run_number,
        "timestamp_utc": utc_now(),
        "model": MODEL,
        "temperature": TEMPERATURE,
        "max_tokens": MAX_TOKENS,
        "detected": False,
        "patch_generation_ok": False,
        "test_generation_ok": False,
        "syntax_ok": False,
        "security_ok": False,
        "functional_ok": False,
        "regression_ok": False,
        "semgrep_ok": False,
        "bandit_ok": False,
        "tests_ok": False,
        "status": "ERROR",
        "changed_lines": 0,
        "changed_files": 0,
        "semgrep_findings": -1,
        "bandit_findings": -1,
        "context_characters": 0,
        "context_lines": 0,
        "generation_seconds": 0.0,
        "test_generation_seconds": 0.0,
        "total_seconds": 0.0,
        "prompt_sha256": "",
        "patch_sha256": "",
        "error": "",
    }

    detected, finding = detect_vulnerability(
        vuln_path
    )

    result["detected"] = detected

    if not detected:
        result["status"] = "NO_FINDING"
        result["total_seconds"] = (
            time.perf_counter() - started
        )
        return result

    try:

        original_content = vuln_path.read_text(
            encoding="utf-8"
        )

        security_context = load_security_context(
            vuln_path,
            finding,
        )

        context = build_context(
            finding,
            original_content,
            condition,
            security_context,
        )

        metadata = context_metadata(
            finding,
            original_content,
            condition,
            security_context,
        )

        result["context_characters"] = metadata[
            "context_characters"
        ]

        result["context_lines"] = metadata[
            "context_lines"
        ]

        prompt = make_prompt(
            finding,
            context,
        )

        result["prompt_sha256"] = sha256_text(
            prompt
        )

        save_artifact(
            experiment_id,
            "context.txt",
            context,
        )

        save_artifact(
            experiment_id,
            "prompt.txt",
            prompt,
        )

        save_artifact(
            experiment_id,
            "finding.json",
            json.dumps(
                finding,
                indent=2,
            ),
        )

        # ------------------------------
        # Generate patch
        # ------------------------------

        generation_start = time.perf_counter()

        patch = generate_patch_with_context(
            finding,
            context,
        )

        result["generation_seconds"] = (
            time.perf_counter()
            - generation_start
        )

        if not patch.strip():
            raise RuntimeError(
                "LLM returned empty patch"
            )

        result["patch_generation_ok"] = True
        result["patch_sha256"] = sha256_text(
            patch
        )

        save_artifact(
            experiment_id,
            "patch.py",
            patch,
        )

        # ------------------------------
        # Generate test
        # ------------------------------

        test_start = time.perf_counter()

        generated_test = generate_test(
            finding,
            patch,
        )

        result["test_generation_seconds"] = (
            time.perf_counter()
            - test_start
        )

        if generated_test.strip():
            result["test_generation_ok"] = True

        save_artifact(
            experiment_id,
            "generated_test.py",
            generated_test,
        )

        # ------------------------------
        # Validate
        # ------------------------------

        validation_dir = tempfile.mkdtemp(
            prefix="avr_validation_"
        )

        try:

            target = (
                Path(validation_dir)
                / vuln_path.name
            )

            shutil.copy2(
                vuln_path,
                target,
            )

            validation = validate_patch(
                repo_path=validation_dir,
                file_path=str(target),
                original_content=original_content,
                patched_content=patch,
                generated_test=generated_test,
            )

            validation_data = result_to_dict(
                validation
            )

            result["syntax_ok"] = validation_data[
                "syntax_ok"
            ]

            result["security_ok"] = validation_data[
                "security_ok"
            ]

            result["functional_ok"] = validation_data[
                "functional_ok"
            ]

            result["regression_ok"] = validation_data[
                "regression_ok"
            ]

            result["semgrep_ok"] = validation_data[
                "semgrep_ok"
            ]

            result["bandit_ok"] = validation_data[
                "bandit_ok"
            ]

            result["tests_ok"] = validation_data[
                "tests_ok"
            ]

            result["status"] = validation_data[
                "status"
            ]

            result["changed_lines"] = validation_data[
                "changed_lines"
            ]

            result["changed_files"] = validation_data[
                "changed_files"
            ]

            result["semgrep_findings"] = validation_data[
                "semgrep_findings"
            ]

            result["bandit_findings"] = validation_data[
                "bandit_findings"
            ]

            save_artifact(
                experiment_id,
                "validation.json",
                json.dumps(
                    validation_data,
                    indent=2,
                    default=str,
                ),
            )

        finally:

            shutil.rmtree(
                validation_dir,
                ignore_errors=True,
            )

    except Exception as exc:

        result["status"] = "ERROR"
        result["error"] = str(exc)

        save_artifact(
            experiment_id,
            "error.txt",
            str(exc),
        )

    result["total_seconds"] = (
        time.perf_counter()
        - started
    )

    return result


def append_jsonl(
    result: dict,
    output_file: Path,
) -> None:

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        output_file,
        "a",
        encoding="utf-8",
    ) as f:

        f.write(
            json.dumps(
                result,
                ensure_ascii=False,
            )
            + "\n"
        )


def append_csv(
    result: dict,
    output_file: Path,
) -> None:

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    exists = output_file.exists()

    with open(
        output_file,
        "a",
        newline="",
        encoding="utf-8",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=CSV_FIELDS,
        )

        if not exists:
            writer.writeheader()

        writer.writerow(
            {
                field: result.get(
                    field,
                    "",
                )
                for field in CSV_FIELDS
            }
        )


def discover_vulnerabilities(
    requested: list[str] | None,
) -> list[Path]:

    if requested:

        paths = []

        for item in requested:

            path = Path(item)

            if not path.is_absolute():
                path = ROOT / item

            if not path.exists():

                candidate = (
                    VULN_DIR / item
                )

                if candidate.exists():
                    path = candidate

            if not path.exists():
                raise FileNotFoundError(
                    f"Vulnerability not found: {item}"
                )

            paths.append(path)

        return paths

    return sorted(
        VULN_DIR.glob("*.py")
    )


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--runs",
        type=int,
        default=None,
    )

    parser.add_argument(
        "--conditions",
        nargs="+",
        default=None,
        choices=[
            "C0",
            "C1",
            "C2",
            "C3",
        ],
    )

    parser.add_argument(
        "--vulns",
        nargs="*",
        default=None,
    )

    args = parser.parse_args()

    runs = (
        args.runs
        if args.runs is not None
        else int(
            CONFIG["experiment"][
                "runs_per_condition"
            ]
        )
    )

    conditions = (
        args.conditions
        if args.conditions is not None
        else CONFIG["experiment"][
            "conditions"
        ]
    )

    vulnerabilities = discover_vulnerabilities(
        args.vulns
    )

    jsonl_file = (
        RESULT_DIR
        / CONFIG["output"]["jsonl"]
    )

    csv_file = (
        RESULT_DIR
        / CONFIG["output"]["csv"]
    )

    print()
    print("=" * 64)
    print("  CONTEXT ABLATION EXPERIMENT")
    print("=" * 64)
    print(f"Vulnerabilities : {len(vulnerabilities)}")
    print(f"Conditions      : {conditions}")
    print(f"Runs            : {runs}")
    print(f"Model           : {MODEL}")
    print(f"Temperature     : {TEMPERATURE}")
    print(f"Max tokens      : {MAX_TOKENS}")
    print("=" * 64)

    total = (
        len(vulnerabilities)
        * len(conditions)
        * runs
    )

    counter = 0

    for vuln in vulnerabilities:

        for condition in conditions:

            for run_number in range(
                1,
                runs + 1,
            ):

                counter += 1

                print(
                    f"\n[{counter}/{total}] "
                    f"{vuln.name} "
                    f"{condition} "
                    f"R{run_number}"
                )

                result = run_single(
                    vuln,
                    condition,
                    run_number,
                )

                append_jsonl(
                    result,
                    jsonl_file,
                )

                append_csv(
                    result,
                    csv_file,
                )

                print(
                    f"  status     = "
                    f"{result['status']}"
                )

                print(
                    f"  security   = "
                    f"{result['security_ok']}"
                )

                print(
                    f"  functional = "
                    f"{result['functional_ok']}"
                )

                print(
                    f"  changed    = "
                    f"{result['changed_lines']} lines"
                )

                print(
                    f"  time       = "
                    f"{result['total_seconds']:.2f}s"
                )

    print()
    print("=" * 64)
    print("  EXPERIMENT COMPLETE")
    print("=" * 64)
    print(f"JSONL: {jsonl_file}")
    print(f"CSV:   {csv_file}")


if __name__ == "__main__":
    main()
