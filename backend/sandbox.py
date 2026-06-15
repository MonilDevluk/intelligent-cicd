import os
import shutil
import subprocess
import tempfile

def run_bandit_scan(file_path: str) -> dict:
    try:
        result = subprocess.run(
            ["bandit", "-r", file_path, "-f", "json", "-q"],
            capture_output=True,
            text=True,
            timeout=30
        )
        import json
        try:
            data = json.loads(result.stdout)
            issues = data.get("results", [])
            high_issues = [i for i in issues if i.get("issue_severity") == "HIGH"]
            medium_issues = [i for i in issues if i.get("issue_severity") == "MEDIUM"]
            return {
                "clean": len(high_issues) == 0,
                "high_count": len(high_issues),
                "medium_count": len(medium_issues),
                "total_count": len(issues),
                "raw": data
            }
        except json.JSONDecodeError:
            return {"clean": True, "high_count": 0, "medium_count": 0, "total_count": 0, "raw": {}}
    except Exception as e:
        return {"clean": True, "high_count": 0, "medium_count": 0, "total_count": 0, "error": str(e)}

def run_sandbox_test(repo_path: str, file_path: str, patched_content: str, generated_test: str = None) -> dict:
    sandbox_dir = tempfile.mkdtemp(prefix="sandbox_")
    try:
        shutil.copytree(repo_path, sandbox_dir, dirs_exist_ok=True)
        relative_path = os.path.relpath(file_path, repo_path)
        sandbox_file = os.path.join(sandbox_dir, relative_path)

        with open(sandbox_file, "w") as f:
            f.write(patched_content)

        # Write auto-generated test if provided
        if generated_test:
            test_file = os.path.join(sandbox_dir, "test_auto_generated.py")
            with open(test_file, "w") as f:
                f.write(generated_test)

        # Run Bandit on patched file
        bandit_result = run_bandit_scan(sandbox_file)

        # Run pytest
        result = subprocess.run(
            ["python", "-m", "pytest", "--tb=short", "-q"],
            cwd=sandbox_dir,
            capture_output=True,
            text=True,
            timeout=60
        )

        passed = result.returncode == 0
        no_tests = "no tests ran" in result.stdout.lower() or result.returncode == 5

        # Determine final status
        if not bandit_result["clean"]:
            status = "NEEDS_REVIEW"
        elif passed:
            status = "SAFE"
        elif no_tests:
            status = "UNVERIFIED"
        else:
            status = "NEEDS_REVIEW"

        return {
            "status": status,
            "passed": passed,
            "no_tests": no_tests,
            "bandit": bandit_result,
            "stdout": result.stdout,
            "stderr": result.stderr
        }

    except Exception as e:
        return {
            "status": "ERROR",
            "passed": False,
            "no_tests": False,
            "bandit": {},
            "stdout": "",
            "stderr": str(e)
        }
    finally:
        shutil.rmtree(sandbox_dir, ignore_errors=True)
