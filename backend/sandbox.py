import os
import shutil
import subprocess
import tempfile

def run_sandbox_test(repo_path: str, file_path: str, patched_content: str) -> dict:
    sandbox_dir = tempfile.mkdtemp(prefix="sandbox_")

    try:
        shutil.copytree(repo_path, sandbox_dir, dirs_exist_ok=True)

        relative_path = os.path.relpath(file_path, repo_path)
        sandbox_file = os.path.join(sandbox_dir, relative_path)

        with open(sandbox_file, "w") as f:
            f.write(patched_content)

        result = subprocess.run(
            ["python", "-m", "pytest", "--tb=short", "-q"],
            cwd=sandbox_dir,
            capture_output=True,
            text=True,
            timeout=60
        )

        passed = result.returncode == 0
        no_tests = "no tests ran" in result.stdout.lower() or result.returncode == 5

        return {
            "status": "SAFE" if passed else ("UNVERIFIED" if no_tests else "NEEDS_REVIEW"),
            "passed": passed,
            "no_tests": no_tests,
            "stdout": result.stdout,
            "stderr": result.stderr
        }

    except Exception as e:
        return {
            "status": "ERROR",
            "passed": False,
            "no_tests": False,
            "stdout": "",
            "stderr": str(e)
        }
    finally:
        shutil.rmtree(sandbox_dir, ignore_errors=True)
