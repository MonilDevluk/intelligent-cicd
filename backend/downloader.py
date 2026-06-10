import os
import shutil
import subprocess
import tempfile

def clone_repo(repo_url: str, commit: str) -> str:
    tmp_dir = tempfile.mkdtemp(prefix="cicd_")
    try:
        subprocess.run(
            ["git", "clone", repo_url, tmp_dir],
            check=True,
            capture_output=True
        )
        subprocess.run(
            ["git", "checkout", commit],
            cwd=tmp_dir,
            check=True,
            capture_output=True
        )
    except subprocess.CalledProcessError as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RuntimeError(f"Clone failed: {e.stderr.decode()}")

    return tmp_dir

def cleanup_repo(tmp_dir: str):
    shutil.rmtree(tmp_dir, ignore_errors=True)
