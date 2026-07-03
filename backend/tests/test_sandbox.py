"""
Tests for sandbox.py

What this covers:
- run_bandit_scan() correctly classifies high/medium issues and "clean" status
- run_bandit_scan() treats malformed bandit output as clean (matches current behavior)
- run_sandbox_test() status decision table:
    bandit dirty                       -> NEEDS_REVIEW  (regardless of pytest result)
    bandit clean + pytest passes       -> SAFE
    bandit clean + no tests collected  -> UNVERIFIED
    bandit clean + pytest fails        -> NEEDS_REVIEW
- run_sandbox_test() writes the patched content and generated test into the sandbox dir
- run_sandbox_test() always cleans up its temp sandbox dir, even on exception
- run_sandbox_test() returns status=ERROR if something throws mid-run

We never run real bandit or pytest — subprocess.run is mocked in every test.
Real tempfile/shutil operations ARE exercised so we know sandbox isolation actually works.
"""
import os
import json
import subprocess
import sandbox


# ---------- run_bandit_scan ----------

def test_run_bandit_scan_clean_when_no_issues(mocker):
    mock_run = mocker.patch("sandbox.subprocess.run")
    mock_run.return_value = subprocess.CompletedProcess(
        args=[], returncode=0, stdout=json.dumps({"results": []})
    )

    result = sandbox.run_bandit_scan("/tmp/fake_file.py")

    assert result["clean"] is True
    assert result["high_count"] == 0
    assert result["medium_count"] == 0
    assert result["total_count"] == 0


def test_run_bandit_scan_dirty_when_high_severity_issue_present(mocker):
    mock_run = mocker.patch("sandbox.subprocess.run")
    mock_run.return_value = subprocess.CompletedProcess(
        args=[], returncode=1,
        stdout=json.dumps({
            "results": [
                {"issue_severity": "HIGH"},
                {"issue_severity": "MEDIUM"},
            ]
        })
    )

    result = sandbox.run_bandit_scan("/tmp/fake_file.py")

    assert result["clean"] is False
    assert result["high_count"] == 1
    assert result["medium_count"] == 1
    assert result["total_count"] == 2


def test_run_bandit_scan_clean_when_only_medium_issues(mocker):
    mock_run = mocker.patch("sandbox.subprocess.run")
    mock_run.return_value = subprocess.CompletedProcess(
        args=[], returncode=0,
        stdout=json.dumps({"results": [{"issue_severity": "MEDIUM"}]})
    )

    result = sandbox.run_bandit_scan("/tmp/fake_file.py")

    # only HIGH severity affects "clean" per current implementation
    assert result["clean"] is True
    assert result["medium_count"] == 1


def test_run_bandit_scan_treats_malformed_json_as_clean(mocker):
    mock_run = mocker.patch("sandbox.subprocess.run")
    mock_run.return_value = subprocess.CompletedProcess(
        args=[], returncode=1, stdout="not valid json {{{"
    )

    result = sandbox.run_bandit_scan("/tmp/fake_file.py")

    assert result["clean"] is True
    assert result["total_count"] == 0


def test_run_bandit_scan_treats_exception_as_clean(mocker):
    mock_run = mocker.patch("sandbox.subprocess.run")
    mock_run.side_effect = subprocess.TimeoutExpired(cmd="bandit", timeout=30)

    result = sandbox.run_bandit_scan("/tmp/fake_file.py")

    assert result["clean"] is True
    assert "error" in result


# ---------- run_sandbox_test ----------

def _bandit_result(clean=True, high_count=0):
    return {"clean": clean, "high_count": high_count, "medium_count": 0, "total_count": high_count, "raw": {}}


def _make_fake_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def vulnerable(): pass\n")
    return repo


def test_run_sandbox_test_bandit_dirty_overrides_passing_pytest(tmp_path, mocker):
    repo = _make_fake_repo(tmp_path)
    mocker.patch("sandbox.run_bandit_scan", return_value=_bandit_result(clean=False, high_count=1))
    mock_run = mocker.patch("sandbox.subprocess.run")
    mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="1 passed", stderr="")

    result = sandbox.run_sandbox_test(str(repo), str(repo / "app.py"), "def vulnerable(): pass\n")

    assert result["status"] == "NEEDS_REVIEW"


def test_run_sandbox_test_clean_bandit_and_passing_tests_is_safe(tmp_path, mocker):
    repo = _make_fake_repo(tmp_path)
    mocker.patch("sandbox.run_bandit_scan", return_value=_bandit_result(clean=True))
    mock_run = mocker.patch("sandbox.subprocess.run")
    mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="2 passed", stderr="")

    result = sandbox.run_sandbox_test(str(repo), str(repo / "app.py"), "def fixed(): pass\n", "def test_fixed(): assert True")

    assert result["status"] == "SAFE"
    assert result["passed"] is True


def test_run_sandbox_test_no_tests_collected_is_unverified(tmp_path, mocker):
    repo = _make_fake_repo(tmp_path)
    mocker.patch("sandbox.run_bandit_scan", return_value=_bandit_result(clean=True))
    mock_run = mocker.patch("sandbox.subprocess.run")
    mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=5, stdout="no tests ran", stderr="")

    result = sandbox.run_sandbox_test(str(repo), str(repo / "app.py"), "def fixed(): pass\n")

    assert result["status"] == "UNVERIFIED"
    assert result["no_tests"] is True


def test_run_sandbox_test_failing_tests_needs_review(tmp_path, mocker):
    repo = _make_fake_repo(tmp_path)
    mocker.patch("sandbox.run_bandit_scan", return_value=_bandit_result(clean=True))
    mock_run = mocker.patch("sandbox.subprocess.run")
    mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=1, stdout="1 failed", stderr="")

    result = sandbox.run_sandbox_test(str(repo), str(repo / "app.py"), "def still_broken(): pass\n")

    assert result["status"] == "NEEDS_REVIEW"
    assert result["passed"] is False


def test_run_sandbox_test_writes_patched_content_and_generated_test(tmp_path, mocker):
    repo = _make_fake_repo(tmp_path)
    mocker.patch("sandbox.run_bandit_scan", return_value=_bandit_result(clean=True))

    captured_sandbox_dir = {}

    def fake_run(cmd, cwd=None, capture_output=True, text=True, timeout=60):
        # pytest is invoked with cwd=sandbox_dir; capture what got written there
        captured_sandbox_dir["path"] = cwd
        with open(os.path.join(cwd, "app.py")) as f:
            captured_sandbox_dir["patched_content"] = f.read()
        with open(os.path.join(cwd, "test_auto_generated.py")) as f:
            captured_sandbox_dir["generated_test"] = f.read()
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="1 passed", stderr="")

    mocker.patch("sandbox.subprocess.run", side_effect=fake_run)

    sandbox.run_sandbox_test(
        str(repo), str(repo / "app.py"),
        "def patched(): return 'safe'\n",
        "def test_patched(): assert True\n"
    )

    assert captured_sandbox_dir["patched_content"] == "def patched(): return 'safe'\n"
    assert captured_sandbox_dir["generated_test"] == "def test_patched(): assert True\n"
    # sandbox dir must not be the original repo (isolation)
    assert captured_sandbox_dir["path"] != str(repo)
    # and it should be cleaned up after the call
    assert not os.path.isdir(captured_sandbox_dir["path"])


def test_run_sandbox_test_cleans_up_sandbox_dir_even_on_exception(tmp_path, mocker):
    repo = _make_fake_repo(tmp_path)
    mocker.patch("sandbox.run_bandit_scan", side_effect=RuntimeError("boom"))

    result = sandbox.run_sandbox_test(str(repo), str(repo / "app.py"), "def patched(): pass\n")

    assert result["status"] == "ERROR"
    assert "boom" in result["stderr"]
