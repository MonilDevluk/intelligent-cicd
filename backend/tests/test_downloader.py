"""
Tests for downloader.py

What this covers:
- clone_repo() succeeds and returns a real directory
- clone_repo() cleans up the temp dir and raises RuntimeError if `git clone` fails
- clone_repo() cleans up the temp dir and raises RuntimeError if `git checkout` fails
- cleanup_repo() removes an existing directory
- cleanup_repo() does not raise if the directory is already gone

We never call real git or hit the network — subprocess.run is mocked in every test.
"""
import subprocess
import os
import pytest
import downloader


def test_clone_repo_success(mocker):
    mock_run = mocker.patch("downloader.subprocess.run")
    mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)

    tmp_dir = downloader.clone_repo("https://github.com/fake/repo.git", "abc123")

    try:
        # Directory should actually exist (mkdtemp is real, only git calls are mocked)
        assert os.path.isdir(tmp_dir)

        # First call = clone, second call = checkout
        assert mock_run.call_count == 2
        clone_call, checkout_call = mock_run.call_args_list
        assert clone_call.args[0] == ["git", "clone", "https://github.com/fake/repo.git", tmp_dir]
        assert checkout_call.args[0] == ["git", "checkout", "abc123"]
        assert checkout_call.kwargs["cwd"] == tmp_dir
    finally:
        downloader.cleanup_repo(tmp_dir)


def test_clone_repo_failure_on_clone_cleans_up_and_raises(mocker):
    mock_run = mocker.patch("downloader.subprocess.run")
    mock_run.side_effect = subprocess.CalledProcessError(
        returncode=128,
        cmd=["git", "clone"],
        stderr=b"fatal: repository not found"
    )

    with pytest.raises(RuntimeError, match="Clone failed: fatal: repository not found"):
        downloader.clone_repo("https://github.com/fake/missing.git", "abc123")

    # We can't get tmp_dir back (exception swallowed it), so confirm no cicd_ dirs were left behind
    leftover = [d for d in os.listdir("/tmp") if d.startswith("cicd_")]
    assert leftover == []


def test_clone_repo_failure_on_checkout_cleans_up_and_raises(mocker):
    mock_run = mocker.patch("downloader.subprocess.run")
    mock_run.side_effect = [
        subprocess.CompletedProcess(args=[], returncode=0),  # clone succeeds
        subprocess.CalledProcessError(  # checkout fails
            returncode=1, cmd=["git", "checkout"], stderr=b"fatal: reference is not a tree"
        ),
    ]

    with pytest.raises(RuntimeError, match="Clone failed: fatal: reference is not a tree"):
        downloader.clone_repo("https://github.com/fake/repo.git", "deadbeef")

    leftover = [d for d in os.listdir("/tmp") if d.startswith("cicd_")]
    assert leftover == []


def test_cleanup_repo_removes_existing_directory(tmp_path):
    target = tmp_path / "some_repo"
    target.mkdir()
    (target / "file.txt").write_text("hello")

    downloader.cleanup_repo(str(target))

    assert not target.exists()


def test_cleanup_repo_on_missing_directory_does_not_raise(tmp_path):
    missing = tmp_path / "never_existed"

    # Should not raise even though the directory was never created
    downloader.cleanup_repo(str(missing))
