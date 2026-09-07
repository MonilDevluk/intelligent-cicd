"""
Tests for patcher.py

What this covers:
- call_groq() returns content on first-try success
- call_groq() retries on non-200 response, then succeeds
- call_groq() retries on request exception, then succeeds
- call_groq() raises RuntimeError after exhausting all retries
- call_groq() sleeps between retries (time.sleep is mocked, so tests stay fast)
- generate_patch() builds the correct prompt for "minimal" vs "enriched" conditions
- generate_patch() / generate_test() raise ValueError immediately if GROQ_API_KEY is missing,
  without making any network call
- generate_test() includes the vulnerability context and correct module name in its prompt

We never hit the real Groq API — requests.post is mocked in every test, and time.sleep
is mocked so retry tests don't actually wait.
"""
import pytest
import requests
import patcher


FAKE_FINDING = {
    "file": "app/views.py",
    "line": 42,
    "rule_id": "python.lang.security.audit.sql-injection",
    "severity": "ERROR",
    "message": "Possible SQL injection via string formatting",
    "code_snippet": "cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")"
}

FAKE_FILE_CONTENT = "def get_user(user_id):\n    cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")\n"


def _groq_response(content: str, status: int = 200):
    class FakeResponse:
        status_code = status
        text = "" if status == 200 else "error text"

        def json(self):
            return {"choices": [{"message": {"content": content}}]}

    return FakeResponse()


# ---------- call_groq ----------

def test_call_groq_success_on_first_attempt(mocker):
    mock_post = mocker.patch("patcher.requests.post")
    mock_post.return_value = _groq_response("fixed code here")

    result = patcher.call_groq("some prompt", api_key="fake-key")

    assert result == "fixed code here"
    assert mock_post.call_count == 1


def test_call_groq_retries_on_non_200_then_succeeds(mocker):
    mock_post = mocker.patch("patcher.requests.post")
    mock_sleep = mocker.patch("patcher.time.sleep")
    mock_post.side_effect = [
        _groq_response("", status=429),
        _groq_response("fixed after retry"),
    ]

    result = patcher.call_groq("some prompt", api_key="fake-key")

    assert result == "fixed after retry"
    assert mock_post.call_count == 2
    assert mock_sleep.call_count == 1  # one wait between the two attempts


def test_call_groq_retries_on_exception_then_succeeds(mocker):
    mock_post = mocker.patch("patcher.requests.post")
    mock_sleep = mocker.patch("patcher.time.sleep")
    mock_post.side_effect = [
        requests.exceptions.Timeout("connection timed out"),
        _groq_response("fixed after exception"),
    ]

    result = patcher.call_groq("some prompt", api_key="fake-key")

    assert result == "fixed after exception"
    assert mock_post.call_count == 2


def test_call_groq_raises_after_exhausting_retries(mocker):
    mock_post = mocker.patch("patcher.requests.post")
    mocker.patch("patcher.time.sleep")  # don't actually wait
    mock_post.return_value = _groq_response("", status=500)

    with pytest.raises(RuntimeError, match="Groq API failed after 3 attempts"):
        patcher.call_groq("some prompt", api_key="fake-key", max_retries=3)

    assert mock_post.call_count == 3


def test_call_groq_does_not_sleep_after_final_attempt(mocker):
    mock_post = mocker.patch("patcher.requests.post")
    mock_sleep = mocker.patch("patcher.time.sleep")
    mock_post.return_value = _groq_response("", status=500)

    with pytest.raises(RuntimeError):
        patcher.call_groq("some prompt", api_key="fake-key", max_retries=3)

    # 3 attempts -> only 2 sleeps in between, no sleep after the last failed attempt
    assert mock_sleep.call_count == 2


# ---------- generate_patch ----------

def test_generate_patch_missing_api_key_raises_without_network_call(mocker, monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    mock_post = mocker.patch("patcher.requests.post")

    with pytest.raises(ValueError, match="GROQ_API_KEY not set"):
        patcher.generate_patch(FAKE_FINDING, FAKE_FILE_CONTENT, prompt_condition="minimal")

    mock_post.assert_not_called()


def test_generate_patch_minimal_prompt_excludes_finding_details(mocker, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "fake-key")
    mock_post = mocker.patch("patcher.requests.post")
    mock_post.return_value = _groq_response("patched content")

    patcher.generate_patch(FAKE_FINDING, FAKE_FILE_CONTENT, prompt_condition="minimal")

    sent_prompt = mock_post.call_args.kwargs["json"]["messages"][0]["content"]
    assert "sql-injection" in sent_prompt          # vuln type is included
    assert FAKE_FILE_CONTENT in sent_prompt         # full file is included
    # enriched-only structured fields must be absent from the minimal prompt
    assert "Line:" not in sent_prompt
    assert "Rule:" not in sent_prompt
    assert "Severity:" not in sent_prompt
    assert "Vulnerable code snippet:" not in sent_prompt


def test_generate_patch_enriched_prompt_includes_full_finding_details(mocker, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "fake-key")
    mock_post = mocker.patch("patcher.requests.post")
    mock_post.return_value = _groq_response("patched content")

    patcher.generate_patch(FAKE_FINDING, FAKE_FILE_CONTENT, prompt_condition="enriched")

    sent_prompt = mock_post.call_args.kwargs["json"]["messages"][0]["content"]
    assert FAKE_FINDING["file"] in sent_prompt
    assert str(FAKE_FINDING["line"]) in sent_prompt
    assert FAKE_FINDING["rule_id"] in sent_prompt
    assert FAKE_FINDING["severity"] in sent_prompt
    assert FAKE_FINDING["message"] in sent_prompt
    assert FAKE_FINDING["code_snippet"] in sent_prompt
    assert FAKE_FILE_CONTENT in sent_prompt


def test_generate_patch_returns_groq_output_directly(mocker, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "fake-key")
    mock_post = mocker.patch("patcher.requests.post")
    mock_post.return_value = _groq_response("def get_user(user_id):\n    cursor.execute(query, (user_id,))\n")

    result = patcher.generate_patch(FAKE_FINDING, FAKE_FILE_CONTENT, prompt_condition="enriched")

    assert result == "def get_user(user_id):\n    cursor.execute(query, (user_id,))"


# ---------- generate_test ----------

def test_generate_test_missing_api_key_raises_without_network_call(mocker, monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    mock_post = mocker.patch("patcher.requests.post")

    with pytest.raises(ValueError, match="GROQ_API_KEY not set"):
        patcher.generate_test(FAKE_FINDING, "patched content here")

    mock_post.assert_not_called()


def test_generate_test_prompt_includes_module_name_and_vuln_context(mocker, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "fake-key")
    mock_post = mocker.patch("patcher.requests.post")
    mock_post.return_value = _groq_response("def test_get_user(): ...")

    patcher.generate_test(FAKE_FINDING, "patched code content")

    sent_prompt = mock_post.call_args.kwargs["json"]["messages"][0]["content"]
    assert "views" in sent_prompt  # module name derived from "app/views.py"
    assert FAKE_FINDING["message"] in sent_prompt
    assert FAKE_FINDING["rule_id"] in sent_prompt
    assert "patched code content" in sent_prompt
