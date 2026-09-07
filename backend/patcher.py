from logger import logger
import os
import re
import time
import requests


GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

DEFAULT_MODEL = "qwen/qwen3.6-27b"
DEFAULT_MAX_TOKENS = 700
DEFAULT_TEMPERATURE = 0.0


def get_model():
    return os.getenv("GROQ_MODEL", DEFAULT_MODEL)


def get_max_tokens():
    try:
        return int(os.getenv("GROQ_MAX_TOKENS", str(DEFAULT_MAX_TOKENS)))
    except ValueError:
        return DEFAULT_MAX_TOKENS


def get_temperature():
    try:
        return float(
            os.getenv(
                "GROQ_TEMPERATURE",
                str(DEFAULT_TEMPERATURE),
            )
        )
    except ValueError:
        return DEFAULT_TEMPERATURE


def call_groq(
    prompt: str,
    api_key: str,
    max_retries: int = 2,
    max_tokens_override: int = None,
) -> str:
    """
    Call Groq with conservative retry/rate-limit handling.

    The Qwen model may emit reasoning unless explicitly told not to.
    We therefore enforce a no-reasoning prompt contract and reject
    responses that were truncated by the output-token limit.
    """
    model = get_model()
    max_tokens = (
        max_tokens_override
        if max_tokens_override is not None
        else get_max_tokens()
    )
    temperature = get_temperature()

    for attempt in range(max_retries):
        try:
            response = requests.post(
                GROQ_URL,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "messages": [
                        {
                            "role": "user",
                            "content": prompt,
                        }
                    ],
                    "temperature": temperature,
                    "max_tokens": max_tokens,

                    # Qwen 3.6 supports explicit non-thinking
                    # mode. This is critical for source generation:
                    # the output budget should contain the patch,
                    # not hidden reasoning.
                    "reasoning_effort": "none",
                },
                timeout=90,
            )

            if response.status_code == 200:
                data = response.json()

                choice = data.get("choices", [{}])[0]
                message = choice.get("message", {})
                content = message.get("content", "") or ""
                finish_reason = choice.get("finish_reason", "")

                if not content.strip():
                    raise RuntimeError(
                        "Groq returned an empty response"
                    )

                # A response ending because max_tokens was reached
                # is not a usable source file.
                if finish_reason == "length":
                    raise RuntimeError(
                        "Groq response was truncated at max_tokens. "
                        f"model={model}, max_tokens={max_tokens}"
                    )

                return content

            logger.error(
                f"[GROQ] Attempt {attempt + 1} failed: "
                f"{response.status_code} {response.text}"
            )

            # Retry ordinary transient HTTP failures (5xx).
            # Never sleep after the final attempt.
            if response.status_code >= 500:
                if attempt < max_retries - 1:
                    wait = max(5.0, 2 ** attempt)
                    logger.warning(
                        f"[GROQ] Server error. "
                        f"Retrying in {wait:.1f}s..."
                    )
                    time.sleep(wait)
                    continue

                raise RuntimeError(
                    f"Groq API failed after {max_retries} attempts: "
                    f"{response.status_code} {response.text}"
                )

            if response.status_code == 429:
                text = response.text.lower()

                # ------------------------------------------------
                # Structural OTPM limit:
                #
                # Example:
                # Limit 1000, Requested 1200
                #
                # Retrying the same request can never succeed.
                # ------------------------------------------------

                otp_match = re.search(
                    r"limit\s+(\d+).*?requested\s+(\d+)",
                    text,
                    flags=re.DOTALL,
                )

                if otp_match:
                    limit = int(otp_match.group(1))
                    requested = int(otp_match.group(2))

                    raise RuntimeError(
                        "Groq output-token request exceeds the "
                        f"organization OTPM limit: "
                        f"requested={requested}, limit={limit}. "
                        "Reduce max_tokens."
                    )

                # ------------------------------------------------
                # Temporary rate limit:
                # respect a server-provided retry interval if
                # available.
                # ------------------------------------------------

                match = re.search(
                    r"try again in\s+([0-9.]+)\s*(ms|s)",
                    text,
                )

                if match:
                    amount = float(match.group(1))
                    unit = match.group(2)
                    wait = (
                        amount / 1000.0
                        if unit == "ms"
                        else amount
                    )
                    wait = max(wait + 1.0, 5.0)
                else:
                    wait = 35.0

                if attempt < max_retries - 1:
                    logger.warning(
                        f"[GROQ] Rate limited. "
                        f"Waiting {wait:.1f}s..."
                    )
                    time.sleep(wait)
                    continue

                raise RuntimeError(
                    "Groq rate limit persisted after retries"
                )

        except RuntimeError:
            raise

        except Exception as e:
            logger.error(
                f"[GROQ] Attempt {attempt + 1} exception: {e}"
            )

            if attempt < max_retries - 1:
                wait = max(5.0, 2 ** attempt)
                logger.warning(
                    f"[GROQ] Retrying in {wait:.1f}s..."
                )
                time.sleep(wait)

    raise RuntimeError(
        f"Groq API failed after {max_retries} attempts"
    )


def _clean_llm_output(content: str) -> str:
    """
    Convert an LLM response into source code only.

    Reasoning output is never allowed to silently become part of
    the generated source. An unterminated <think> block is rejected.
    """
    content = content.strip()

    # Complete reasoning block: remove it.
    content = re.sub(
        r"<think>.*?</think>",
        "",
        content,
        flags=re.DOTALL | re.IGNORECASE,
    ).strip()

    # If a reasoning block remains, it was truncated.
    if re.search(r"<think>", content, flags=re.IGNORECASE):
        raise RuntimeError(
            "LLM response contains an unterminated <think> block"
        )

    # Remove markdown fences if the model ignored the instruction.
    if content.startswith("```"):
        lines = content.splitlines()

        if lines:
            lines = lines[1:]

        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]

        content = "\n".join(lines).strip()

    # Reject obvious conversational output.
    first = content.splitlines()[0].strip() if content else ""

    if first.lower().startswith(
        (
            "here is",
            "here's",
            "sure,",
            "certainly,",
            "the fixed",
            "the corrected",
        )
    ):
        raise RuntimeError(
            "LLM returned explanatory text instead of source code"
        )

    if not content:
        raise RuntimeError(
            "LLM returned empty source after cleaning"
        )

    return content


def generate_patch(
    finding: dict,
    file_content: str,
    prompt_condition: str = "enriched",
    max_retries: int = 3,
) -> str:

    api_key = os.getenv("GROQ_API_KEY")

    if not api_key:
        raise ValueError("GROQ_API_KEY not set")

    if prompt_condition == "minimal":
        prompt = f"""You are a security engineer.

/no_think

Fix the following vulnerability.

Vulnerability type:
{finding['rule_id'].split('.')[-1]}

Full file content:
{file_content}

Return ONLY the complete fixed file content.
No explanations.
No markdown.
No code fences.
"""

    else:
        prompt = f"""You are a security engineer.

/no_think

Fix ONLY the vulnerability described below.

Vulnerability Details:
- File: {finding['file']}
- Line: {finding['line']}
- Rule: {finding['rule_id']}
- Severity: {finding['severity']}
- Issue: {finding['message']}
- Vulnerable code:
{finding['code_snippet']}

Full file content:
{file_content}

Requirements:
1. Fix only the reported vulnerability.
2. Preserve all unrelated behavior.
3. Do not introduce unnecessary dependencies.
4. Prefer the smallest correct security fix.
5. Return ONLY the complete fixed file content.
6. Do NOT output reasoning, analysis, <think> tags, or commentary.
7. No explanations.
7. No markdown.
8. No code fences.
"""

    patch_max_tokens = int(
        os.getenv("GROQ_PATCH_MAX_TOKENS", "900")
    )

    result = call_groq(
        prompt,
        api_key,
        max_retries,
        max_tokens_override=patch_max_tokens,
    )

    return _clean_llm_output(result)


def generate_test(
    finding: dict,
    patched_content: str,
    max_retries: int = 3,
) -> str:

    api_key = os.getenv("GROQ_API_KEY")

    if not api_key:
        raise ValueError("GROQ_API_KEY not set")

    module_name = os.path.basename(
        finding["file"]
    ).replace(".py", "")

    prompt = f"""You are a security testing engineer.

/no_think

Write a compact pytest test file for the patched Python code.

Original vulnerability:
{finding['message']}

Rule:
{finding['rule_id']}

Vulnerable code:
{finding['code_snippet']}

Patched code:
{patched_content}

Requirements:
1. Test normal safe behavior.
2. Test the security boundary relevant to the vulnerability.
3. Keep the test compact.
4. Import the module correctly.
5. Return ONLY the pytest file.
6. Do NOT output reasoning, analysis, <think> tags, or commentary.
7. No explanations.
7. No markdown.
8. No code fences.

Module name:
{module_name}
"""

    test_max_tokens = int(
        os.getenv("GROQ_TEST_MAX_TOKENS", "500")
    )

    result = call_groq(
        prompt,
        api_key,
        max_retries,
        max_tokens_override=test_max_tokens,
    )

    return _clean_llm_output(result)


def generate_refined_patch(
    finding,
    file_content,
    context,
    validation_feedback,
):
    """
    Generate a revised patch using feedback from a previous
    validation attempt.
    """

    api_key = os.getenv("GROQ_API_KEY")

    if not api_key:
        raise RuntimeError("GROQ_API_KEY is not set")

    prompt = f"""
You are an expert secure software engineer performing
vulnerability remediation.

Return ONLY the complete replacement source file.
Do not use markdown fences.
Do not explain the answer.

VULNERABILITY
-------------
Rule: {finding.get("rule_id", "")}
Severity: {finding.get("severity", "")}
Message: {finding.get("message", "")}
Line: {finding.get("line", "")}

SECURITY CONTEXT
----------------
{context}

CURRENT SOURCE FILE
-------------------
{file_content}

PREVIOUS VALIDATION FEEDBACK
----------------------------
{validation_feedback}

TASK
----
Correct the vulnerability and address every failure reported
by validation feedback.

Requirements:

1. Preserve existing intended behavior.
2. Make the smallest reasonable security fix.
3. Do not introduce unrelated changes.
4. Do not remove functionality merely to make tests pass.
5. Ensure attacker-controlled input cannot exploit the reported
   vulnerability.
6. Return the COMPLETE replacement source file.
"""

    result = call_groq(prompt, api_key)

    return _clean_llm_output(result)
