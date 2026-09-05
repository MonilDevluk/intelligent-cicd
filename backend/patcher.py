from logger import logger
import os
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


def call_groq(prompt: str, api_key: str, max_retries: int = 3) -> str:
    model = get_model()
    max_tokens = get_max_tokens()
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
                },
                timeout=60,
            )

            if response.status_code == 200:
                data = response.json()

                content = (
                    data
                    .get("choices", [{}])[0]
                    .get("message", {})
                    .get("content", "")
                )

                if not content.strip():
                    raise RuntimeError(
                        "Groq returned an empty response"
                    )

                return content

            logger.error(
                f"[GROQ] Attempt {attempt + 1} failed: "
                f"{response.status_code} {response.text}"
            )

            if response.status_code == 429:
                text = response.text.lower()

                if (
                    "expected output tokens exceed" in text
                    or "reduce max_tokens" in text
                ):
                    raise RuntimeError(
                        "Groq output-token limit exceeded. "
                        f"model={model}, max_tokens={max_tokens}"
                    )

        except RuntimeError:
            raise

        except Exception as e:
            logger.error(
                f"[GROQ] Attempt {attempt + 1} exception: {e}"
            )

        if attempt < max_retries - 1:
            wait = max(2 ** attempt, 5)

            logger.warning(
                f"[GROQ] Retrying in {wait}s..."
            )

            time.sleep(wait)

    raise RuntimeError(
        f"Groq API failed after {max_retries} attempts"
    )


def _clean_llm_output(content: str) -> str:
    content = content.strip()

    if content.startswith("```"):
        lines = content.splitlines()

        if lines:
            lines = lines[1:]

        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]

        content = "\n".join(lines).strip()

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
6. No explanations.
7. No markdown.
8. No code fences.
"""

    result = call_groq(
        prompt,
        api_key,
        max_retries,
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
6. No explanations.
7. No markdown.
8. No code fences.

Module name:
{module_name}
"""

    result = call_groq(
        prompt,
        api_key,
        max_retries,
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
