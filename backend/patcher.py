import os
import time
import requests

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

def generate_patch(finding: dict, file_content: str, prompt_condition: str = "enriched", max_retries: int = 3) -> str:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise ValueError("GROQ_API_KEY not set")

    if prompt_condition == "minimal":
        prompt = f"""You are a security engineer. Fix the following vulnerability.
Vulnerability type: {finding['rule_id'].split('.')[-1]}
Full file content:
{file_content}
Return ONLY the complete fixed file content, no explanations, no markdown, no code blocks.
"""
    else:
        prompt = f"""You are a security engineer. Fix the following vulnerability in the code.
Vulnerability Details:
- File: {finding['file']}
- Line: {finding['line']}
- Rule: {finding['rule_id']}
- Severity: {finding['severity']}
- Issue: {finding['message']}
- Vulnerable code snippet: {finding['code_snippet']}
Full file content:
{file_content}
Instructions:
1. Fix ONLY the vulnerability described above
2. Do NOT change any other logic or structure
3. Return ONLY the complete fixed file content, no explanations, no markdown, no code blocks
"""

    for attempt in range(max_retries):
        try:
            response = requests.post(
                GROQ_URL,
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": "llama-3.1-8b-instant",
                    "messages": [{"role": "user", "content": prompt}]
                },
                timeout=30
            )
            if response.status_code == 200:
                return response.json()["choices"][0]["message"]["content"]
            print(f"[GROQ] Attempt {attempt+1} failed: {response.status_code} {response.text}")
        except Exception as e:
            print(f"[GROQ] Attempt {attempt+1} exception: {e}")

        if attempt < max_retries - 1:
            wait = 2 ** attempt
            print(f"[GROQ] Retrying in {wait}s...")
            time.sleep(wait)

    raise RuntimeError(f"Groq API failed after {max_retries} attempts")
