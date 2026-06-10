import os
import requests

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

def generate_patch(finding: dict, file_content: str) -> str:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise ValueError("GROQ_API_KEY not set")

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

    response = requests.post(
        GROQ_URL,
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "model": "llama-3.1-8b-instant",
            "messages": [{"role": "user", "content": prompt}]
        }
    )

    if response.status_code != 200:
        raise RuntimeError(f"Groq API error: {response.text}")

    return response.json()["choices"][0]["message"]["content"]
