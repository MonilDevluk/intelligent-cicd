import os
from supabase import create_client

def get_client():
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_KEY")
    return create_client(url, key)

def save_scan(repo_url: str, branch: str, commit_hash: str) -> str:
    client = get_client()
    result = client.table("scans").insert({
        "repo_url": repo_url,
        "branch": branch,
        "commit_hash": commit_hash
    }).execute()
    return result.data[0]["id"]

def save_finding(scan_id: str, finding: dict) -> str:
    client = get_client()
    result = client.table("findings").insert({
        "scan_id": scan_id,
        "file_path": finding["file"],
        "line_number": finding["line"],
        "rule_id": finding["rule_id"],
        "severity": finding["severity"],
        "message": finding["message"],
        "code_snippet": finding["code_snippet"]
    }).execute()
    return result.data[0]["id"]

def save_patch(finding_id: str, original_code: str, patched_code: str, sandbox_status: str, test_output: str, prompt_condition: str = ""):
    client = get_client()
    client.table("patches").insert({
        "finding_id": finding_id,
        "original_code": original_code,
        "patched_code": patched_code,
        "sandbox_status": sandbox_status,
        "test_output": test_output,
        "prompt_condition": prompt_condition
    }).execute()
