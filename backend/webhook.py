import hmac
import hashlib
import os
from fastapi import APIRouter, Request, HTTPException, BackgroundTasks
from downloader import clone_repo, cleanup_repo
from scanner import run_scan

router = APIRouter()

def verify_signature(payload: bytes, signature: str) -> bool:
    secret = os.getenv("GITHUB_WEBHOOK_SECRET", "").encode()
    mac = hmac.new(secret, payload, hashlib.sha256)
    expected = "sha256=" + mac.hexdigest()
    return hmac.compare_digest(expected, signature)

def process_repo(repo_url: str, commit: str):
    tmp_dir = clone_repo(repo_url, commit)
    try:
        findings = run_scan(tmp_dir)
        print(f"[SCAN COMPLETE] {len(findings)} findings for {repo_url}@{commit}")
        for f in findings:
            print(f)
    finally:
        cleanup_repo(tmp_dir)

@router.post("/webhook")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    signature = request.headers.get("X-Hub-Signature-256", "")
    payload = await request.body()

    if not verify_signature(payload, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")

    data = await request.json()

    if "zen" in data:
        return {"status": "pong"}

    repo_url = data["repository"]["clone_url"]
    branch = data["ref"].split("/")[-1]
    commit = data["after"]

    background_tasks.add_task(process_repo, repo_url, commit)

    return {
        "status": "accepted",
        "repo": repo_url,
        "branch": branch,
        "commit": commit
    }
