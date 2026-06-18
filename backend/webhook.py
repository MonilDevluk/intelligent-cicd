import hmac
import hashlib
import os
import time
from fastapi import APIRouter, Request, HTTPException, BackgroundTasks
from downloader import clone_repo, cleanup_repo
from scanner import run_scan
from patcher import generate_patch, generate_test
from github_pr import create_pull_request
from sandbox import run_sandbox_test
from logger import logger
from database import save_scan, save_finding, save_patch

router = APIRouter()

# Global lock — prevents concurrent pipelines
_pipeline_running = False

def verify_signature(payload: bytes, signature: str) -> bool:
    secret = os.getenv("GITHUB_WEBHOOK_SECRET", "").encode()
    mac = hmac.new(secret, payload, hashlib.sha256)
    expected = "sha256=" + mac.hexdigest()
    return hmac.compare_digest(expected, signature)

def process_repo(repo_url: str, branch: str, commit: str):
    global _pipeline_running
    if _pipeline_running:
        logger.warning(f"[LOCK] Pipeline already running. Skipping: {commit[:7]}")
        return
    _pipeline_running = True
    logger.info(f"[LOCK] Pipeline started: {commit[:7]}")
    tmp_dir = clone_repo(repo_url, commit)
    try:
        findings = run_scan(tmp_dir)
        logger.info(f"[SCAN COMPLETE] {len(findings)} findings")
        scan_id = save_scan(repo_url, branch, commit)
        logger.info(f"[DB] Scan saved: {scan_id}")
        for finding in findings:
            file_path = finding["file"]
            try:
                with open(file_path, "r") as f:
                    file_content = f.read()
                finding_id = save_finding(scan_id, finding)
                logger.info(f"[DB] Finding saved: {finding_id}")
                for condition in ["minimal", "enriched"]:
                    time.sleep(10)
                    try:
                        patch = generate_patch(finding, file_content, prompt_condition=condition)
                        logger.info(f"[PATCH GENERATED] condition={condition} {file_path}:{finding['line']}")
                        generated_test = generate_test(finding, patch)
                        logger.info(f"[TEST GENERATED] condition={condition} {file_path}:{finding['line']}")
                        test_result = run_sandbox_test(tmp_dir, file_path, patch, generated_test)
                        logger.info(f"[SANDBOX] condition={condition} status={test_result['status']}")
                        pr_url = ""
                        if test_result["status"] in ["SAFE", "UNVERIFIED", "NEEDS_REVIEW"]:
                            try:
                                pr = create_pull_request(repo_url, file_path, patch, finding, condition, original_content=file_content)
                                pr_url = pr.get("pr_url", "")
                                logger.info(f"[PR CREATED] {pr_url}")
                            except Exception as pr_e:
                                logger.error(f"[PR FAILED] {pr_e}")
                        save_patch(
                            finding_id,
                            file_content,
                            patch,
                            test_result["status"],
                            test_result["stdout"],
                            prompt_condition=condition,
                            generated_test=generated_test,
                            pr_url=pr_url
                        )
                        logger.info(f"[DB] Patch saved: condition={condition}")
                    except Exception as e:
                        logger.error(f"[FAILED] condition={condition} {file_path}: {e}")
            except Exception as e:
                logger.error(f"[FAILED] {file_path}: {e}")
    finally:
        cleanup_repo(tmp_dir)
        _pipeline_running = False
        logger.info("[LOCK] Pipeline released.")

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
    if _pipeline_running:
        logger.warning(f"[LOCK] Push received but pipeline busy. Ignoring: {commit[:7]}")
        return {"status": "busy", "message": "Pipeline already running. Push ignored."}

    background_tasks.add_task(process_repo, repo_url, branch, commit)
    return {
        "status": "accepted",
        "repo": repo_url,
        "branch": branch,
        "commit": commit
    }
