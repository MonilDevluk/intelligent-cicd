import hmac
import hashlib
import os
from fastapi import APIRouter, Request, HTTPException

router = APIRouter()

def verify_signature(payload: bytes, signature: str) -> bool:
    secret = os.getenv("GITHUB_WEBHOOK_SECRET", "").encode()
    mac = hmac.new(secret, payload, hashlib.sha256)
    expected = "sha256=" + mac.hexdigest()
    return hmac.compare_digest(expected, signature)

@router.post("/webhook")
async def github_webhook(request: Request):
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

    return {
        "status": "received",
        "repo": repo_url,
        "branch": branch,
        "commit": commit
    }
