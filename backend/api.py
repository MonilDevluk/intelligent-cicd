from fastapi import APIRouter
from database import get_client

router = APIRouter()

@router.get("/scans")
def get_scans():
    client = get_client()
    result = client.table("scans").select("*").order("created_at", desc=True).execute()
    return result.data

@router.get("/scans/{scan_id}")
def get_scan(scan_id: str):
    client = get_client()
    scan = client.table("scans").select("*").eq("id", scan_id).execute()
    findings = client.table("findings").select("*").eq("scan_id", scan_id).execute()
    return {
        "scan": scan.data[0] if scan.data else None,
        "findings": findings.data
    }

@router.get("/findings/{finding_id}/patches")
def get_patches(finding_id: str):
    client = get_client()
    result = client.table("patches").select("*").eq("finding_id", finding_id).execute()
    patches = {"minimal": None, "enriched": None}
    for patch in result.data:
        condition = patch.get("prompt_condition", "")
        if condition in patches:
            patches[condition] = patch
    return patches

@router.get("/stats")
def get_stats():
    client = get_client()
    scans = client.table("scans").select("id", count="exact").execute()
    findings = client.table("findings").select("id", count="exact").execute()
    patches = client.table("patches").select("id", count="exact").execute()
    safe = client.table("patches").select("id", count="exact").eq("sandbox_status", "SAFE").execute()
    needs_review = client.table("patches").select("id", count="exact").eq("sandbox_status", "NEEDS_REVIEW").execute()
    return {
        "total_scans": scans.count,
        "total_findings": findings.count,
        "total_patches": patches.count,
        "safe_patches": safe.count,
        "needs_review_patches": needs_review.count
    }
