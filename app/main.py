"""
app/main.py
FastAPI Server for DevSecOps CI/CD Exposure Manager (ShieldCI).
Provides REST APIs for on-demand & scheduled scanning across Repositories, Websites, and Databases.
"""

import os
import shutil
import tempfile
from contextlib import asynccontextmanager
from typing import List, Optional

# pyrefly: ignore [missing-import]
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Query, Response, Header, Depends, status, Request
# pyrefly: ignore [missing-import]
from fastapi.staticfiles import StaticFiles
# pyrefly: ignore [missing-import]
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, PlainTextResponse
# pyrefly: ignore [missing-import]
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.models.schemas import (
    ScanRequest, ScanResult, ScanHistorySummary, ScheduledScan,
    ScheduleCreateRequest, SeverityLevel, TargetCategory
)
from app.models.auth_schemas import (
    UserSignupRequest, UserLoginRequest, UserResponse, AuthTokenResponse
)
from app.core.security import (
    hash_password, verify_password, create_access_token, decode_access_token
)
from app.core.orchestrator import ExposureOrchestrator
from app.core.storage import storage
from app.core.scheduler import scheduler


orchestrator = ExposureOrchestrator()
scheduler.set_orchestrator(orchestrator)


async def get_current_user_optional(authorization: Optional[str] = Header(None)) -> Optional[UserResponse]:
    """Extracts authenticated user from Authorization Bearer token header if present."""
    if not authorization:
        return None
    claims = decode_access_token(authorization)
    if not claims or not claims.get("sub"):
        return None
    return storage.get_user_by_id(claims["sub"])


async def get_current_user(authorization: Optional[str] = Header(None)) -> UserResponse:
    """Dependency that mandates a valid Bearer authentication token."""
    user = await get_current_user_optional(authorization)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please sign in or create an account.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def get_client_ip(request: Optional[Request] = None) -> str:
    """Retrieves client IP address, respecting reverse proxy headers."""
    if not request:
        return "127.0.0.1"
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


def enforce_guest_quota(request: Request = None, current_user: Optional[UserResponse] = None):
    """Enforces 5 scans/day quota for unauthenticated guests. Logged-in users get unlimited scans."""
    user = current_user if isinstance(current_user, UserResponse) else None
    if user or request is None:
        return
    client_ip = get_client_ip(request)
    allowed, count, limit = storage.check_and_increment_guest_quota(client_ip, limit=5)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Guest daily scan quota exceeded ({count}/{limit} used). Please sign in or create an account for unlimited scans."
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Start background continuous scheduler only if not in serverless runtime
    if not settings.IS_SERVERLESS:
        scheduler.start()
    yield
    # Shutdown: Stop scheduler
    if not settings.IS_SERVERLESS:
        scheduler.stop()


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Universal Tri-Vector Posture Management: Audit Any Repository, Website, or Database At Any Time",
    version=settings.VERSION,
    debug=settings.DEBUG,
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = settings.STATIC_DIR
try:
    os.makedirs(STATIC_DIR, exist_ok=True)
except OSError:
    pass


@app.get("/", response_class=HTMLResponse)
@app.get("/api", response_class=HTMLResponse)
@app.get("/api/", response_class=HTMLResponse)
@app.get("/api/index", response_class=HTMLResponse)
@app.get("/api/index.py", response_class=HTMLResponse)
@app.get("/index.html", response_class=HTMLResponse)
@app.get("/api/index.html", response_class=HTMLResponse)
async def serve_dashboard():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.isfile(index_path):
        try:
            with open(index_path, "r", encoding="utf-8") as f:
                return HTMLResponse(content=f.read())
        except Exception:
            return FileResponse(index_path)
    return HTMLResponse("<h1>ShieldCI Exposure Manager API is running. UI file missing in /static/index.html</h1>")


@app.post("/api/scan", response_model=ScanResult)
async def trigger_scan(
    request: ScanRequest,
    http_req: Request = None,
    current_user: Optional[UserResponse] = Depends(get_current_user_optional)
):
    """
    Triggers a security exposure scan on any target:
    - Repository (Git URL or local path)
    - Website (HTTPS / HTTP URL)
    - Database (Connection URI or host:port)
    """
    user = current_user if isinstance(current_user, UserResponse) else None
    enforce_guest_quota(http_req, user)
    if user:
        request.user_email = user.email

    target = request.target or request.repo_url or request.target_path
    if not target or not target.strip():
        raise HTTPException(status_code=400, detail="Target URL, path, or connection string must be provided.")

    try:
        result = orchestrator.run_scan(request)
        return result
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except TimeoutError as e:
        raise HTTPException(status_code=408, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan Error: {str(e)}")


@app.post("/api/scan/website", response_model=ScanResult)
async def scan_website(
    url: str = Query(..., description="Target website or API URL (e.g. https://example.com)"),
    http_req: Request = None,
    fail_on_severity: SeverityLevel = Query(SeverityLevel.HIGH),
    max_allowed_pes: float = Query(60.0),
    current_user: Optional[UserResponse] = Depends(get_current_user_optional)
):
    """Dedicated endpoint to audit any live website or web API."""
    user = current_user if isinstance(current_user, UserResponse) else None
    enforce_guest_quota(http_req, user)
    if not url or not url.strip():
        raise HTTPException(status_code=400, detail="URL must be provided.")
    try:
        req = ScanRequest(
            target=url.strip(),
            target_type=TargetCategory.WEBSITE,
            fail_on_severity=fail_on_severity,
            max_allowed_pes=max_allowed_pes,
            user_email=user.email if user else None
        )
        return orchestrator.run_scan(req)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Website Scan Error: {str(e)}")


@app.post("/api/scan/database", response_model=ScanResult)
async def scan_database(
    target: str = Query(..., description="Database URI (e.g. postgresql://user:pass@host:5432/db) or host:port"),
    http_req: Request = None,
    engine: Optional[str] = Query(None, description="Database engine (postgres, mysql, redis, mongodb, elasticsearch, mssql)"),
    fail_on_severity: SeverityLevel = Query(SeverityLevel.HIGH),
    max_allowed_pes: float = Query(60.0),
    current_user: Optional[UserResponse] = Depends(get_current_user_optional)
):
    """Dedicated endpoint to audit any database posture and access security."""
    user = current_user if isinstance(current_user, UserResponse) else None
    enforce_guest_quota(http_req, user)
    if not target or not target.strip():
        raise HTTPException(status_code=400, detail="Database target must be provided.")
    try:
        req = ScanRequest(
            target=target.strip(),
            target_type=TargetCategory.DATABASE,
            db_type=engine,
            fail_on_severity=fail_on_severity,
            max_allowed_pes=max_allowed_pes,
            user_email=user.email if user else None
        )
        return orchestrator.run_scan(req)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database Scan Error: {str(e)}")


@app.post("/api/scan/upload", response_model=ScanResult)
async def upload_and_scan(
    file: UploadFile = File(...),
    http_req: Request = None,
    fail_on_severity: SeverityLevel = Form(SeverityLevel.HIGH),
    max_allowed_pes: float = Form(60.0),
    current_user: Optional[UserResponse] = Depends(get_current_user_optional)
):
    """
    Uploads a repository ZIP archive and runs full security audit.
    """
    user = current_user if isinstance(current_user, UserResponse) else None
    enforce_guest_quota(http_req, user)
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip archive files are supported.")

    temp_zip = tempfile.NamedTemporaryFile(
        delete=False,
        suffix=".zip",
        dir=settings.TEMP_SCAN_DIR
    )
    temp_zip_path = temp_zip.name

    try:
        max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
        total_size = 0
        
        while chunk := await file.read(1024 * 1024):
            total_size += len(chunk)
            if total_size > max_bytes:
                raise HTTPException(status_code=413, detail=f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_MB}MB.")
            temp_zip.write(chunk)
        temp_zip.close()

        req = ScanRequest(
            target_path=file.filename,
            target_type=TargetCategory.REPOSITORY,
            repo_name=os.path.splitext(file.filename)[0],
            fail_on_severity=fail_on_severity,
            max_allowed_pes=max_allowed_pes,
            user_email=user.email if user else None
        )

        result = orchestrator.run_scan(
            request=req,
            is_zip_upload=True,
            temp_zip_path=temp_zip_path
        )
        return result

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload Scan Error: {str(e)}")
    finally:
        if os.path.exists(temp_zip_path):
            try:
                os.remove(temp_zip_path)
            except Exception:
                pass


@app.get("/api/scans", response_model=List[ScanHistorySummary])
async def get_scan_history(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    target_type: Optional[str] = Query(None, pattern="^(repository|website|database)$"),
    current_user: Optional[UserResponse] = Depends(get_current_user_optional)
):
    """Retrieves list of past scans. Authenticated users see their own history; guests see guest scans."""
    actual_limit = limit.default if hasattr(limit, "default") else int(limit)
    actual_offset = offset.default if hasattr(offset, "default") else int(offset)
    actual_target_type = target_type.default if hasattr(target_type, "default") else target_type
    user = current_user if isinstance(current_user, UserResponse) else None
    user_email = user.email if user else None
    return storage.list_scans(limit=actual_limit, offset=actual_offset, target_type=actual_target_type, user_email=user_email)


@app.get("/api/scans/{scan_id}", response_model=ScanResult)
async def get_scan_by_id(scan_id: str):
    """Retrieves full details of a specific scan."""
    result = storage.get_scan(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan result not found.")
    return result


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str):
    """Deletes a scan record from history."""
    deleted = storage.delete_scan(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return {"status": "success", "message": f"Scan {scan_id} deleted"}


@app.get("/api/scans/{scan_id}/export")
async def export_scan(scan_id: str, format: str = Query("sarif", pattern="^(sarif|json|csv)$")):
    """
    Exports a scan report in SARIF 2.1.0, JSON, or CSV formats.
    """
    scan = storage.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan result not found.")

    clean_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in scan.repo_name)

    if format == "sarif":
        sarif_data = storage.export_sarif(scan)
        return JSONResponse(
            content=sarif_data,
            headers={"Content-Disposition": f'attachment; filename="shieldci_{clean_name}_{scan_id[:8]}.sarif"'}
        )
    elif format == "csv":
        csv_data = storage.export_csv(scan)
        return PlainTextResponse(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="shieldci_{clean_name}_{scan_id[:8]}.csv"'}
        )
    else:
        return JSONResponse(
            content=scan.model_dump(),
            headers={"Content-Disposition": f'attachment; filename="shieldci_{clean_name}_{scan_id[:8]}.json"'}
        )


@app.get("/api/scans/{scan_id}/patch")
async def download_scan_patch(scan_id: str):
    """
    Downloads the 1-click self-healing git unified patch (.patch) or server configuration.
    Applicable directly with `git apply shieldci-remediation.patch`.
    """
    scan = storage.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan result not found.")

    clean_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in scan.repo_name)
    patch_content = scan.unified_patch or (
        "# ShieldCI Automated Remediation\n"
        "# No code-level patches required for this asset.\n"
    )

    return PlainTextResponse(
        content=patch_content,
        media_type="text/x-diff",
        headers={"Content-Disposition": f'attachment; filename="shieldci_remediation_{clean_name}_{scan_id[:8]}.patch"'}
    )


@app.get("/api/scans/{scan_id}/attack-graph")
async def get_scan_attack_graph(scan_id: str):
    """
    Retrieves the correlated Attack Graph and Toxic Combinations for a scan.
    """
    scan = storage.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan result not found.")

    if scan.attack_graph:
        return scan.attack_graph
    
    # Fallback compute if older scan record
    toxic_combos, graph = orchestrator.correlator.correlate(
        findings=scan.findings,
        target_name=scan.repo_name
    )
    return graph


@app.post("/api/scan/triangulate", response_model=ScanResult)
async def scan_with_triangulation(
    request: ScanRequest,
    http_req: Request = None,
    current_user: Optional[UserResponse] = Depends(get_current_user_optional)
):
    """
    Automated Triangulation Scan:
    Inspects repository configs (compose, env, workflows) to auto-discover and probe
    live web endpoints and databases, linking all exposures into a unified attack graph.
    """
    user = current_user if isinstance(current_user, UserResponse) else None
    enforce_guest_quota(http_req, user)
    if user:
        request.user_email = user.email

    target = request.target or request.repo_url or request.target_path
    if not target or not target.strip():
        raise HTTPException(status_code=400, detail="Target repository URL or path is required.")

    request.auto_triangulate = True
    return orchestrator.run_scan(request)


# Scheduled Scans Endpoints (Restricted to Authenticated Users)
@app.get("/api/schedules", response_model=List[ScheduledScan])
async def list_schedules(current_user: UserResponse = Depends(get_current_user)):
    """Lists continuous automated scheduled scans for the authenticated user."""
    user = current_user if isinstance(current_user, UserResponse) else None
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required. Please sign in.")
    return storage.get_schedules(user_email=user.email)


@app.post("/api/schedules", response_model=ScheduledScan)
async def create_schedule(
    req: ScheduleCreateRequest,
    current_user: UserResponse = Depends(get_current_user)
):
    """Creates a new recurring automated scan. Requires an authenticated account."""
    user = current_user if isinstance(current_user, UserResponse) else None
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required. Please sign in.")

    if not req.target or not req.target.strip():
        raise HTTPException(status_code=400, detail="Target URL, path, or connection string is required.")

    schedule = scheduler.create_schedule(
        target=req.target.strip(),
        target_type=req.target_type,
        branch=req.branch,
        interval_minutes=req.interval_minutes,
        fail_on_severity=req.fail_on_severity,
        max_allowed_pes=req.max_allowed_pes,
        user_email=user.email
    )
    return schedule


@app.post("/api/schedules/{schedule_id}/run")
async def trigger_schedule_now(
    schedule_id: str,
    current_user: UserResponse = Depends(get_current_user)
):
    """Triggers an immediate execution of a scheduled scan in the background. Requires authentication."""
    user = current_user if isinstance(current_user, UserResponse) else None
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required. Please sign in.")

    scheduler.run_scheduled_job(schedule_id)
    return {"status": "triggered", "schedule_id": schedule_id}


@app.delete("/api/schedules/{schedule_id}")
async def delete_schedule(
    schedule_id: str,
    current_user: UserResponse = Depends(get_current_user)
):
    """Deletes a scheduled scan. Requires authentication."""
    user = current_user if isinstance(current_user, UserResponse) else None
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required. Please sign in.")

    deleted = scheduler.delete_schedule(schedule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Schedule not found.")
    return {"status": "success", "message": f"Schedule {schedule_id} removed"}


@app.get("/api/auth/quota")
async def get_scan_quota(
    http_req: Request = None,
    current_user: Optional[UserResponse] = Depends(get_current_user_optional)
):
    """
    Returns scan quota status for the current client:
    - Logged-in users receive unlimited scans.
    - Unauthenticated guests receive up to 5 scans per day.
    """
    user = current_user if isinstance(current_user, UserResponse) else None
    if user:
        return {
            "authenticated": True,
            "unlimited": True,
            "scans_used": 0,
            "max_scans": -1,
            "remaining_scans": -1,
            "user_email": user.email
        }
    client_ip = get_client_ip(http_req)
    used, limit = storage.get_guest_quota(client_ip, limit=5)
    return {
        "authenticated": False,
        "unlimited": False,
        "scans_used": used,
        "max_scans": limit,
        "remaining_scans": max(0, limit - used),
        "user_email": None
    }


# ==============================================================
# Authentication & User Management Endpoints
# ==============================================================
@app.post("/api/auth/signup", response_model=AuthTokenResponse, status_code=status.HTTP_201_CREATED)
async def signup(req: UserSignupRequest):
    """
    Registers a new user account with email and password.
    """
    existing = storage.get_user_by_email(req.email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists. Please sign in."
        )

    pw_hash, salt = hash_password(req.password)
    user = storage.create_user(
        email=req.email,
        password_hash=pw_hash,
        salt=salt,
        full_name=req.full_name,
        organization=req.organization
    )
    token = create_access_token(user_id=user.id, email=user.email)
    return AuthTokenResponse(
        access_token=token,
        token_type="bearer",
        user=user
    )


@app.post("/api/auth/login", response_model=AuthTokenResponse)
async def login(req: UserLoginRequest):
    """
    Authenticates a user with email and password, returning a cryptographically signed access token.
    """
    user_record = storage.get_user_by_email(req.email)
    if not user_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not verify_password(req.password, user_record["password_hash"], user_record["salt"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    storage.update_last_login(user_record["id"])
    user = storage.get_user_by_id(user_record["id"])
    if not user:
        raise HTTPException(status_code=500, detail="User lookup failed.")

    token = create_access_token(user_id=user.id, email=user.email)
    return AuthTokenResponse(
        access_token=token,
        token_type="bearer",
        user=user
    )


@app.get("/api/auth/me", response_model=UserResponse)
async def get_my_profile(current_user: UserResponse = Depends(get_current_user)):
    """
    Retrieves the currently authenticated user's profile from the session token.
    """
    return current_user


@app.post("/api/auth/logout")
async def logout():
    """
    Logs out the current user session.
    """
    return {"status": "success", "message": "Successfully logged out."}


# Webhook CI/CD Integration
@app.post("/api/webhook/github")
async def github_webhook(payload: dict):
    """
    Webhook receiver for GitHub push/PR events to trigger scans automatically at any time.
    """
    repo_url = payload.get("repository", {}).get("clone_url") or payload.get("repository", {}).get("html_url")
    if not repo_url:
        return {"status": "ignored", "reason": "No repository URL found in webhook payload."}

    ref = payload.get("ref", "")
    branch = ref.split("/")[-1] if "/" in ref else None

    req = ScanRequest(
        repo_url=repo_url,
        branch=branch,
        target_type=TargetCategory.REPOSITORY,
        repo_name=payload.get("repository", {}).get("name")
    )
    
    try:
        result = orchestrator.run_scan(req)
        return {
            "status": "completed",
            "scan_id": result.scan_id,
            "policy_passed": result.summary.policy_passed,
            "pes": result.summary.pipeline_exposure_score
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.APP_ENV,
        "features": {
            "repository_scanner": True,
            "website_scanner": True,
            "database_scanner": True,
            "attack_path_correlator": True,
            "toxic_combinations": True,
            "auto_discovery_triangulation": True,
            "autonomous_self_healing": True,
            "git_clone": True,
            "zip_upload": True,
            "scheduling": True,
            "history": True,
            "sarif_export": True,
            "user_authentication": True
        }
    }


if __name__ == "__main__":
    # pyrefly: ignore [missing-import]
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
