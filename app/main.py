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
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Query, Response
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
from app.core.orchestrator import ExposureOrchestrator
from app.core.storage import storage
from app.core.scheduler import scheduler


orchestrator = ExposureOrchestrator()
scheduler.set_orchestrator(orchestrator)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Start background scheduler
    scheduler.start()
    yield
    # Shutdown: Stop scheduler
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
os.makedirs(STATIC_DIR, exist_ok=True)


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    return HTMLResponse("<h1>ShieldCI Exposure Manager API is running. UI file missing in /static/index.html</h1>")


@app.post("/api/scan", response_model=ScanResult)
async def trigger_scan(request: ScanRequest):
    """
    Triggers a security exposure scan on any target:
    - Repository (Git URL or local path)
    - Website (HTTPS / HTTP URL)
    - Database (Connection URI or host:port)
    """
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
    fail_on_severity: SeverityLevel = Query(SeverityLevel.HIGH),
    max_allowed_pes: float = Query(60.0)
):
    """Dedicated endpoint to audit any live website or web API."""
    if not url or not url.strip():
        raise HTTPException(status_code=400, detail="URL must be provided.")
    try:
        req = ScanRequest(
            target=url.strip(),
            target_type=TargetCategory.WEBSITE,
            fail_on_severity=fail_on_severity,
            max_allowed_pes=max_allowed_pes
        )
        return orchestrator.run_scan(req)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Website Scan Error: {str(e)}")


@app.post("/api/scan/database", response_model=ScanResult)
async def scan_database(
    target: str = Query(..., description="Database URI (e.g. postgresql://user:pass@host:5432/db) or host:port"),
    engine: Optional[str] = Query(None, description="Database engine (postgres, mysql, redis, mongodb, elasticsearch, mssql)"),
    fail_on_severity: SeverityLevel = Query(SeverityLevel.HIGH),
    max_allowed_pes: float = Query(60.0)
):
    """Dedicated endpoint to audit any database posture and access security."""
    if not target or not target.strip():
        raise HTTPException(status_code=400, detail="Database target must be provided.")
    try:
        req = ScanRequest(
            target=target.strip(),
            target_type=TargetCategory.DATABASE,
            db_type=engine,
            fail_on_severity=fail_on_severity,
            max_allowed_pes=max_allowed_pes
        )
        return orchestrator.run_scan(req)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database Scan Error: {str(e)}")


@app.post("/api/scan/upload", response_model=ScanResult)
async def upload_and_scan(
    file: UploadFile = File(...),
    fail_on_severity: SeverityLevel = Form(SeverityLevel.HIGH),
    max_allowed_pes: float = Form(60.0)
):
    """
    Uploads a repository ZIP archive and runs full security audit.
    """
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
            max_allowed_pes=max_allowed_pes
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
    target_type: Optional[str] = Query(None, regex="^(repository|website|database)$")
):
    """Retrieves list of past scans across all asset types."""
    return storage.list_scans(limit=limit, offset=offset, target_type=target_type)


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
async def export_scan(scan_id: str, format: str = Query("sarif", regex="^(sarif|json|csv)$")):
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


# Scheduled Scans Endpoints
@app.get("/api/schedules", response_model=List[ScheduledScan])
async def list_schedules():
    """Lists all automated scheduled scans."""
    return storage.get_schedules()


@app.post("/api/schedules", response_model=ScheduledScan)
async def create_schedule(req: ScheduleCreateRequest):
    """Creates a new recurring automated scan for any repository, website, or database."""
    if not req.target or not req.target.strip():
        raise HTTPException(status_code=400, detail="Target URL, path, or connection string is required.")

    schedule = scheduler.create_schedule(
        target=req.target.strip(),
        target_type=req.target_type,
        branch=req.branch,
        interval_minutes=req.interval_minutes,
        fail_on_severity=req.fail_on_severity,
        max_allowed_pes=req.max_allowed_pes
    )
    return schedule


@app.post("/api/schedules/{schedule_id}/run")
async def trigger_schedule_now(schedule_id: str):
    """Triggers an immediate execution of a scheduled scan in the background."""
    scheduler.run_scheduled_job(schedule_id)
    return {"status": "triggered", "schedule_id": schedule_id}


@app.delete("/api/schedules/{schedule_id}")
async def delete_schedule(schedule_id: str):
    """Deletes a scheduled scan."""
    deleted = scheduler.delete_schedule(schedule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Schedule not found.")
    return {"status": "success", "message": f"Schedule {schedule_id} removed"}


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
            "git_clone": True,
            "zip_upload": True,
            "scheduling": True,
            "history": True,
            "sarif_export": True
        }
    }


if __name__ == "__main__":
    # pyrefly: ignore [missing-import]
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
