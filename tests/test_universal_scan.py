"""
tests/test_universal_scan.py
Comprehensive test suite verifying local, remote Git, ZIP upload, SQLite storage, SARIF export, and scheduler.
"""

import os
import sys
import zipfile
import tempfile
from datetime import datetime

# Ensure root dir is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import settings
from app.models.schemas import ScanRequest, SeverityLevel, SourceType
from app.core.orchestrator import ExposureOrchestrator
from app.core.storage import storage
from app.core.scheduler import scheduler
from app.core.repo_fetcher import RepoFetcher


def test_repo_fetcher_url_detection():
    print("Testing RepoFetcher URL detection...")
    assert RepoFetcher.is_git_url("https://github.com/octocat/Hello-World")
    assert RepoFetcher.is_git_url("http://gitlab.com/group/repo.git")
    assert RepoFetcher.is_git_url("git@github.com:owner/repo.git")
    assert RepoFetcher.is_git_url("owner/repo")
    assert not RepoFetcher.is_git_url("./sample_vulnerable_repo")
    assert not RepoFetcher.is_git_url("C:\\some\\folder")

    assert RepoFetcher.normalize_git_url("owner/repo") == "https://github.com/owner/repo.git"
    assert RepoFetcher.extract_repo_name("https://github.com/owner/super-repo.git") == "super-repo"
    print("[OK] RepoFetcher URL detection passed")


def test_local_scan_and_storage():
    print("Testing local scan & storage...")
    orchestrator = ExposureOrchestrator()
    req = ScanRequest(
        target_path="./sample_vulnerable_repo",
        fail_on_severity=SeverityLevel.HIGH,
        max_allowed_pes=60.0
    )
    result = orchestrator.run_scan(req)
    assert result.scan_id is not None
    assert result.repo_name == "sample_vulnerable_repo"
    assert result.summary.total_findings >= 1
    assert result.summary.pipeline_exposure_score > 0
    assert result.source_type == SourceType.LOCAL

    # Check persistence in SQLite
    saved_scan = storage.get_scan(result.scan_id)
    assert saved_scan is not None
    assert saved_scan.scan_id == result.scan_id
    assert saved_scan.summary.total_findings == result.summary.total_findings

    # Check scan history listing
    history = storage.list_scans(limit=10)
    assert len(history) >= 1
    assert any(h.scan_id == result.scan_id for h in history)
    print("[OK] Local scan & storage passed")
    return result


def test_zip_upload_scan():
    print("Testing ZIP archive scan...")
    orchestrator = ExposureOrchestrator()
    
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
        zip_path = tf.name

    try:
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("Dockerfile", "FROM python:latest\nEXPOSE 22\n")
            zf.writestr("requirements.txt", "requests==2.31.0\n")
            zf.writestr("secrets.py", "AWS_SECRET = 'AKIA1234567890ABCDEF'\n")

        req = ScanRequest(
            target_path="mock_archive.zip",
            repo_name="mock_archive"
        )
        result = orchestrator.run_scan(
            request=req,
            is_zip_upload=True,
            temp_zip_path=zip_path
        )
        assert result.source_type == SourceType.UPLOAD
        assert result.summary.total_findings >= 3
        assert result.summary.critical_count >= 1
        print("[OK] ZIP archive scan passed")
    finally:
        if os.path.exists(zip_path):
            os.remove(zip_path)


def test_exports_sarif_json_csv(scan_result):
    print("Testing SARIF, JSON, and CSV exports...")
    # SARIF Export
    sarif = storage.export_sarif(scan_result)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) > 0
    assert len(sarif["runs"][0]["results"]) == len(scan_result.findings)

    # CSV Export
    csv_text = storage.export_csv(scan_result)
    assert "Severity,Category,Title" in csv_text
    assert "sample_vulnerable_repo" in csv_text or len(csv_text.splitlines()) > 1

    # JSON export
    raw_json = scan_result.model_dump_json()
    assert scan_result.scan_id in raw_json
    print("[OK] SARIF, JSON, CSV exports passed")


def test_schedule_management():
    print("Testing background scheduler...")
    orchestrator = ExposureOrchestrator()
    scheduler.set_orchestrator(orchestrator)

    sched = scheduler.create_schedule(
        target="./sample_vulnerable_repo",
        branch="main",
        interval_minutes=15,
        fail_on_severity=SeverityLevel.HIGH,
        max_allowed_pes=60.0
    )
    assert sched.id is not None
    assert sched.interval_minutes == 15

    # Run scheduled job manually
    scheduler.run_scheduled_job(sched.id)
    
    schedules = storage.get_schedules()
    matched = next((s for s in schedules if s.id == sched.id), None)
    assert matched is not None
    assert matched.last_run_at is not None
    assert matched.last_status in ["PASSED", "FAILED"]

    # Delete schedule
    deleted = scheduler.delete_schedule(sched.id)
    assert deleted is True
    print("[OK] Scheduler management passed")


if __name__ == "__main__":
    print("========================================")
    print(" ShieldCI Universal Scan Verification ")
    print("========================================")
    test_repo_fetcher_url_detection()
    scan_res = test_local_scan_and_storage()
    test_zip_upload_scan()
    test_exports_sarif_json_csv(scan_res)
    test_schedule_management()
    print("========================================")
    print(" ALL TESTS COMPLETED SUCCESSFULLY! ")
    print("========================================")
