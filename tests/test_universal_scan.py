"""
tests/test_universal_scan.py
Comprehensive test suite verifying Tri-Vector Exposure Defense:
1. Repositories (local, remote Git URLs, ZIP archives)
2. Live Websites & Web APIs (SSL/TLS, security headers, CORS, sensitive paths)
3. Databases (PostgreSQL, MySQL, Redis, MongoDB, Elasticsearch posture & credentials)
4. SQLite persistent history, continuous background scheduling, and multi-format exports.
"""

import os
import sys
import zipfile
import tempfile
from datetime import datetime

# Ensure root dir is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
from app.config import settings
from app.models.schemas import ScanRequest, SeverityLevel, SourceType, TargetCategory
from app.core.orchestrator import ExposureOrchestrator
from app.core.storage import storage
from app.core.scheduler import scheduler
from app.core.repo_fetcher import RepoFetcher
from app.scanners.web_scanner import WebsiteScanner
from app.scanners.database_scanner import DatabaseScanner
from app.core.auto_discovery import AutoDiscoveryEngine
from app.core.correlator import AttackCorrelator
from app.core.remediator import AutoRemediator
from app.main import download_scan_patch, get_scan_attack_graph, scan_with_triangulation, health_check


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
    print("Testing local repo scan & storage...")
    orchestrator = ExposureOrchestrator()
    req = ScanRequest(
        target_path="./sample_vulnerable_repo",
        fail_on_severity=SeverityLevel.HIGH,
        max_allowed_pes=60.0
    )
    result = orchestrator.run_scan(req)
    assert result.scan_id is not None
    assert result.repo_name == "sample_vulnerable_repo"
    assert result.target_type == TargetCategory.REPOSITORY
    assert result.summary.total_findings >= 1
    assert result.summary.pipeline_exposure_score > 0
    assert result.source_type == SourceType.LOCAL

    # Check persistence in SQLite
    saved_scan = storage.get_scan(result.scan_id)
    assert saved_scan is not None
    assert saved_scan.scan_id == result.scan_id
    assert saved_scan.summary.total_findings == result.summary.total_findings
    assert saved_scan.target_type == TargetCategory.REPOSITORY

    # Check scan history listing
    history = storage.list_scans(limit=10)
    assert len(history) >= 1
    assert any(h.scan_id == result.scan_id for h in history)
    print("[OK] Local repo scan & storage passed")
    return result


def test_zip_upload_scan():
    print("Testing ZIP archive repo scan...")
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
        assert result.target_type == TargetCategory.REPOSITORY
        assert result.summary.total_findings >= 3
        assert result.summary.critical_count >= 1
        print("[OK] ZIP archive scan passed")
    finally:
        if os.path.exists(zip_path):
            os.remove(zip_path)


def test_website_scanner():
    print("Testing Website & API Scanner...")
    orchestrator = ExposureOrchestrator()
    req = ScanRequest(
        target="https://example.com",
        target_type=TargetCategory.WEBSITE,
        fail_on_severity=SeverityLevel.HIGH,
        max_allowed_pes=60.0
    )
    result = orchestrator.run_scan(req)
    assert result.scan_id is not None
    assert result.target_type == TargetCategory.WEBSITE
    assert result.source_type == SourceType.WEB
    assert "example.com" in result.repo_name
    assert result.metadata is not None
    assert "status_code" in result.metadata
    print(f"[OK] Website scan passed: {len(result.findings)} exposures identified in example.com")
    return result


def test_database_scanner():
    print("Testing Database Posture Scanner...")
    orchestrator = ExposureOrchestrator()
    
    # Audit a database URI with exposed default credentials and unencrypted connection
    db_target = "postgresql://postgres:postgres@127.0.0.1:5432/appdb"
    req = ScanRequest(
        target=db_target,
        target_type=TargetCategory.DATABASE,
        fail_on_severity=SeverityLevel.HIGH,
        max_allowed_pes=60.0
    )
    result = orchestrator.run_scan(req)
    assert result.scan_id is not None
    assert result.target_type == TargetCategory.DATABASE
    assert result.source_type == SourceType.DATABASE
    assert "POSTGRESQL" in result.repo_name.upper()
    assert result.summary.total_findings >= 2
    # Verify masked credentials in target_path
    assert "postgres:****@" in result.target_path
    assert any("Default Database Password" in f.title or "Database Credentials Exposed" in f.title for f in result.findings)
    print(f"[OK] Database scan passed: {len(result.findings)} exposures identified in test DB target")
    return result


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
    assert len(csv_text.splitlines()) > 1

    # JSON export
    raw_json = scan_result.model_dump_json()
    assert scan_result.scan_id in raw_json
    print("[OK] SARIF, JSON, CSV exports passed")


def test_tri_vector_schedules():
    print("Testing Tri-Vector background scheduling...")
    orchestrator = ExposureOrchestrator()
    scheduler.set_orchestrator(orchestrator)

    # 1. Schedule for Repository
    sched_repo = scheduler.create_schedule(
        target="./sample_vulnerable_repo",
        target_type=TargetCategory.REPOSITORY,
        interval_minutes=30
    )
    assert sched_repo.target_type == TargetCategory.REPOSITORY

    # 2. Schedule for Website
    sched_web = scheduler.create_schedule(
        target="https://example.com",
        target_type=TargetCategory.WEBSITE,
        interval_minutes=60
    )
    assert sched_web.target_type == TargetCategory.WEBSITE

    # 3. Schedule for Database
    sched_db = scheduler.create_schedule(
        target="redis://127.0.0.1:6379",
        target_type=TargetCategory.DATABASE,
        interval_minutes=15
    )
    assert sched_db.target_type == TargetCategory.DATABASE

    # Run scheduled database job
    scheduler.run_scheduled_job(sched_db.id)
    schedules = storage.get_schedules()
    matched = next((s for s in schedules if s.id == sched_db.id), None)
    assert matched is not None
    assert matched.last_run_at is not None

    # Cleanup test schedules
    scheduler.delete_schedule(sched_repo.id)
    scheduler.delete_schedule(sched_web.id)
    scheduler.delete_schedule(sched_db.id)
    print("[OK] Tri-vector scheduler management passed")


def test_auto_discovery_engine():
    print("Testing Auto-Discovery Triangulation Engine...")
    engine = AutoDiscoveryEngine()
    disc = engine.discover("./sample_vulnerable_repo")
    assert disc is not None
    assert len(disc.discovered_services) >= 2, f"Expected services in compose, got: {disc.discovered_services}"
    service_names = [s.name for s in disc.discovered_services]
    assert "web" in service_names
    assert "db" in service_names
    assert any("5432" in s for s in disc.discovered_db_targets)
    assert any("staging.internal-api.io" in w for w in disc.discovered_web_targets)
    assert "docker-compose.yml" in disc.source_files
    print(f"[OK] Auto-Discovery passed: detected {len(disc.discovered_services)} services, {len(disc.discovered_web_targets)} web targets, {len(disc.discovered_db_targets)} DB targets")
    return disc


def test_attack_correlator_and_toxic_combinations(repo_res):
    print("Testing Attack Path Correlator & Toxic Combinations...")
    assert repo_res.toxic_combinations is not None
    assert len(repo_res.toxic_combinations) >= 1, "Expected at least 1 toxic combination"
    
    tc = repo_res.toxic_combinations[0]
    assert tc.title is not None
    assert len(tc.exploit_chain) >= 2
    assert tc.impact is not None
    assert tc.remediation_advice is not None

    # Verify attack graph
    assert repo_res.attack_graph is not None
    assert len(repo_res.attack_graph.nodes) >= 3
    assert len(repo_res.attack_graph.edges) >= 2
    assert repo_res.attack_graph.exploitability_index > 0
    print(f"[OK] Attack Correlator passed: {len(repo_res.toxic_combinations)} toxic combinations, {len(repo_res.attack_graph.nodes)} graph nodes, exploitability={repo_res.attack_graph.exploitability_index}%")


def test_remediator_patch_generation(repo_res):
    print("Testing 1-Click Self-Healing & Unified Patch Generator...")
    assert repo_res.unified_patch is not None
    assert len(repo_res.unified_patch) > 50
    assert "--- a/" in repo_res.unified_patch or "+++ b/" in repo_res.unified_patch
    assert "USER 10001" in repo_res.unified_patch or "pull_request" in repo_res.unified_patch

    # Test web security config generator
    configs = AutoRemediator.generate_web_security_configs(["Strict-Transport-Security", "Content-Security-Policy"])
    assert "nginx" in configs and "Strict-Transport-Security" in configs["nginx"]
    assert "caddy" in configs and "Content-Security-Policy" in configs["caddy"]
    print("[OK] Remediator Patch Generator passed")


def test_api_endpoints_patch_and_graph(repo_res):
    print("Testing API endpoints for Patch download, Attack Graph, and Triangulation...")
    
    # 1. Patch Download
    patch_resp = asyncio.run(download_scan_patch(repo_res.scan_id))
    assert patch_resp.status_code == 200
    assert "text/x-diff" in patch_resp.media_type
    assert len(patch_resp.body) > 0

    # 2. Attack Graph API
    graph = asyncio.run(get_scan_attack_graph(repo_res.scan_id))
    assert len(graph.nodes) >= 3
    assert len(graph.edges) >= 2
    assert graph.exploitability_index > 0

    # 3. Triangulate Scan API
    tri_req = ScanRequest(target="./sample_vulnerable_repo", target_type=TargetCategory.REPOSITORY)
    tri_res = asyncio.run(scan_with_triangulation(tri_req))
    assert tri_res.auto_discovery is not None
    assert tri_res.toxic_combinations is not None
    assert tri_res.attack_graph is not None
    assert tri_res.unified_patch is not None

    # 4. Health Check Features
    health = asyncio.run(health_check())
    features = health.get("features", {})
    assert features.get("attack_path_correlator") is True
    assert features.get("auto_discovery_triangulation") is True
    assert features.get("autonomous_self_healing") is True

    print("[OK] API endpoints (patch, attack-graph, triangulate, health) verified successfully")


if __name__ == "__main__":
    print("==================================================")
    print(" ShieldCI Tri-Vector Universal Scan Verification ")
    print(" Repositories | Websites | Databases ")
    print("==================================================")
    test_repo_fetcher_url_detection()
    repo_res = test_local_scan_and_storage()
    test_zip_upload_scan()
    web_res = test_website_scanner()
    db_res = test_database_scanner()
    test_exports_sarif_json_csv(web_res)
    test_tri_vector_schedules()
    test_auto_discovery_engine()
    test_attack_correlator_and_toxic_combinations(repo_res)
    test_remediator_patch_generation(repo_res)
    test_api_endpoints_patch_and_graph(repo_res)
    print("==================================================")
    print(" ALL NEXT-GEN SHIELDCI TESTS COMPLETED SUCCESSFULLY! ")
    print("==================================================")

