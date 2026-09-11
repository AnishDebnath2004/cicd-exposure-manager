"""
tests/test_pdf_export.py
Unit tests verifying executive PDF audit report generation and API endpoints.
"""

import os
import sys
import asyncio
from datetime import datetime

# Ensure root dir is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from app.main import export_scan, download_scan_pdf
from app.core.storage import storage
from app.models.schemas import (
    ScanResult,
    ScanSummary,
    Finding,
    FindingCategory,
    SeverityLevel,
    TargetCategory,
    SourceType,
    ToxicCombination,
)


@pytest.fixture
def sample_scan():
    summary = ScanSummary(
        total_findings=2,
        critical_count=1,
        high_count=1,
        medium_count=0,
        low_count=0,
        info_count=0,
        pipeline_exposure_score=78.5,
        risk_grade="F",
        policy_passed=False,
        scan_duration_seconds=2.45,
        scanned_files_count=18,
    )
    findings = [
        Finding(
            id="FINDING-001",
            category=FindingCategory.SECRET_EXPOSURE,
            severity=SeverityLevel.CRITICAL,
            title="Exposed GitHub Personal Access Token",
            description="A raw GitHub personal access token was discovered hardcoded in CI workflow file.",
            file_path=".github/workflows/deploy.yml",
            line_number=34,
            snippet="GITHUB_TOKEN: ghp_1234567890abcdef1234567890abcdef123456",
            remediation_advice="Revoke the exposed token and migrate to GitHub Encrypted Secrets.",
            auto_fixable=True,
            fix_patch="- GITHUB_TOKEN: ghp_1234...\n+ GITHUB_TOKEN: ${{ secrets.PROD_GITHUB_TOKEN }}",
        ),
        Finding(
            id="FINDING-002",
            category=FindingCategory.PIPELINE_MISCONFIG,
            severity=SeverityLevel.HIGH,
            title="Unpinned Third-Party GitHub Action",
            description="Workflow references mutable tag '@v1' instead of immutable commit SHA-1 hash.",
            file_path=".github/workflows/build.yml",
            line_number=12,
            snippet="uses: actions/checkout@v1",
            remediation_advice="Pin action by full 40-character commit hash to guard against tag-jacking supply chain attacks.",
        ),
    ]
    toxic = [
        ToxicCombination(
            id="TOXIC-001",
            title="Hardcoded Secret + Unpinned CI Runner",
            severity=SeverityLevel.CRITICAL,
            likelihood="High",
            exploit_chain=[
                "Unpinned GitHub Action compromised",
                "Arbitrary code execution on CI runner",
                "Extraction of hardcoded production credentials",
            ],
            impact="Full cloud infrastructure compromise via stolen deployment token.",
            remediation_advice="Enforce action commit pinning and rotate credentials.",
        )
    ]
    scan = ScanResult(
        scan_id="test_scan_pdf_001",
        target_path="./sample_vulnerable_repo",
        repo_name="sample_vulnerable_repo",
        repo_url="https://github.com/org/sample_vulnerable_repo",
        branch="main",
        source_type=SourceType.LOCAL,
        target_type=TargetCategory.REPOSITORY,
        timestamp=datetime.utcnow(),
        summary=summary,
        findings=findings,
        toxic_combinations=toxic,
        unified_patch="--- .github/workflows/deploy.yml\n+++ .github/workflows/deploy.yml\n@@ -34,1 +34,1 @@\n- GITHUB_TOKEN: ghp_1234\n+ GITHUB_TOKEN: ${{ secrets.TOKEN }}",
    )
    return scan


def test_pdf_exporter_generates_valid_pdf(sample_scan):
    """Verifies that export_pdf returns non-empty bytes conforming to PDF spec."""
    pdf_bytes = storage.export_pdf(sample_scan)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 2000
    # Every valid PDF file begins with %PDF-
    assert pdf_bytes.startswith(b"%PDF-")


def test_pdf_exporter_clean_scan():
    """Verifies that PDF export operates correctly on clean assets with zero findings."""
    clean_summary = ScanSummary(
        total_findings=0,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        info_count=0,
        pipeline_exposure_score=4.0,
        risk_grade="A+",
        policy_passed=True,
        scan_duration_seconds=0.85,
        scanned_files_count=12,
    )
    clean_scan = ScanResult(
        scan_id="clean_scan_002",
        target_path="https://example.com",
        repo_name="Example Corp Web",
        target_type=TargetCategory.WEBSITE,
        summary=clean_summary,
        findings=[],
        toxic_combinations=[],
    )
    pdf_bytes = storage.export_pdf(clean_scan)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF-")


def test_pdf_export_api_endpoints(sample_scan):
    """Verifies the export_scan and download_scan_pdf async endpoints."""
    # Save scan to database storage
    storage.save_scan(sample_scan)

    # 1. Test export_scan with format="pdf"
    resp = asyncio.run(export_scan(scan_id=sample_scan.scan_id, format="pdf"))
    assert resp.status_code == 200
    assert resp.media_type == "application/pdf"
    assert "attachment" in resp.headers["Content-Disposition"]
    assert sample_scan.scan_id[:8] in resp.headers["Content-Disposition"]
    assert resp.body.startswith(b"%PDF-")

    # 2. Test dedicated alias download_scan_pdf
    resp_alias = asyncio.run(download_scan_pdf(scan_id=sample_scan.scan_id))
    assert resp_alias.status_code == 200
    assert resp_alias.media_type == "application/pdf"
    assert resp_alias.body.startswith(b"%PDF-")
