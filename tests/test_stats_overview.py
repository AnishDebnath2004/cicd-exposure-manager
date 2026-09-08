"""
tests/test_stats_overview.py
Tests for the /api/stats/overview endpoint and live database-backed hero metrics.
"""

import asyncio
import uuid
from datetime import datetime, timezone
import pytest

from app.main import get_overview_stats
from app.core.storage import storage
from app.models.schemas import ScanResult, ScanSummary, SeverityLevel, SourceType, TargetCategory


def test_get_overview_stats_endpoint():
    """Verify that get_overview_stats returns valid schema and defaults."""
    data = asyncio.run(get_overview_stats())

    assert "commits_and_assets" in data
    assert "entropy_precision" in data
    assert "agentless_ephemeral" in data
    assert "avg_latency" in data
    assert "total_scans" in data
    assert "raw_assets_count" in data
    assert data["agentless_ephemeral"] == "100%"
    assert "%" in data["entropy_precision"]


def test_overview_stats_reacts_to_new_scans():
    """Verify that saving new scans to storage updates aggregate counts and latency."""
    initial_stats = storage.get_overview_stats()
    initial_scans = initial_stats["total_scans"]
    initial_files = initial_stats["raw_assets_count"]

    # Create a synthetic scan result
    scan_id = f"test-stats-{uuid.uuid4().hex[:8]}"
    mock_scan = ScanResult(
        scan_id=scan_id,
        target_path="https://github.com/example/repo",
        repo_name="example-repo",
        source_type=SourceType.LOCAL,
        target_type=TargetCategory.REPOSITORY,
        timestamp=datetime.now(timezone.utc),
        summary=ScanSummary(
            total_findings=3,
            critical_count=1,
            high_count=1,
            medium_count=1,
            low_count=0,
            info_count=0,
            pipeline_exposure_score=45.0,
            risk_grade="C",
            policy_passed=False,
            scan_duration_seconds=1.85,
            scanned_files_count=120
        ),
        findings=[]
    )

    try:
        storage.save_scan(mock_scan)

        updated_stats = storage.get_overview_stats()
        assert updated_stats["total_scans"] == initial_scans + 1
        assert updated_stats["raw_assets_count"] == initial_files + 120
        assert updated_stats["commits_and_assets"] != "0"

        # Also verify via API endpoint handler
        api_data = asyncio.run(get_overview_stats())
        assert api_data["total_scans"] == initial_scans + 1
        assert "<" in api_data["avg_latency"] or "s" in api_data["avg_latency"]

    finally:
        # Clean up the test scan
        storage.delete_scan(scan_id)
        cleaned_stats = storage.get_overview_stats()
        assert cleaned_stats["total_scans"] == initial_scans
