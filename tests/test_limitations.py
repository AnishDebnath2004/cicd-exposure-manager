"""
tests/test_limitations.py
Verification suite for Guest Limitations:
1. Restricting Continuous Schedules to Authenticated Users (401 for guests)
2. Daily Guest Scan Quota (5 scans per IP/day, 429 upon exceeding)
3. Unlimited Scans for Authenticated Users
4. Private Per-User Scan History Scoping
"""

import os
import sys
import asyncio

# Ensure root dir is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import HTTPException
from app.models.schemas import ScanRequest, ScheduleCreateRequest, SeverityLevel, TargetCategory
from app.models.auth_schemas import UserSignupRequest
from app.core.storage import storage
from app.main import (
    trigger_scan, list_schedules, create_schedule, get_scan_history,
    signup, get_scan_quota
)


class DummyRequest:
    """Mock FastAPI Request object for testing."""
    def __init__(self, client_ip="192.168.1.100", headers=None):
        self.headers = headers or {}
        self.client = type("Client", (), {"host": client_ip})()


def test_continuous_schedules_require_auth():
    print("Testing Continuous Schedules authentication enforcement...")
    # 1. Unauthenticated call to list_schedules or create_schedule should fail
    # Calling create_schedule directly without current_user dependency injection
    req = ScheduleCreateRequest(
        target="https://example.com",
        target_type=TargetCategory.WEBSITE,
        interval_minutes=60
    )

    # In FastAPI, Depends(get_current_user) blocks guests with 401.
    # When creating user:
    user_email = f"sched_test_{os.urandom(4).hex()}@shieldci.io"
    auth_resp = asyncio.run(signup(UserSignupRequest(
        email=user_email,
        password="TestPassword123!",
        full_name="Schedule Admin"
    )))
    user = auth_resp.user

    # Authenticated user can create schedule
    created_sched = asyncio.run(create_schedule(req, current_user=user))
    assert created_sched.id is not None
    assert created_sched.user_email == user_email.lower()

    # Authenticated user can list their schedules
    user_schedules = asyncio.run(list_schedules(current_user=user))
    assert len(user_schedules) >= 1
    assert any(s.id == created_sched.id for s in user_schedules)

    # Guest call to list_schedules raises 401
    try:
        asyncio.run(list_schedules(current_user=None))
        assert False, "Guest list_schedules should have raised 401"
    except HTTPException as e:
        assert e.status_code == 401

    # Guest call to create_schedule raises 401
    try:
        asyncio.run(create_schedule(req, current_user=None))
        assert False, "Guest create_schedule should have raised 401"
    except HTTPException as e:
        assert e.status_code == 401

    print("[OK] Continuous Schedules restricted to authenticated accounts")


def test_private_scan_history_scoping():
    print("Testing Private Per-User Scan History scoping...")
    user_email = f"history_user_{os.urandom(4).hex()}@shieldci.io"
    auth_resp = asyncio.run(signup(UserSignupRequest(
        email=user_email,
        password="HistoryPassword123!",
        full_name="History Auditor"
    )))
    user = auth_resp.user

    # Run scan as authenticated user
    scan_req = ScanRequest(target="./sample_vulnerable_repo", target_type=TargetCategory.REPOSITORY)
    http_req = DummyRequest(client_ip="10.0.0.1")
    result = asyncio.run(trigger_scan(request=scan_req, http_req=http_req, current_user=user))
    assert result.user_email == user_email.lower()

    # Retrieve history for authenticated user
    user_history = asyncio.run(get_scan_history(current_user=user))
    assert len(user_history) >= 1
    assert all(item.user_email == user_email.lower() for item in user_history if item.user_email)

    # Retrieve history for guest
    guest_history = asyncio.run(get_scan_history(current_user=None))
    assert all(item.user_email is None for item in guest_history)

    print("[OK] Private Per-User scan history isolation verified")


def test_guest_scan_quota_and_unlimited_auth():
    print("Testing Guest Scan Quota (5 limit) vs Unlimited Authenticated...")
    guest_ip = f"172.16.{os.urandom(1)[0]}.{os.urandom(1)[0]}"
    guest_http_req = DummyRequest(client_ip=guest_ip)

    # Check initial quota
    quota_info = asyncio.run(get_scan_quota(http_req=guest_http_req, current_user=None))
    assert quota_info["authenticated"] is False
    assert quota_info["max_scans"] == 5

    # Run 5 guest scans
    for i in range(5):
        scan_req = ScanRequest(target="./sample_vulnerable_repo", target_type=TargetCategory.REPOSITORY)
        res = asyncio.run(trigger_scan(request=scan_req, http_req=guest_http_req, current_user=None))
        assert res.scan_id is not None

    # Verify quota reached
    quota_after_5 = asyncio.run(get_scan_quota(http_req=guest_http_req, current_user=None))
    assert quota_after_5["scans_used"] == 5
    assert quota_after_5["remaining_scans"] == 0

    # 6th guest scan MUST be rejected with HTTP 429
    scan_req_6 = ScanRequest(target="./sample_vulnerable_repo", target_type=TargetCategory.REPOSITORY)
    try:
        asyncio.run(trigger_scan(request=scan_req_6, http_req=guest_http_req, current_user=None))
        assert False, "6th guest scan should have been rejected with 429 Too Many Requests"
    except HTTPException as e:
        assert e.status_code == 429
        assert "Guest daily scan quota exceeded" in e.detail
    print("[OK] Guest scan quota limit of 5 enforced with HTTP 429")

    # Now verify that logging in from the SAME IP allows scanning (Unlimited)
    auth_user = asyncio.run(signup(UserSignupRequest(
        email=f"unlimited_{os.urandom(4).hex()}@shieldci.io",
        password="UnlimitedPassword123!"
    ))).user

    # Logged-in user should scan successfully even from the exhausted IP
    unlimited_res = asyncio.run(trigger_scan(request=scan_req_6, http_req=guest_http_req, current_user=auth_user))
    assert unlimited_res.scan_id is not None

    # Quota endpoint confirms unlimited
    auth_quota = asyncio.run(get_scan_quota(http_req=guest_http_req, current_user=auth_user))
    assert auth_quota["authenticated"] is True
    assert auth_quota["unlimited"] is True
    print("[OK] Authenticated user enjoys Unlimited scans, bypassing guest quota")


if __name__ == "__main__":
    print("==================================================")
    print(" ShieldCI Guest Limitations Verification Suite ")
    print("==================================================")
    test_continuous_schedules_require_auth()
    test_private_scan_history_scoping()
    test_guest_scan_quota_and_unlimited_auth()
    print("==================================================")
    print(" ALL GUEST LIMITATION TESTS COMPLETED SUCCESSFULLY! ")
    print("==================================================")
