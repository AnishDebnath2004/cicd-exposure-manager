"""
tests/test_domain_isolation.py
Automated test suite verifying full multi-domain access across Domain 01 (Code),
Domain 02 (Web), and Domain 03 (Database) for developers and users,
while ensuring Administrator governance remains strictly protected.
"""

import os
import sys
import uuid
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import HTTPException
from app.models.schemas import ScanRequest, TargetCategory, SeverityLevel, ScheduleCreateRequest
from app.models.auth_schemas import (
    UserSignupRequest, UserResponse, UserProfileUpdateRequest
)
from app.main import (
    signup, trigger_scan, scan_website, scan_database, upload_and_scan,
    create_schedule, update_profile, require_admin
)
from app.core.storage import storage


def cleanup_test_domain_users():
    """Removes any test developer accounts and test scans/schedules from storage."""
    try:
        with storage.adapter._get_connection() as conn:
            if storage.engine_type == "postgresql":
                with storage.adapter._get_cursor(conn) as cur:
                    cur.execute("DELETE FROM schedules WHERE user_email LIKE %s", ('%@shieldci.test',))
                    cur.execute("DELETE FROM scans WHERE user_email LIKE %s", ('%@shieldci.test',))
                    cur.execute("DELETE FROM users WHERE email LIKE %s", ('%@shieldci.test',))
            else:
                cur = conn.cursor()
                cur.execute("DELETE FROM schedules WHERE user_email LIKE '%@shieldci.test'")
                cur.execute("DELETE FROM scans WHERE user_email LIKE '%@shieldci.test'")
                cur.execute("DELETE FROM users WHERE email LIKE '%@shieldci.test'")
            conn.commit()
        storage.refresh()
    except Exception as e:
        print(f"Warning during test domain cleanup: {e}")


def create_test_dev(domain: str) -> tuple[UserResponse, str]:
    """Helper to register a developer user with a specific preferred domain."""
    email = f"dev_{domain}_{uuid.uuid4().hex[:8]}@shieldci.test"
    req = UserSignupRequest(
        email=email,
        password="TestPassword2026!",
        full_name=f"Dev {domain.upper()}",
        role="developer",
        preferred_domain=domain
    )
    auth = asyncio.run(signup(req))
    return auth.user, auth.access_token


def test_multi_domain_developer_access():
    print("Testing Multi-Domain Developer Access across Code, Web, and Database...")
    dev, token = create_test_dev("domain_01")
    assert dev.role == "developer"

    # 1. Domain 01: Repository Scan
    repo_req = ScanRequest(
        target="./sample_vulnerable_repo",
        target_path="./sample_vulnerable_repo",
        target_type=TargetCategory.REPOSITORY,
        user_email=dev.email
    )
    res_repo = asyncio.run(trigger_scan(request=repo_req, current_user=dev))
    assert res_repo is not None
    assert res_repo.target_type == TargetCategory.REPOSITORY
    print("[OK] Developer can audit Domain 01: Repository")

    # 2. Domain 02: Website Scan
    web_res = asyncio.run(scan_website(url="https://example.com", current_user=dev))
    assert web_res is not None
    assert web_res.target_type == TargetCategory.WEBSITE
    print("[OK] Developer can audit Domain 02: Website & API")

    # 3. Domain 03: Database Scan
    db_res = asyncio.run(scan_database(target="redis://127.0.0.1:6379", current_user=dev))
    assert db_res is not None
    assert db_res.target_type == TargetCategory.DATABASE
    print("[OK] Developer can audit Domain 03: Database & Cloud")

    # 4. Schedule scans across any domain
    sched_req = ScheduleCreateRequest(
        target="https://example.com",
        target_type=TargetCategory.WEBSITE,
        interval_minutes=60,
        fail_on_severity=SeverityLevel.HIGH,
        max_allowed_pes=50.0
    )
    created_sched = asyncio.run(create_schedule(sched_req, current_user=dev))
    assert created_sched.id is not None
    assert created_sched.target_type == TargetCategory.WEBSITE
    print("[OK] Developer can create schedules across domains")

    # 5. Profile Domain update is permitted
    updated = asyncio.run(update_profile(
        UserProfileUpdateRequest(preferred_domain="domain_02"),
        current_user=dev
    ))
    assert updated.preferred_domain == "domain_02"
    print("[OK] Developer can update preferred landing domain")


def test_admin_governance_strictly_protected():
    print("Testing Admin Governance protection against non-admin developers...")
    dev, _ = create_test_dev("domain_02")
    try:
        asyncio.run(require_admin(dev))
        assert False, "Developer should have been blocked with 403 Forbidden"
    except HTTPException as e:
        assert e.status_code == 403
        assert "Administrator privileges are required" in e.detail
        print("[OK] Admin Console remains strictly protected against non-admin developers (403 Forbidden)")


def test_admin_multi_domain_governance():
    print("Testing Administrator Multi-Domain Governance...")
    admin_dict = storage.get_user_by_email("debnathanish19@gmail.com")
    assert admin_dict is not None
    admin = UserResponse(**admin_dict)
    assert admin.role == "admin"

    res_admin = asyncio.run(require_admin(admin))
    assert res_admin.id == admin.id
    print("[OK] Administrator retains full multi-domain governance and administrative privileges")


if __name__ == "__main__":
    cleanup_test_domain_users()
    try:
        test_multi_domain_developer_access()
        test_admin_governance_strictly_protected()
        test_admin_multi_domain_governance()
        print("ALL MULTI-DOMAIN AND ADMIN TESTS PASSED SUCCESSFULLY!")
    finally:
        cleanup_test_domain_users()
