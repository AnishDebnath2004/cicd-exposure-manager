"""
tests/test_domain_isolation.py
Automated test suite verifying strict single-domain developer isolation.
Ensures developers can only audit and operate within their registered domain.
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


def test_domain_01_developer_permissions_and_restrictions():
    print("Testing Domain 01 Developer permissions and restrictions...")
    dev1, token = create_test_dev("domain_01")
    assert dev1.role == "developer"
    assert dev1.preferred_domain == "domain_01"

    # 1. Allowed: Repository Scan
    repo_req = ScanRequest(
        target="./sample_vulnerable_repo",
        target_path="./sample_vulnerable_repo",
        target_type=TargetCategory.REPOSITORY,
        user_email=dev1.email
    )
    try:
        res = asyncio.run(trigger_scan(request=repo_req, current_user=dev1))
        assert res is not None
        assert res.target_type == TargetCategory.REPOSITORY
        print("[OK] Domain 01 Developer successfully scanned a repository")
    except HTTPException as e:
        assert e.status_code != 403, f"Unexpected 403 for allowed domain: {e.detail}"

    # 2. Blocked: Website Scan (via trigger_scan)
    web_req = ScanRequest(
        target="https://example.com",
        target_type=TargetCategory.WEBSITE,
        user_email=dev1.email
    )
    try:
        asyncio.run(trigger_scan(request=web_req, current_user=dev1))
        assert False, "Expected 403 Forbidden for website scan"
    except HTTPException as e:
        assert e.status_code == 403
        assert "Domain Access Restricted" in e.detail
        assert "Domain 01: Code Repository & CI/CD Security" in e.detail
        print("[OK] Domain 01 Developer blocked from website scan (403 Forbidden)")

    # 3. Blocked: Website Scan (via dedicated scan_website endpoint)
    try:
        asyncio.run(scan_website(url="https://example.com", current_user=dev1))
        assert False, "Expected 403 Forbidden for scan_website"
    except HTTPException as e:
        assert e.status_code == 403
        assert "Domain Access Restricted" in e.detail
        print("[OK] Domain 01 Developer blocked from scan_website endpoint (403 Forbidden)")

    # 4. Blocked: Database Scan (via dedicated scan_database endpoint)
    try:
        asyncio.run(scan_database(target="redis://127.0.0.1:6379", current_user=dev1))
        assert False, "Expected 403 Forbidden for scan_database"
    except HTTPException as e:
        assert e.status_code == 403
        assert "Domain Access Restricted" in e.detail
        print("[OK] Domain 01 Developer blocked from database scan (403 Forbidden)")

    # 5. Schedule Creation: Blocked for website, Allowed for repository
    try:
        asyncio.run(create_schedule(
            req=ScheduleCreateRequest(target="https://example.com", target_type=TargetCategory.WEBSITE),
            current_user=dev1
        ))
        assert False, "Expected 403 Forbidden for website schedule"
    except HTTPException as e:
        assert e.status_code == 403
        print("[OK] Domain 01 Developer blocked from scheduling website scan (403 Forbidden)")

    sched = asyncio.run(create_schedule(
        req=ScheduleCreateRequest(target="./sample_vulnerable_repo", target_type=TargetCategory.REPOSITORY),
        current_user=dev1
    ))
    assert sched is not None
    assert sched.target_type == TargetCategory.REPOSITORY
    print("[OK] Domain 01 Developer successfully scheduled a repository scan")

    # 6. Immutable Domain: Attempting to switch to domain_02 MUST fail with 403
    try:
        asyncio.run(update_profile(
            req=UserProfileUpdateRequest(preferred_domain="domain_02"),
            current_user=dev1
        ))
        assert False, "Expected 403 Forbidden for domain change"
    except HTTPException as e:
        assert e.status_code == 403
        assert "Domain cannot be changed for a developer account" in e.detail
        print("[OK] Domain 01 Developer domain mutation blocked (403 Forbidden)")


def test_domain_02_developer_permissions_and_restrictions():
    print("Testing Domain 02 Developer permissions and restrictions...")
    dev2, token = create_test_dev("domain_02")
    assert dev2.role == "developer"
    assert dev2.preferred_domain == "domain_02"

    # 1. Blocked: Repository Scan
    repo_req = ScanRequest(
        target="./sample_vulnerable_repo",
        target_path="./sample_vulnerable_repo",
        target_type=TargetCategory.REPOSITORY,
        user_email=dev2.email
    )
    try:
        asyncio.run(trigger_scan(request=repo_req, current_user=dev2))
        assert False, "Expected 403 Forbidden for repository scan"
    except HTTPException as e:
        assert e.status_code == 403
        assert "Domain Access Restricted" in e.detail
        assert "Domain 02: Web & API Perimeter" in e.detail
        print("[OK] Domain 02 Developer blocked from repository scan (403 Forbidden)")

    # 2. Blocked: Database Scan
    db_req = ScanRequest(
        target="redis://127.0.0.1:6379",
        target_type=TargetCategory.DATABASE,
        user_email=dev2.email
    )
    try:
        asyncio.run(trigger_scan(request=db_req, current_user=dev2))
        assert False, "Expected 403 Forbidden for database scan"
    except HTTPException as e:
        assert e.status_code == 403
        print("[OK] Domain 02 Developer blocked from database scan (403 Forbidden)")

    # 3. Allowed: Website Scan
    web_req = ScanRequest(
        target="https://example.com",
        target_type=TargetCategory.WEBSITE,
        user_email=dev2.email
    )
    try:
        res = asyncio.run(trigger_scan(request=web_req, current_user=dev2))
        assert res is not None
        assert res.target_type == TargetCategory.WEBSITE
        print("[OK] Domain 02 Developer successfully scanned a website")
    except HTTPException as e:
        assert e.status_code != 403, f"Unexpected 403 for allowed domain: {e.detail}"


def test_domain_03_developer_permissions_and_restrictions():
    print("Testing Domain 03 Developer permissions and restrictions...")
    dev3, token = create_test_dev("domain_03")
    assert dev3.role == "developer"
    assert dev3.preferred_domain == "domain_03"

    # 1. Blocked: Repository Scan
    repo_req = ScanRequest(
        target="./sample_vulnerable_repo",
        target_type=TargetCategory.REPOSITORY,
        user_email=dev3.email
    )
    try:
        asyncio.run(trigger_scan(request=repo_req, current_user=dev3))
        assert False, "Expected 403 Forbidden for repository scan"
    except HTTPException as e:
        assert e.status_code == 403
        assert "Domain 03: Database & Cloud Infrastructure" in e.detail
        print("[OK] Domain 03 Developer blocked from repository scan (403 Forbidden)")

    # 2. Blocked: Website Scan
    try:
        asyncio.run(scan_website(url="https://example.com", current_user=dev3))
        assert False, "Expected 403 Forbidden for website scan"
    except HTTPException as e:
        assert e.status_code == 403
        print("[OK] Domain 03 Developer blocked from website scan (403 Forbidden)")

    # 3. Allowed: Database Scan
    try:
        res = asyncio.run(scan_database(target="redis://127.0.0.1:6379", current_user=dev3))
        assert res is not None
        assert res.target_type == TargetCategory.DATABASE
        print("[OK] Domain 03 Developer successfully scanned a database")
    except HTTPException as e:
        assert e.status_code != 403, f"Unexpected 403 for allowed domain: {e.detail}"


def test_admin_multi_domain_access():
    print("Testing Administrator Multi-Domain Access (Unrestricted)...")
    admin_dict = storage.get_user_by_email("debnathanish19@gmail.com")
    assert admin_dict is not None
    admin = UserResponse(**admin_dict)
    assert admin.role == "admin"

    # Admin is not restricted by domain checks
    repo_req = ScanRequest(
        target="./sample_vulnerable_repo",
        target_type=TargetCategory.REPOSITORY,
        user_email=admin.email
    )
    res_repo = asyncio.run(trigger_scan(request=repo_req, current_user=admin))
    assert res_repo is not None

    res_web = asyncio.run(scan_website(url="https://example.com", current_user=admin))
    assert res_web is not None

    res_db = asyncio.run(scan_database(target="redis://127.0.0.1:6379", current_user=admin))
    assert res_db is not None

    print("[OK] Administrator retains complete multi-domain access across Repositories, Websites, and Databases")


if __name__ == "__main__":
    test_domain_01_developer_permissions_and_restrictions()
    test_domain_02_developer_permissions_and_restrictions()
    test_domain_03_developer_permissions_and_restrictions()
    test_admin_multi_domain_access()
    print("ALL DOMAIN ISOLATION TESTS PASSED!")
