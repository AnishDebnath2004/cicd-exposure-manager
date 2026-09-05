"""
tests/test_admin_rbac.py
Test suite for Admin-only RBAC governance, delegation, and promotion/demotion rules.
"""

import os
import sys
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# pyrefly: ignore [missing-import]
from fastapi import HTTPException
from app.core.storage import storage
from app.models.auth_schemas import UserResponse, UserRoleUpdateRequest, AdminCreateUserRequest
from app.main import require_admin, admin_list_users, admin_update_user_role, admin_create_user


def test_admin_rbac():
    print("==================================================")
    print(" Testing Administrator RBAC & Delegation Policy ")
    print("==================================================")

    # 1. Fetch real admin user and developer user from storage
    admin_dict = storage.get_user_by_email("debnathanish19@gmail.com")
    developer_dict = storage.get_user_by_email("arkapravamaity2000@gmail.com")
    if not developer_dict:
        storage.create_user(
            email="arkapravamaity2000@gmail.com",
            password_hash="mockhash",
            salt="mocksalt",
            full_name="Arka",
            role="developer",
            preferred_domain="domain_01"
        )
        developer_dict = storage.get_user_by_email("arkapravamaity2000@gmail.com")

    assert admin_dict is not None, "Admin user debnathanish19@gmail.com should exist in database"
    admin = UserResponse(**admin_dict)
    assert admin.role == "admin", f"Admin user should have role 'admin', got '{admin.role}'"
    print(f"[OK] Admin user verified: {admin.email} (role: {admin.role})")

    assert developer_dict is not None, "Developer user arkapravamaity2000@gmail.com should exist in database"
    developer = UserResponse(**developer_dict)
    print(f"[OK] Developer user verified: {developer.email} (role: {developer.role})")

    # 2. Test require_admin dependency with developer account (MUST fail with 403)
    try:
        asyncio.run(require_admin(developer))
        assert False, "require_admin should have raised 403 for developer account"
    except HTTPException as e:
        assert e.status_code == 403, f"Expected status 403, got {e.status_code}"
        print(f"[OK] Developer successfully blocked with 403: {e.detail}")

    # 3. Test require_admin dependency with admin account (MUST succeed)
    admin_auth = asyncio.run(require_admin(admin))
    assert admin_auth.id == admin.id
    print("[OK] Admin account successfully passed require_admin check")

    # 4. Test admin_list_users with admin privilege
    user_list = asyncio.run(admin_list_users(limit=100, offset=0, admin_user=admin))
    assert user_list.total >= 2
    emails = [u.email for u in user_list.users]
    assert "debnathanish19@gmail.com" in emails
    assert "arkapravamaity2000@gmail.com" in emails
    print(f"[OK] admin_list_users returned {user_list.total} users: {emails}")

    # 5. Test self-demotion protection (Admin cannot demote themselves)
    try:
        asyncio.run(admin_update_user_role(
            user_id=admin.id,
            req=UserRoleUpdateRequest(role="developer"),
            admin_user=admin
        ))
        assert False, "Admin should NOT be allowed to demote their own account"
    except HTTPException as e:
        assert e.status_code == 400, f"Expected status 400, got {e.status_code}"
        print(f"[OK] Self-demotion protection verified (400 Bad Request): {e.detail}")

    # 6. Test promoting developer to admin
    promoted = asyncio.run(admin_update_user_role(
        user_id=developer.id,
        req=UserRoleUpdateRequest(role="admin"),
        admin_user=admin
    ))
    assert promoted.role == "admin"
    assert storage.get_user_by_id(developer.id).role == "admin"
    print(f"[OK] Developer promoted to admin successfully: {promoted.email} is now {promoted.role}")

    # 7. Test demoting back to developer
    demoted = asyncio.run(admin_update_user_role(
        user_id=developer.id,
        req=UserRoleUpdateRequest(role="developer"),
        admin_user=admin
    ))
    assert demoted.role == "developer"
    assert storage.get_user_by_id(developer.id).role == "developer"
    print(f"[OK] Demoted back to developer successfully: {demoted.email} is now {demoted.role}")

    # 8. Test Admin creating a new user / admin and cleaning up
    test_email = "test_admin_prov@shieldci.io"
    created = asyncio.run(admin_create_user(
        req=AdminCreateUserRequest(
            email=test_email,
            password="AdminProvisionedPass2026!",
            full_name="Provisioned Admin",
            role="admin"
        ),
        admin_user=admin
    ))
    assert created.email == test_email
    assert created.role == "admin"
    print(f"[OK] Admin direct user provisioning passed: {created.email} (role: {created.role})")

    # Clean up the test provisioned account
    with storage.adapter._get_connection() as conn:
        if storage.engine_type == "postgresql":
            with storage.adapter._get_cursor(conn) as cursor:
                cursor.execute("DELETE FROM users WHERE id = %s", (created.id,))
        else:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE id = ?", (created.id,))
        conn.commit()
    storage.refresh()
    print("[OK] Test provisioned user deleted and cleaned up")

    print("==================================================")
    print(" ALL ADMIN RBAC TESTS PASSED SUCCESSFULLY! ")
    print("==================================================")


def test_admin_signup_restriction():
    print("Testing Administrator Signup Restriction Policy...")
    from app.models.auth_schemas import UserSignupRequest
    from app.main import signup

    # 1. Unauthorized email attempting to sign up as admin -> MUST fail with 403
    unauthorized_email = f"stranger_{os.urandom(4).hex()}@example.com"
    req_unauthorized = UserSignupRequest(
        email=unauthorized_email,
        password="TestPassword2026!",
        full_name="Stranger Hacker",
        role="admin"
    )
    try:
        asyncio.run(signup(req_unauthorized))
        assert False, "Unauthorized user should have been blocked from signing up as Administrator"
    except HTTPException as e:
        assert e.status_code == 403
        assert "not authorized to register as an Administrator" in e.detail
        print(f"[OK] Unauthorized admin signup blocked with 403 Forbidden: {e.detail}")

    # 2. Same unauthorized email attempting to sign up as developer -> MUST succeed
    req_developer = UserSignupRequest(
        email=unauthorized_email,
        password="TestPassword2026!",
        full_name="Legit Developer",
        role="developer"
    )
    dev_auth = asyncio.run(signup(req_developer))
    assert dev_auth.user.role == "developer"
    print(f"[OK] Same account allowed to register as developer: {dev_auth.user.email}")

    # Clean up created developer test user
    with storage.adapter._get_connection() as conn:
        if storage.engine_type == "postgresql":
            with storage.adapter._get_cursor(conn) as cursor:
                cursor.execute("DELETE FROM users WHERE id = %s", (dev_auth.user.id,))
        else:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE id = ?", (dev_auth.user.id,))
        conn.commit()
    storage.refresh()
    print("[OK] Test developer cleaned up successfully.")


if __name__ == "__main__":
    test_admin_rbac()
    test_admin_signup_restriction()
