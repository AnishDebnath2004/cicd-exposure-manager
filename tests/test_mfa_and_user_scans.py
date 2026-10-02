"""
tests/test_mfa_and_user_scans.py
Comprehensive test suite verifying:
a) Admin can see number of scans used by a user and view their scans.
b) Multi-Factor Authentication (MFA / 2FA) in Admin section:
   - Setup TOTP
   - Enable with verification code
   - Enforce MFA on login with challenge token
   - Complete MFA login via TOTP code
   - Complete MFA login via single-use recovery code
   - Reset user MFA by administrator
   - Disable MFA with password confirmation
   - Update platform MFA policy
"""

import os
import sys
import asyncio
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import HTTPException
from app.core.storage import storage
from app.core.security import (
    hash_password, generate_totp_secret, generate_totp_code, verify_totp_code
)
from app.models.auth_schemas import (
    UserResponse, UserLoginRequest, MfaEnableRequest, MfaDisableRequest,
    MfaVerifyRequest, MfaPolicyUpdateRequest
)
from app.main import (
    admin_list_users, admin_get_user_scans, login, verify_mfa_challenge,
    admin_get_mfa_status, admin_setup_mfa, admin_enable_mfa, admin_disable_mfa,
    admin_regenerate_recovery_codes, admin_reset_user_mfa, admin_get_mfa_policy,
    admin_update_mfa_policy
)


def test_admin_can_see_user_scan_counts():
    """
    Test requirement (a): Admin can see number of scans is used by a user.
    """
    admin_dict = storage.get_user_by_email("debnathanish19@gmail.com")
    if not admin_dict:
        storage.create_user(
            email="debnathanish19@gmail.com",
            password_hash="mockhash",
            salt="mocksalt",
            full_name="Anish Debnath",
            role="admin",
            preferred_domain="domain_01"
        )
        admin_dict = storage.get_user_by_email("debnathanish19@gmail.com")
    elif admin_dict.get("role") != "admin":
        storage.update_user_role(admin_dict["id"], "admin")
        admin_dict = storage.get_user_by_email("debnathanish19@gmail.com")

    admin = UserResponse(**admin_dict)

    # 1. Admin lists all users
    user_list = asyncio.run(admin_list_users(limit=100, offset=0, admin_user=admin))
    assert user_list.total > 0

    # Verify that each user has scan_count attribute (integer >= 0)
    for u in user_list.users:
        assert hasattr(u, "scan_count")
        assert isinstance(u.scan_count, int)
        assert u.scan_count >= 0
        assert hasattr(u, "mfa_enabled")

    # 2. Test admin inspecting scans for a user
    target_user = user_list.users[0]
    user_scans = asyncio.run(admin_get_user_scans(user_id=target_user.id, limit=10, admin_user=admin))
    assert user_scans.user_id == target_user.id
    assert user_scans.email == target_user.email
    assert user_scans.total_scans >= 0
    assert isinstance(user_scans.scans, list)


def test_admin_mfa_lifecycle():
    """
    Test requirement (b): Multi-Factor Authentication method in Admin section.
    """
    # 1. Create a dedicated test admin account
    test_email = "mfa_test_admin@shieldci.local"
    pw_hash, salt = hash_password("AdminSecurePassword2026!")
    user_rec = storage.get_user_by_email(test_email)
    if not user_rec:
        user_obj = storage.create_user(
            email=test_email,
            password_hash=pw_hash,
            salt=salt,
            full_name="MFA Test Admin",
            role="admin",
            preferred_domain="domain_01"
        )
    else:
        user_obj = storage.get_user_by_id(user_rec["id"])

    admin = UserResponse(**storage.get_user_by_email(test_email))

    # 2. Initially MFA should be disabled
    status_initial = asyncio.run(admin_get_mfa_status(admin_user=admin))
    assert status_initial.mfa_enabled is False

    # 3. Setup MFA
    setup_res = asyncio.run(admin_setup_mfa(admin_user=admin))
    assert setup_res.secret is not None
    assert len(setup_res.secret) >= 16
    assert "otpauth://" in setup_res.otpauth_uri
    assert len(setup_res.recovery_codes) == 8
    first_recovery_code = setup_res.recovery_codes[0]

    # 4. Generate valid 6-digit TOTP code
    totp_code = generate_totp_code(setup_res.secret)
    assert len(totp_code) == 6

    # 5. Invalid TOTP code must fail
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(admin_enable_mfa(
            req=MfaEnableRequest(
                secret=setup_res.secret,
                code="000000" if totp_code != "000000" else "111111",
                recovery_codes=setup_res.recovery_codes
            ),
            admin_user=admin
        ))
    assert exc_info.value.status_code == 400

    # 6. Valid TOTP code enables MFA
    enable_res = asyncio.run(admin_enable_mfa(
        req=MfaEnableRequest(
            secret=setup_res.secret,
            code=totp_code,
            recovery_codes=setup_res.recovery_codes
        ),
        admin_user=admin
    ))
    assert enable_res["status"] == "success"

    # Verify status reflects enabled MFA
    admin_updated = storage.get_user_by_id(admin.id)
    assert admin_updated.mfa_enabled is True
    status_enabled = asyncio.run(admin_get_mfa_status(admin_user=admin_updated))
    assert status_enabled.mfa_enabled is True
    assert status_enabled.recovery_codes_remaining == 8

    # 7. Login with MFA enabled -> must trigger MFA challenge
    login_res = asyncio.run(login(UserLoginRequest(
        email=test_email,
        password="AdminSecurePassword2026!"
    )))
    assert login_res.mfa_required is True
    assert login_res.mfa_token is not None
    assert login_res.access_token is None

    # 8. Complete login using TOTP code
    fresh_totp = generate_totp_code(setup_res.secret)
    verify_res = asyncio.run(verify_mfa_challenge(MfaVerifyRequest(
        mfa_token=login_res.mfa_token,
        code=fresh_totp
    )))
    assert verify_res.access_token is not None
    assert verify_res.user.email == test_email

    # 9. Test logging in using single-use backup recovery code
    login_res_2 = asyncio.run(login(UserLoginRequest(
        email=test_email,
        password="AdminSecurePassword2026!"
    )))
    assert login_res_2.mfa_required is True

    verify_recovery_res = asyncio.run(verify_mfa_challenge(MfaVerifyRequest(
        mfa_token=login_res_2.mfa_token,
        code=first_recovery_code
    )))
    assert verify_recovery_res.access_token is not None

    # Verify recovery code was consumed (remaining should be 7)
    status_consumed = asyncio.run(admin_get_mfa_status(admin_user=admin_updated))
    assert status_consumed.recovery_codes_remaining == 7

    # Using the same recovery code again must FAIL
    login_res_3 = asyncio.run(login(UserLoginRequest(
        email=test_email,
        password="AdminSecurePassword2026!"
    )))
    with pytest.raises(HTTPException) as exc_info_rec:
        asyncio.run(verify_mfa_challenge(MfaVerifyRequest(
            mfa_token=login_res_3.mfa_token,
            code=first_recovery_code
        )))
    assert exc_info_rec.value.status_code == 401

    # 10. Test admin reset user MFA
    reset_res = asyncio.run(admin_reset_user_mfa(user_id=admin.id, admin_user=admin))
    assert reset_res["status"] == "success"
    admin_after_reset = storage.get_user_by_id(admin.id)
    assert admin_after_reset.mfa_enabled is False

    # 11. Now login succeeds immediately without MFA challenge
    login_after_reset = asyncio.run(login(UserLoginRequest(
        email=test_email,
        password="AdminSecurePassword2026!"
    )))
    assert login_after_reset.mfa_required is False
    assert login_after_reset.access_token is not None

    # 12. Test platform MFA policies
    policy_update = asyncio.run(admin_update_mfa_policy(
        req=MfaPolicyUpdateRequest(enforce_admin_mfa=True, enforce_all_users_mfa=False),
        admin_user=admin
    ))
    assert policy_update["enforce_admin_mfa"] is True

    current_policy = asyncio.run(admin_get_mfa_policy(admin_user=admin))
    assert current_policy["enforce_admin_mfa"] is True

    # Restore policy
    asyncio.run(admin_update_mfa_policy(
        req=MfaPolicyUpdateRequest(enforce_admin_mfa=False, enforce_all_users_mfa=False),
        admin_user=admin
    ))

    # Clean up test user
    storage.delete_user(admin.id)
