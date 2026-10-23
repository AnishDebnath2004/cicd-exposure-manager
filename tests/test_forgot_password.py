"""
tests/test_forgot_password.py
Verification test suite for "Forget Password" (Forgot Password) flow
for both Admin & Users in ShieldCI.
"""

import os
import sys
import asyncio
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import HTTPException
from app.core.storage import storage
from app.core.security import hash_password, verify_password, decode_access_token
from app.models.auth_schemas import (
    PasswordResetRequest, PasswordResetConfirmRequest, UserLoginRequest
)
from app.main import (
    request_password_reset, confirm_password_reset, login
)


def test_user_forgot_password_lifecycle():
    """
    Test standard User / Developer password reset lifecycle:
    1. Register/Ensure test user.
    2. Request password reset (generates code and token).
    3. Wrong code rejected.
    4. Confirm password reset with new password.
    5. Old password no longer works for login.
    6. New password successfully logs in.
    """
    test_email = f"user_forgot_{os.urandom(4).hex()}@shieldci.io"
    initial_password = "InitialUserPassword123!"
    new_password = "BrandNewUserPassword456!"

    pw_hash, salt = hash_password(initial_password)
    user = storage.create_user(
        email=test_email,
        password_hash=pw_hash,
        salt=salt,
        full_name="Forgot User Test",
        organization="Quality Engineering",
        role="developer"
    )

    try:
        # 1. Request reset
        req = PasswordResetRequest(email=test_email, role="user")
        reset_res = asyncio.run(request_password_reset(req))
        assert reset_res.status == "success"
        assert reset_res.reset_token is not None
        assert reset_res.reset_code is not None
        assert len(reset_res.reset_code) == 6
        assert reset_res.email == test_email.lower()

        # 2. Reject wrong code
        bad_confirm_req = PasswordResetConfirmRequest(
            reset_token=reset_res.reset_token,
            code="000000",
            new_password=new_password,
            confirm_password=new_password
        )
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(confirm_password_reset(bad_confirm_req))
        assert exc_info.value.status_code == 400

        # 3. Confirm with valid code and new password
        good_confirm_req = PasswordResetConfirmRequest(
            reset_token=reset_res.reset_token,
            code=reset_res.reset_code,
            new_password=new_password,
            confirm_password=new_password
        )
        confirm_res = asyncio.run(confirm_password_reset(good_confirm_req))
        assert confirm_res.status == "success"
        assert confirm_res.access_token is not None
        assert confirm_res.user.email == test_email.lower()

        # 4. Old password must fail login
        with pytest.raises(HTTPException) as login_exc:
            asyncio.run(login(UserLoginRequest(email=test_email, password=initial_password)))
        assert login_exc.value.status_code == 401

        # 5. New password must succeed login
        fresh_login = asyncio.run(login(UserLoginRequest(email=test_email, password=new_password)))
        assert fresh_login.access_token is not None
        assert fresh_login.user.email == test_email.lower()

    finally:
        # Cleanup
        try:
            with storage.adapter._get_connection() as conn:
                if storage.engine_type == "postgresql":
                    with storage.adapter._get_cursor(conn) as cur:
                        cur.execute("DELETE FROM users WHERE email = %s", (test_email.lower(),))
                else:
                    cur = conn.cursor()
                    cur.execute("DELETE FROM users WHERE email = ?", (test_email.lower(),))
                conn.commit()
            storage.refresh()
        except Exception:
            pass


def test_admin_forgot_password_lifecycle_and_role_protection():
    """
    Test Administrator password reset lifecycle and role protection:
    1. Non-admin attempting Admin password reset is rejected (403 Forbidden).
    2. Valid Administrator receives reset token and code.
    3. Confirms reset with new password.
    4. Admin login succeeds with new password.
    """
    admin_email = "debnathanish19@gmail.com"  # authorized admin
    temp_admin_pass = "AdminInitialPass2026!"
    temp_new_admin_pass = "AdminNewResetPass2026!"

    admin_dict = storage.get_user_by_email(admin_email)
    if not admin_dict:
        pw_hash, salt = hash_password(temp_admin_pass)
        storage.create_user(
            email=admin_email,
            password_hash=pw_hash,
            salt=salt,
            full_name="Admin Security Owner",
            role="admin"
        )
    else:
        pw_hash, salt = hash_password(temp_admin_pass)
        storage.update_user_password(admin_dict["id"], pw_hash, salt)
        if admin_dict.get("role") != "admin":
            storage.update_user_role(admin_dict["id"], "admin")

    # Create dummy regular user to test role protection
    regular_email = f"standard_dev_{os.urandom(4).hex()}@shieldci.io"
    pw_hash_reg, salt_reg = hash_password("StandardPass123!")
    storage.create_user(
        email=regular_email,
        password_hash=pw_hash_reg,
        salt=salt_reg,
        full_name="Standard Dev",
        role="developer"
    )

    try:
        # 1. Standard user cannot request reset through Admin portal
        with pytest.raises(HTTPException) as role_exc:
            asyncio.run(request_password_reset(PasswordResetRequest(email=regular_email, role="admin")))
        assert role_exc.value.status_code == 403

        # 2. Administrator requests reset
        admin_reset_req = PasswordResetRequest(email=admin_email, role="admin")
        admin_reset_res = asyncio.run(request_password_reset(admin_reset_req))
        assert admin_reset_res.status == "success"
        assert admin_reset_res.role == "admin"
        assert admin_reset_res.reset_code is not None

        # 3. Confirm Administrator password reset
        confirm_res = asyncio.run(confirm_password_reset(PasswordResetConfirmRequest(
            reset_token=admin_reset_res.reset_token,
            code=admin_reset_res.reset_code,
            new_password=temp_new_admin_pass,
            confirm_password=temp_new_admin_pass
        )))
        assert confirm_res.status == "success"
        assert confirm_res.user.role == "admin"

        # 4. Administrator login with new password succeeds with required_role='admin'
        admin_login = asyncio.run(login(UserLoginRequest(
            email=admin_email,
            password=temp_new_admin_pass,
            required_role="admin"
        )))
        assert admin_login.access_token is not None
        assert admin_login.user.role == "admin"

    finally:
        # Cleanup regular user
        try:
            with storage.adapter._get_connection() as conn:
                if storage.engine_type == "postgresql":
                    with storage.adapter._get_cursor(conn) as cur:
                        cur.execute("DELETE FROM users WHERE email = %s", (regular_email.lower(),))
                else:
                    cur = conn.cursor()
                    cur.execute("DELETE FROM users WHERE email = ?", (regular_email.lower(),))
                conn.commit()
            storage.refresh()
        except Exception:
            pass


def test_nonexistent_email_rejection():
    """Requesting password reset for non-existent email returns 404."""
    with pytest.raises(HTTPException) as exc:
        asyncio.run(request_password_reset(PasswordResetRequest(
            email="doesnotexist_981273981@shieldci.io"
        )))
    assert exc.value.status_code == 404


def test_password_mismatch_and_short_password_validation():
    """PasswordResetConfirmRequest enforces length >= 8 and matching confirm_password."""
    with pytest.raises(Exception):
        PasswordResetConfirmRequest(
            reset_token="dummy.token.123",
            code="123456",
            new_password="short",
            confirm_password="short"
        )

    with pytest.raises(Exception):
        PasswordResetConfirmRequest(
            reset_token="dummy.token.123",
            code="123456",
            new_password="ValidPassword123!",
            confirm_password="MismatchPassword456!"
        )


def test_ui_forgot_password_elements_and_controllers_present():
    """Verifies that the HTML interface includes Forget Password options for Admin & Users."""
    html_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app", "static", "index.html")
    assert os.path.isfile(html_path), "index.html must exist"

    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()

    # 1. Check Controller functions
    required_functions = [
        "openForgotPasswordFlow",
        "cancelForgotPasswordFlow",
        "setForgotRole",
        "toggleForgotRole",
        "backToForgotStep1",
        "autoFillForgotCode",
        "handleForgotPasswordRequest",
        "handleForgotPasswordConfirm"
    ]
    for fn in required_functions:
        assert f"function {fn}" in html or f"async function {fn}" in html, f"Missing function: {fn}"

    # 2. Check DOM Elements
    required_ids = [
        "forgotPasswordForm",
        "forgotRoleBadge",
        "forgotToggleRoleBtn",
        "forgotStep1",
        "forgotStep2",
        "forgotEmail",
        "forgotRequestBtn",
        "forgotCode",
        "forgotNewPassword",
        "forgotConfirmPassword",
        "forgotConfirmBtn",
        "forgotDispCode",
        "forgotConfirmedEmail",
        "modalForgotPassLink",
        "modalForgotBottomBtn"
    ]
    for dom_id in required_ids:
        assert f'id="{dom_id}"' in html, f"Missing element ID: {dom_id}"

    # 3. Check that Admin login sections feature "Forgot password" option
    assert "openForgotPasswordFlow('admin'" in html, "Admin login must have Forgot Password hook"

    # 4. Check that User login sections feature "Forgot password" option
    assert "openForgotPasswordFlow('user'" in html, "User login must have Forgot Password hook"

