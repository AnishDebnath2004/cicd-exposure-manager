"""
tests/test_settings.py
Verification suite for ShieldCI Settings System:
- Quality Gate Thresholds
- Scanner & Shannon Entropy Rules
- Exposure Scoring Weights
- Outbound Webhook Alerts
- User Profile & Password Updates
"""

import os
import sys
import asyncio

# Ensure root dir is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import HTTPException
from app.config import settings
from app.models.schemas import (
    SettingsUpdateRequest, WebhookTestRequest, SeverityLevel
)
from app.models.auth_schemas import (
    UserSignupRequest, UserProfileUpdateRequest, PasswordChangeRequest, UserResponse
)
from app.core.storage import storage
from app.main import (
    get_settings, update_settings, reset_settings, test_webhook,
    update_profile, change_password, signup
)


def test_get_and_update_settings():
    print("Testing GET /api/settings and PUT /api/settings...")
    
    # 1. Fetch initial settings
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        initial = loop.run_until_complete(get_settings())
        assert initial is not None
        assert initial.default_fail_severity in (SeverityLevel.HIGH, "HIGH")

        # 2. Update settings
        update_req = SettingsUpdateRequest(
            default_fail_severity=SeverityLevel.CRITICAL,
            default_max_pes=75.5,
            auto_fail_on_toxic_combos=False,
            shannon_entropy_threshold=4.8,
            min_token_length_for_entropy=28,
            weight_critical=30.0,
            webhook_url="https://hooks.example.com/alerts",
            webhook_enabled=True,
            notify_on_gate_failure_only=False
        )
        updated = loop.run_until_complete(update_settings(update_req))
        assert updated.default_fail_severity == SeverityLevel.CRITICAL
        assert updated.default_max_pes == 75.5
        assert updated.auto_fail_on_toxic_combos is False
        assert updated.shannon_entropy_threshold == 4.8
        assert updated.min_token_length_for_entropy == 28
        assert updated.weight_critical == 30.0
        assert updated.webhook_url == "https://hooks.example.com/alerts"
        assert updated.webhook_enabled is True
        assert updated.notify_on_gate_failure_only is False

        # 3. Verify in-memory config synchronized
        assert settings.policy_gate.DEFAULT_FAIL_SEVERITY == "CRITICAL"
        assert settings.policy_gate.DEFAULT_MAX_PES == 75.5
        assert settings.AUTO_FAIL_ON_TOXIC_COMBOS is False
        assert settings.scanner.SHANNON_ENTROPY_THRESHOLD == 4.8
        assert settings.scoring_weights.CRITICAL == 30.0
        assert settings.WEBHOOK_ENABLED is True

        # 4. Reset settings back to defaults
        reset = loop.run_until_complete(reset_settings())
        assert reset.default_fail_severity in (SeverityLevel.HIGH, "HIGH")
        assert reset.default_max_pes == 60.0
        assert reset.auto_fail_on_toxic_combos is True
        assert reset.shannon_entropy_threshold == 4.4
        assert reset.weight_critical == 25.0
        assert reset.webhook_enabled is False

        print("[OK] Settings GET, PUT, and Reset verification passed")
    finally:
        loop.close()


def test_webhook_endpoint_validation():
    print("Testing POST /api/settings/test-webhook validation...")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        # Test invalid URL triggers HTTP 400
        invalid_req = WebhookTestRequest(webhook_url="ftp://invalid-scheme")
        try:
            loop.run_until_complete(test_webhook(invalid_req))
            assert False, "Should have raised HTTPException for non-http url"
        except HTTPException as e:
            assert e.status_code == 400

        print("[OK] Webhook URL validation passed")
    finally:
        loop.close()


def test_user_profile_and_password_update():
    print("Testing User Profile and Password updates...")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        # Create a fresh test user
        import uuid
        test_email = f"settings_test_{uuid.uuid4().hex[:8]}@shieldci.io"
        test_pw = "OriginalP@ssw0rd123!"
        auth_resp = loop.run_until_complete(signup(UserSignupRequest(
            email=test_email,
            password=test_pw,
            full_name="Alex Original",
            organization="Original Security Org"
        )))
        user = auth_resp.user

        # Test profile update
        profile_update = UserProfileUpdateRequest(
            full_name="Alex CyberDefender",
            organization="SecOps Global"
        )
        updated_user = loop.run_until_complete(update_profile(profile_update, current_user=user))
        assert updated_user.full_name == "Alex CyberDefender"
        assert updated_user.organization == "SecOps Global"
        print("[OK] Profile update passed")

        # Test password change with wrong existing password
        try:
            loop.run_until_complete(change_password(
                PasswordChangeRequest(
                    current_password="WrongCurrentPassword!",
                    new_password="NewSecureP@ssw0rd456!"
                ),
                current_user=updated_user
            ))
            assert False, "Should have failed with wrong current password"
        except HTTPException as e:
            assert e.status_code == 400
        print("[OK] Wrong current password rejected")

        # Test password change with correct existing password
        pw_result = loop.run_until_complete(change_password(
            PasswordChangeRequest(
                current_password=test_pw,
                new_password="NewSecureP@ssw0rd456!"
            ),
            current_user=updated_user
        ))
        assert pw_result["status"] == "success"

        # Verify new password in storage
        raw = storage.get_user_by_email(test_email)
        from app.core.security import verify_password
        assert verify_password("NewSecureP@ssw0rd456!", raw["password_hash"], raw["salt"]) is True
        print("[OK] Password update and verification passed")
    finally:
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
        loop.close()



if __name__ == "__main__":
    print("=" * 50)
    print(" ShieldCI Settings & Preferences Test Suite ")
    print("=" * 50)
    test_get_and_update_settings()
    test_webhook_endpoint_validation()
    test_user_profile_and_password_update()
    print("=" * 50)
    print(" ALL SETTINGS TESTS COMPLETED SUCCESSFULLY! ")
    print("=" * 50)
