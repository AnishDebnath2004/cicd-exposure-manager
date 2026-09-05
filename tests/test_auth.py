"""
tests/test_auth.py
Verification suite for Email Signup, Login, and Session Security in ShieldCI.
"""

import os
import sys
import asyncio

# Ensure root dir is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import HTTPException
from app.config import settings
from app.models.auth_schemas import UserSignupRequest, UserLoginRequest
from app.core.security import (
    hash_password, verify_password, create_access_token, decode_access_token
)
from app.core.storage import storage
from app.main import signup, login, get_my_profile, get_current_user, get_current_user_optional, health_check


def test_password_hashing_and_verification():
    print("Testing password hashing & verification...")
    password = "SuperSecretPassword123!"
    hash_val, salt = hash_password(password)
    
    assert hash_val is not None and len(hash_val) == 64
    assert salt is not None and len(salt) == 32
    assert verify_password(password, hash_val, salt) is True
    assert verify_password("WrongPassword!", hash_val, salt) is False
    print("[OK] Password hashing with PBKDF2-HMAC-SHA256 passed")


def test_token_creation_and_decoding():
    print("Testing token signing & validation...")
    user_id = "test-user-uuid-123"
    email = "security.engineer@shieldci.local"
    
    token = create_access_token(user_id=user_id, email=email, expires_seconds=3600)
    assert token is not None and len(token.split(".")) == 3
    
    claims = decode_access_token(token)
    assert claims is not None
    assert claims["sub"] == user_id
    assert claims["email"] == email
    
    # Test Bearer header parsing
    claims_bearer = decode_access_token(f"Bearer {token}")
    assert claims_bearer is not None
    assert claims_bearer["sub"] == user_id
    
    # Test invalid / tampered token
    tampered = token[:-4] + "abcd"
    assert decode_access_token(tampered) is None
    print("[OK] Cryptographic HMAC-SHA256 tokens passed")


def test_user_signup_and_login_flow():
    print("Testing user signup, duplicate prevention, and login flow...")
    test_email = f"dev_{os.urandom(4).hex()}@shieldci.io"
    test_password = "StrongPassword2026!"
    
    try:
        # 1. Sign Up
        signup_req = UserSignupRequest(
            email=test_email,
            password=test_password,
            full_name="Alex River",
            organization="CloudSec Ops"
        )
        auth_resp = asyncio.run(signup(signup_req))
        assert auth_resp.access_token is not None
        assert auth_resp.user.email == test_email.lower()
        assert auth_resp.user.full_name == "Alex River"
        assert auth_resp.user.organization == "CloudSec Ops"
        print(f"[OK] Sign up successful for {test_email}")
        
        # 2. Duplicate Signup Rejection
        try:
            asyncio.run(signup(signup_req))
            assert False, "Duplicate signup should have failed with 409"
        except HTTPException as e:
            assert e.status_code == 409
        print("[OK] Duplicate signup rejected (409 Conflict)")
        
        # 3. Successful Login
        login_req = UserLoginRequest(email=test_email, password=test_password)
        login_resp = asyncio.run(login(login_req))
        assert login_resp.access_token is not None
        assert login_resp.user.email == test_email.lower()
        print("[OK] Login successful with valid credentials")
        
        # 4. Failed Login (Wrong Password)
        bad_login_req = UserLoginRequest(email=test_email, password="WrongPassword999")
        try:
            asyncio.run(login(bad_login_req))
            assert False, "Bad login should have failed with 401"
        except HTTPException as e:
            assert e.status_code == 401
        print("[OK] Invalid login rejected (401 Unauthorized)")
        
        # 5. Session Verification (/api/auth/me)
        user_me = asyncio.run(get_my_profile(current_user=login_resp.user))
        assert user_me.email == test_email.lower()
        assert user_me.id == login_resp.user.id
        print("[OK] Current user session verification passed")
    finally:
        # Strictly delete test user so tests never pollute the database
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
        except Exception as e:
            print(f"Warning during auth cleanup: {e}")



def test_auth_feature_in_health():
    print("Testing user_authentication feature flag in health check...")
    health = asyncio.run(health_check())
    assert health["features"].get("user_authentication") is True
    print("[OK] Health check feature flag verified")


if __name__ == "__main__":
    print("==================================================")
    print(" ShieldCI Authentication & Security Test Suite ")
    print("==================================================")
    test_password_hashing_and_verification()
    test_token_creation_and_decoding()
    test_user_signup_and_login_flow()
    test_auth_feature_in_health()
    print("==================================================")
    print(" ALL AUTHENTICATION TESTS COMPLETED SUCCESSFULLY! ")
    print("==================================================")
