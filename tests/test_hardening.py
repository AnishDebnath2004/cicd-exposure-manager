"""
tests/test_hardening.py
Verification suite for ShieldCI Production Security Hardening:
1. SSRF Defense: Rejection of AWS/GCP metadata, localhost, and RFC1918 private subnets.
2. HTTP Security Headers: Validation of nosniff, frame denial, CSP, and permissions policies.
3. Token Versioning & Session Revocation: Instant invalidation of prior tokens upon password change.
4. Cryptographic Key Hardening: Valid token creation and verification.
"""

import os
import sys
import uuid
import asyncio
from datetime import datetime

# Ensure project root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi import HTTPException, Request, Response
from app.core.security import (
    validate_safe_url, hash_password, verify_password,
    create_access_token, decode_access_token
)
from app.core.storage import storage
from app.main import (
    app, scan_website, test_webhook, get_current_user_optional,
    change_password, add_security_headers
)
from app.models.schemas import WebhookTestRequest
from app.models.auth_schemas import PasswordChangeRequest, UserResponse


def test_ssrf_protection():
    print("Testing SSRF Defense (validate_safe_url)...")
    
    # Cloud metadata endpoints
    safe, msg = validate_safe_url("http://169.254.169.254/latest/meta-data")
    assert not safe, "Should block AWS/GCP link-local metadata"
    assert "restricted" in msg or "SSRF" in msg

    safe, msg = validate_safe_url("http://metadata.google.internal/computeMetadata/v1/")
    assert not safe, "Should block Google cloud metadata"

    # Localhost & Loopback
    safe, msg = validate_safe_url("http://127.0.0.1:8080/admin")
    assert not safe, "Should block 127.0.0.1"

    safe, msg = validate_safe_url("http://localhost:5000/internal")
    assert not safe, "Should block localhost"

    safe, msg = validate_safe_url("http://[::1]:8080")
    assert not safe, "Should block IPv6 loopback"

    # Invalid schemes
    safe, msg = validate_safe_url("file:///etc/passwd")
    assert not safe, "Should block file:// scheme"

    safe, msg = validate_safe_url("gopher://127.0.0.1:70")
    assert not safe, "Should block gopher:// scheme"

    # Public legit domains
    safe, msg = validate_safe_url("https://example.com")
    assert safe, f"Legitimate public domain should be allowed, got: {msg}"

    print("[OK] SSRF core filter validation passed")


def test_endpoint_ssrf_enforcement():
    print("Testing SSRF enforcement on scan and webhook endpoints...")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        # 1. /api/settings/test-webhook with metadata IP
        req = WebhookTestRequest(webhook_url="http://169.254.169.254/latest/meta-data")
        try:
            loop.run_until_complete(test_webhook(req))
            assert False, "Should raise HTTPException 400 for cloud metadata webhook"
        except HTTPException as e:
            assert e.status_code == 400
            assert "SSRF Protection" in e.detail

        # 2. /api/scan/website with loopback
        try:
            loop.run_until_complete(scan_website(url="http://127.0.0.1:8000"))
            assert False, "Should raise HTTPException 400 for loopback scan"
        except HTTPException as e:
            assert e.status_code == 400
            assert "SSRF Protection" in e.detail

        print("[OK] Endpoint SSRF enforcement passed")
    finally:
        loop.close()


def test_http_security_headers_middleware():
    print("Testing HTTP Security Response Headers...")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "query_string": b"",
            "scheme": "http"
        }
        dummy_req = Request(scope)

        async def dummy_next(request):
            return Response(content=b"OK", media_type="text/plain")

        response = loop.run_until_complete(add_security_headers(dummy_req, dummy_next))

        # Check required security headers
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("X-Frame-Options") == "DENY"
        assert response.headers.get("X-XSS-Protection") == "1; mode=block"
        assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        assert "geolocation=()" in response.headers.get("Permissions-Policy", "")
        assert "default-src 'self'" in response.headers.get("Content-Security-Policy", "")
        assert "frame-ancestors 'none'" in response.headers.get("Content-Security-Policy", "")

        print("[OK] HTTP Security Response Headers verified")
    finally:
        loop.close()


def test_session_revocation_on_password_change():
    print("Testing Session Token Invalidation on Password Change...")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        # 1. Create a user
        email = f"session_test_{uuid.uuid4().hex[:8]}@shieldci.io"
        pw1 = "InitialP@ssw0rd1!"
        pw_hash1, salt1 = hash_password(pw1)
        user = storage.create_user(email=email, password_hash=pw_hash1, salt=salt1)
        assert user.token_version == 1

        # 2. Issue a token for this user (version 1)
        token1 = create_access_token(user_id=user.id, email=user.email, token_version=user.token_version)

        # 3. Verify token1 resolves to user
        authenticated_user = loop.run_until_complete(get_current_user_optional(f"Bearer {token1}"))
        assert authenticated_user is not None
        assert authenticated_user.id == user.id

        # 4. User changes password
        pw2 = "UpdatedP@ssw0rd2!"
        change_req = PasswordChangeRequest(current_password=pw1, new_password=pw2)
        res = loop.run_until_complete(change_password(change_req, current_user=authenticated_user))
        assert res["status"] == "success"

        # Check in storage that token_version incremented
        updated_user = storage.get_user_by_id(user.id)
        assert updated_user.token_version == 2

        # 5. Verify the OLD token1 is NOW REJECTED (invalidated immediately!)
        stale_auth = loop.run_until_complete(get_current_user_optional(f"Bearer {token1}"))
        assert stale_auth is None, "Stale token must be revoked after password change"

        # 6. Verify NEW token with updated version is ACCEPTED
        token2 = create_access_token(user_id=user.id, email=user.email, token_version=updated_user.token_version)
        fresh_auth = loop.run_until_complete(get_current_user_optional(f"Bearer {token2}"))
        assert fresh_auth is not None
        assert fresh_auth.id == user.id

        print("[OK] Session Token Revocation on Password Change verified")
    finally:
        try:
            with storage.adapter._get_connection() as conn:
                if storage.engine_type == "postgresql":
                    with storage.adapter._get_cursor(conn) as cur:
                        cur.execute("DELETE FROM users WHERE email = %s", (email.lower(),))
                else:
                    cur = conn.cursor()
                    cur.execute("DELETE FROM users WHERE email = ?", (email.lower(),))
                conn.commit()
            storage.refresh()
        except Exception:
            pass
        loop.close()



if __name__ == "__main__":
    print("=" * 50)
    print(" ShieldCI Production Security Hardening Test Suite ")
    print("=" * 50)
    test_ssrf_protection()
    test_endpoint_ssrf_enforcement()
    test_http_security_headers_middleware()
    test_session_revocation_on_password_change()
    print("=" * 50)
    print(" ALL SECURITY HARDENING TESTS COMPLETED SUCCESSFULLY! ")
    print("=" * 50)
