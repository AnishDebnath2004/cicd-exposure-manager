"""
app/core/security.py
Cryptographic security primitives, password hashing, and token signing for ShieldCI.
Uses standard Python hashlib & hmac for robust, zero-dependency, cross-platform security.
"""

import os
import hmac
import base64
import hashlib
import json
import secrets
import time
from typing import Optional, Tuple, Dict, Any

from fastapi import Header, HTTPException, status
from app.models.auth_schemas import UserResponse


# Secret key for HMAC token signing (can be overridden via environment variable)
SECRET_KEY = os.getenv("SHIELDCI_SECRET_KEY", "shieldci_super_secret_jwt_hmac_signing_key_2026_devsecops")
HASH_ITERATIONS = 200_000


def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """
    Hashes a password using PBKDF2-HMAC-SHA256 with a unique cryptographic salt.
    Returns (hex_digest, salt_hex).
    """
    if not salt:
        salt_bytes = secrets.token_bytes(16)
        salt = salt_bytes.hex()
    else:
        salt_bytes = bytes.fromhex(salt)

    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt_bytes,
        HASH_ITERATIONS
    )
    return key.hex(), salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """
    Verifies a plain password against the stored PBKDF2 hash using constant-time comparison.
    """
    new_hash, _ = hash_password(password, salt=salt)
    return hmac.compare_digest(new_hash, stored_hash)


def _b64_url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def _b64_url_decode(data: str) -> bytes:
    padding = '=' * (4 - (len(data) % 4)) if len(data) % 4 != 0 else ''
    return base64.urlsafe_b64decode((data + padding).encode('utf-8'))


def create_access_token(user_id: str, email: str, expires_seconds: int = 7 * 86400) -> str:
    """
    Generates a cryptographically signed Bearer token containing user claims and expiration.
    Format: header_b64.payload_b64.signature_b64
    """
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user_id,
        "email": email,
        "iat": now,
        "exp": now + expires_seconds
    }

    header_b64 = _b64_url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    payload_b64 = _b64_url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')

    signature = hmac.new(SECRET_KEY.encode('utf-8'), signing_input, hashlib.sha256).digest()
    signature_b64 = _b64_url_encode(signature)

    return f"{header_b64}.{payload_b64}.{signature_b64}"


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Decodes and validates a signed access token.
    Returns the claims dict if valid and non-expired; otherwise None.
    """
    if not token or not isinstance(token, str):
        return None

    # Handle Bearer prefix if passed directly
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    parts = token.split(".")
    if len(parts) != 3:
        return None

    header_b64, payload_b64, signature_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')

    expected_sig = hmac.new(SECRET_KEY.encode('utf-8'), signing_input, hashlib.sha256).digest()
    expected_sig_b64 = _b64_url_encode(expected_sig)

    if not hmac.compare_digest(signature_b64, expected_sig_b64):
        return None

    try:
        payload_bytes = _b64_url_decode(payload_b64)
        claims = json.loads(payload_bytes.decode('utf-8'))
        
        # Check expiration
        exp = claims.get("exp")
        if exp and int(time.time()) > int(exp):
            return None

        return claims
    except Exception:
        return None
