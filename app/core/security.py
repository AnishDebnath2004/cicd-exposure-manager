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
import socket
import ipaddress
from urllib.parse import urlparse
from typing import Optional, Tuple, Dict, Any

from fastapi import Header, HTTPException, status
from app.models.auth_schemas import UserResponse


# Secret key for HMAC token signing
_ENV_SECRET = os.getenv("SHIELDCI_SECRET_KEY")
if not _ENV_SECRET:
    # If in production without explicit key, generate secure random key per instance
    if os.getenv("APP_ENV", "development").lower() in ("production", "prod"):
        SECRET_KEY = secrets.token_hex(32)
    else:
        SECRET_KEY = "shieldci_super_secret_jwt_hmac_signing_key_2026_devsecops"
else:
    SECRET_KEY = _ENV_SECRET

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


def create_access_token(user_id: str, email: str, token_version: int = 1, expires_seconds: int = 7 * 86400) -> str:
    """
    Generates a cryptographically signed Bearer token containing user claims, token_version, and expiration.
    Format: header_b64.payload_b64.signature_b64
    """
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user_id,
        "email": email,
        "ver": token_version,
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


def validate_safe_url(url: str, allow_private: Optional[bool] = None) -> Tuple[bool, str]:
    """
    Validates a target URL against Server-Side Request Forgery (SSRF).
    Guarantees that outbound HTTP requests cannot target:
    - Cloud metadata (169.254.169.254, fd00:ec2::254, metadata.google.internal)
    - Local loopback (127.0.0.0/8, ::1, localhost)
    - Private networks (RFC1918 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
    - Link-local, multicast, or unspecified IP addresses
    """
    if allow_private is None:
        allow_private = os.getenv("SHIELDCI_ALLOW_PRIVATE_TARGETS", "").lower() in ("true", "1", "yes")

    if not url or not isinstance(url, str):
        return False, "Target URL cannot be empty."

    try:
        parsed = urlparse(url.strip())
    except Exception as e:
        return False, f"Malformed URL: {str(e)}"

    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"Unsupported URL scheme '{parsed.scheme}'. Only http and https are allowed."

    hostname = parsed.hostname
    if not hostname:
        return False, "URL missing valid hostname."

    hostname_lower = hostname.lower()

    # Immediate check for known metadata & loopback hostnames
    if not allow_private:
        restricted_hosts = (
            "localhost", "127.0.0.1", "::1", "0.0.0.0",
            "169.254.169.254", "metadata.google.internal",
            "instance-data", "metadata"
        )
        if hostname_lower in restricted_hosts or hostname_lower.endswith(".internal"):
            return False, f"Target '{hostname}' is a restricted host (SSRF Protection)."

    if allow_private:
        return True, "Target URL allowed (private testing enabled)."

    # Resolve IP addresses for hostname
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    try:
        addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        return False, f"Unable to resolve hostname '{hostname}': {str(e)}"
    except Exception as e:
        return False, f"DNS resolution error for '{hostname}': {str(e)}"

    for entry in addr_info:
        ip_str = entry[4][0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_loopback:
                return False, f"Target resolves to loopback IP {ip_str} (SSRF Protection)."
            if ip_obj.is_private:
                return False, f"Target resolves to private network IP {ip_str} (SSRF Protection)."
            if ip_obj.is_link_local:
                return False, f"Target resolves to link-local/cloud metadata IP {ip_str} (SSRF Protection)."
            if ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
                return False, f"Target resolves to non-routable IP {ip_str} (SSRF Protection)."
        except ValueError:
            return False, f"Invalid IP address resolved: {ip_str}"

    return True, "Target URL validated successfully."

