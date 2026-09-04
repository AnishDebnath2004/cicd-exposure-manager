"""
scripts/reset_password.py
CLI utility to safely reset a user's password directly in the active ShieldCI database (PostgreSQL or SQLite).

Usage:
    python scripts/reset_password.py <email> <new_password>
Example:
    python scripts/reset_password.py debnathanish19@gmail.com "MyNewSecurePassword2026!"
"""

import os
import sys
import argparse
import logging

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app.core.storage import storage
from app.core.security import hash_password, verify_password

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("reset_password")


def reset_password(email: str, new_password: str):
    email = email.strip().lower()
    if len(new_password) < 8:
        logger.error("New password must be at least 8 characters long.")
        sys.exit(1)

    logger.info(f"Target Database Engine: {storage.engine_type.upper()}")
    
    # 1. Look up user
    user = storage.get_user_by_email(email)
    if not user:
        logger.error(f"User with email '{email}' not found in the active database.")
        sys.exit(1)

    logger.info(f"Found user: {user.get('full_name') or email} (ID: {user['id']})")
    
    # 2. Hash new password
    new_hash, new_salt = hash_password(new_password)

    # 3. Update password in database
    success = storage.update_user_password(user["id"], new_hash, new_salt)
    if not success:
        logger.error("Failed to update password in database.")
        sys.exit(1)

    # 4. Verify update
    updated_user = storage.get_user_by_email(email)
    is_valid = verify_password(new_password, updated_user["password_hash"], updated_user["salt"])

    if is_valid:
        logger.info("=" * 60)
        logger.info(f"Password for '{email}' has been successfully updated and verified!")
        logger.info(f"New Token Version: {updated_user.get('token_version')}")
        logger.info("You can now log in using your new password.")
        logger.info("=" * 60)
    else:
        logger.error("Verification failed: updated hash does not match new password.")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Reset a user password in ShieldCI.")
    parser.add_argument("email", help="User email address")
    parser.add_argument("password", help="New password (minimum 8 characters)")
    args = parser.parse_args()

    reset_password(args.email, args.password)
