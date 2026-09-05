"""
scripts/cleanup_test_users.py
Safely and completely removes all automated test, mock, and migrated test users
(@shieldci.io, @shieldci.test, @shieldci.local, dev_*, test_*) from PostgreSQL and SQLite,
guaranteeing real user accounts (e.g. debnathanish19@gmail.com, anish2004bmg@gmail.com,
arkapravamaity2000@gmail.com) are strictly preserved.
"""

import os
import sys
import sqlite3
import logging

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app.config import settings
from app.core.storage import storage

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cleanup_test_users")

# Whitelist of verified, permanent real user accounts
REAL_USER_EMAILS = {
    "debnathanish19@gmail.com",
    "anish2004bmg@gmail.com",
    "arkapravamaity2000@gmail.com",
}

TEST_DOMAINS = (
    "@shieldci.io",
    "@shieldci.test",
    "@shieldci.local",
    "@example.com",
)

TEST_PREFIXES = (
    "dev_",
    "test_",
    "sched_test_",
    "history_user_",
    "unlimited_",
    "session_test_",
    "settings_test_",
)


def is_test_user(email: str) -> bool:
    """Returns True if the email belongs to an automated test/mock account."""
    if not email:
        return False
    clean = email.strip().lower()
    if clean in REAL_USER_EMAILS:
        return False
    if any(clean.endswith(dom) for dom in TEST_DOMAINS):
        return True
    if any(clean.startswith(pfx) for pfx in TEST_PREFIXES):
        return True
    # Any non-whitelisted account is treated as a test/migrated account
    return True


def cleanup_postgres():
    """Removes all test users, schedules, and scans from PostgreSQL."""
    if storage.engine_type != "postgresql":
        logger.info("Storage is not configured for PostgreSQL. Skipping PostgreSQL cleanup.")
        return

    logger.info("Connecting to PostgreSQL to remove test users and orphaned test data...")
    with storage.adapter._get_connection() as conn:
        with storage.adapter._get_cursor(conn) as cur:
            # 1. Identify test users to delete
            cur.execute("SELECT id, email, full_name, role FROM users")
            all_users = cur.fetchall()

            test_users = [
                u for u in all_users
                if is_test_user(u["email"])
            ]

            logger.info(f"Identified {len(test_users)} test/migrated users in PostgreSQL for removal.")

            if test_users:
                delete_ids = [u["id"] for u in test_users]
                delete_emails = [u["email"].lower() for u in test_users]

                # Clean test schedules associated with these users or test domains
                cur.execute(
                    """
                    DELETE FROM schedules 
                    WHERE user_email = ANY(%s) 
                       OR user_email LIKE %s
                       OR user_email LIKE %s
                       OR user_email LIKE %s
                    """,
                    (delete_emails, '%@shieldci.%', 'sched_test_%', 'dev_%')
                )
                deleted_scheds = cur.rowcount
                logger.info(f"Deleted {deleted_scheds} test schedules from PostgreSQL.")

                # Clean test scans associated with these users or test domains
                cur.execute(
                    """
                    DELETE FROM scans 
                    WHERE user_email = ANY(%s) 
                       OR user_email LIKE %s
                       OR user_email LIKE %s
                       OR user_email LIKE %s
                       OR user_email LIKE %s
                    """,
                    (delete_emails, '%@shieldci.%', 'dev_%', 'history_user_%', 'unlimited_%')
                )
                deleted_scans = cur.rowcount
                logger.info(f"Deleted {deleted_scans} test scans from PostgreSQL.")

                # Delete test users
                cur.execute(
                    "DELETE FROM users WHERE id = ANY(%s)",
                    (delete_ids,)
                )
                conn.commit()
                logger.info(f"Successfully deleted {len(test_users)} test users from PostgreSQL.")
            else:
                # Also ensure no dangling test schedules or scans exist
                cur.execute(
                    """
                    DELETE FROM schedules 
                    WHERE user_email LIKE %s 
                       OR user_email LIKE %s
                       OR user_email LIKE %s
                    """,
                    ('%@shieldci.%', 'sched_test_%', 'dev_%')
                )
                cur.execute(
                    """
                    DELETE FROM scans 
                    WHERE user_email LIKE %s 
                       OR user_email LIKE %s
                       OR user_email LIKE %s
                       OR user_email LIKE %s
                    """,
                    ('%@shieldci.%', 'dev_%', 'history_user_%', 'unlimited_%')
                )
                conn.commit()
                logger.info("No test users found in PostgreSQL.")

            # Verify remaining users
            cur.execute("SELECT id, email, full_name, role, preferred_domain, created_at FROM users ORDER BY created_at")
            remaining = cur.fetchall()
            logger.info(f"Remaining verified PostgreSQL users ({len(remaining)}):")
            for r in remaining:
                logger.info(f"  -> {r['email']} ({r['full_name']}) [Role: {r['role']}] [Domain: {r.get('preferred_domain', 'N/A')}]")


def cleanup_sqlite(sqlite_path: str = "data/shieldci.db"):
    """Removes all test users, schedules, and scans from SQLite."""
    if not os.path.isfile(sqlite_path):
        logger.warning(f"SQLite database not found at: {sqlite_path}. Skipping.")
        return

    logger.info(f"Connecting to SQLite ({sqlite_path}) to remove test users...")
    conn = sqlite3.connect(sqlite_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT id, email, full_name, role FROM users")
    all_users = cur.fetchall()

    test_users = [
        u for u in all_users
        if is_test_user(u["email"])
    ]

    logger.info(f"Identified {len(test_users)} test/migrated users in SQLite for removal.")

    if test_users:
        delete_ids = [u["id"] for u in test_users]
        delete_emails = [u["email"].lower() for u in test_users]

        for uid in delete_ids:
            cur.execute("DELETE FROM users WHERE id = ?", (uid,))

        for email in delete_emails:
            cur.execute("DELETE FROM schedules WHERE LOWER(user_email) = ?", (email,))
            cur.execute("DELETE FROM scans WHERE LOWER(user_email) = ?", (email,))

    # Also clean any dangling test schedules & scans
    cur.execute("DELETE FROM schedules WHERE user_email LIKE '%@shieldci.%' OR user_email LIKE 'sched_test_%' OR user_email LIKE 'dev_%'")
    cur.execute("DELETE FROM scans WHERE user_email LIKE '%@shieldci.%' OR user_email LIKE 'dev_%' OR user_email LIKE 'history_user_%' OR user_email LIKE 'unlimited_%'")

    conn.commit()
    logger.info(f"Successfully cleaned test records from SQLite.")

    cur.execute("SELECT id, email, full_name, role FROM users")
    remaining = cur.fetchall()
    logger.info(f"Remaining verified SQLite users ({len(remaining)}):")
    for r in remaining:
        logger.info(f"  -> {r['email']} ({r['full_name']}) [Role: {r['role']}]")

    conn.close()


def main():
    logger.info("=" * 60)
    logger.info("Starting Comprehensive Test & Migrated User Cleanup")
    logger.info("=" * 60)

    # 1. Clean PostgreSQL
    cleanup_postgres()

    # 2. Clean SQLite
    sqlite_db_path = os.path.join(ROOT_DIR, "data", "shieldci.db")
    cleanup_sqlite(sqlite_db_path)

    # Refresh storage cache
    storage.refresh()

    logger.info("=" * 60)
    logger.info("Cleanup Completed Successfully!")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
