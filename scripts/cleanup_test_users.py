"""
scripts/cleanup_test_users.py
Safely removes all automated test users (@shieldci.io) from PostgreSQL and SQLite,
guaranteeing real user accounts (e.g. debnathanish19@gmail.com) are strictly preserved.
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

REAL_USER_EMAILS = {"debnathanish19@gmail.com"}


def cleanup_postgres():
    logger.info("Connecting to PostgreSQL to remove test users...")
    with storage.adapter._get_connection() as conn:
        with storage.adapter._get_cursor(conn) as cur:
            # 1. Identify test users to delete
            cur.execute("""
                SELECT id, email, full_name, role 
                FROM users 
                WHERE email LIKE '%@shieldci.io'
            """)
            test_users = cur.fetchall()
            
            # Double-check: ensure no real user is ever in the deletion list
            safe_to_delete = [
                u for u in test_users 
                if u["email"].lower() not in REAL_USER_EMAILS
            ]

            logger.info(f"Identified {len(safe_to_delete)} test users in PostgreSQL for removal.")

            if safe_to_delete:
                delete_ids = [u["id"] for u in safe_to_delete]
                
                # Delete test users
                cur.execute(
                    "DELETE FROM users WHERE id = ANY(%s)",
                    (delete_ids,)
                )
                conn.commit()
                logger.info(f"Successfully deleted {len(safe_to_delete)} test users from PostgreSQL.")
            else:
                logger.info("No test users found in PostgreSQL.")

            # Verify remaining users
            cur.execute("SELECT id, email, full_name, role, created_at FROM users")
            remaining = cur.fetchall()
            logger.info(f"Remaining PostgreSQL users ({len(remaining)}):")
            for r in remaining:
                logger.info(f"  -> {r['email']} ({r['full_name']}) [Role: {r['role']}] [ID: {r['id']}]")


def cleanup_sqlite(sqlite_path: str = "data/shieldci.db"):
    if not os.path.isfile(sqlite_path):
        logger.warning(f"SQLite database not found at: {sqlite_path}. Skipping.")
        return

    logger.info(f"Connecting to SQLite ({sqlite_path}) to remove test users...")
    conn = sqlite3.connect(sqlite_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT id, email, full_name, role FROM users WHERE email LIKE '%@shieldci.io'")
    test_users = cur.fetchall()

    safe_to_delete = [
        u for u in test_users 
        if u["email"].lower() not in REAL_USER_EMAILS
    ]

    logger.info(f"Identified {len(safe_to_delete)} test users in SQLite for removal.")

    if safe_to_delete:
        delete_ids = [u["id"] for u in safe_to_delete]
        cur.executemany("DELETE FROM users WHERE id = ?", [(uid,) for uid in delete_ids])
        
        # Also clean test schedules & scans belonging to test users
        cur.execute("DELETE FROM schedules WHERE user_email LIKE '%@shieldci.io'")
        cur.execute("DELETE FROM scans WHERE user_email LIKE '%@shieldci.io'")
        
        conn.commit()
        logger.info(f"Successfully deleted {len(safe_to_delete)} test users from SQLite.")
    else:
        logger.info("No test users found in SQLite.")

    cur.execute("SELECT id, email, full_name, role FROM users")
    remaining = cur.fetchall()
    logger.info(f"Remaining SQLite users ({len(remaining)}):")
    for r in remaining:
        logger.info(f"  -> {r['email']} ({r['full_name']})")

    conn.close()


def main():
    logger.info("=" * 60)
    logger.info("Starting Test User Cleanup")
    logger.info("=" * 60)
    
    # 1. Clean PostgreSQL
    cleanup_postgres()
    
    # 2. Clean SQLite
    sqlite_db_path = os.path.join(ROOT_DIR, "data", "shieldci.db")
    cleanup_sqlite(sqlite_db_path)
    
    logger.info("=" * 60)
    logger.info("Cleanup Completed Successfully!")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
