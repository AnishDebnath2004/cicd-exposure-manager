"""
scripts/migrate_sqlite_to_pg.py
Database Migration Tool: Copies data from local SQLite (shieldci.db) to PostgreSQL (Supabase / Neon / RDS).

Usage:
    python scripts/migrate_sqlite_to_pg.py
    python scripts/migrate_sqlite_to_pg.py --pg-url "postgresql://user:pass@host:5432/dbname?sslmode=require"
    python scripts/migrate_sqlite_to_pg.py --sqlite-path data/shieldci.db --dry-run
"""

import os
import sys
import sqlite3
import argparse
import logging

# Ensure project root is in sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app.config import settings
from app.core.storage import PostgresStorageAdapter

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("migrate_to_pg")


def migrate_data(sqlite_path: str, pg_url: str, dry_run: bool = False):
    if not os.path.isfile(sqlite_path):
        logger.error(f"SQLite database file not found at: {sqlite_path}")
        sys.exit(1)

    logger.info(f"Opening source SQLite database: {sqlite_path}")
    sqlite_conn = sqlite3.connect(sqlite_path)
    sqlite_conn.row_factory = sqlite3.Row
    sqlite_cur = sqlite_conn.cursor()

    if dry_run:
        logger.info("[DRY RUN] Simulating migration without writing to PostgreSQL...")
    else:
        logger.info(f"Connecting to target PostgreSQL database...")
        pg_adapter = PostgresStorageAdapter(pg_url)
        if not pg_adapter.check_connection():
            logger.error("Failed to connect to target PostgreSQL instance. Please check your credentials and network.")
            sys.exit(1)
        logger.info("Connected to PostgreSQL successfully. Target tables and schema verified.")

    # 1. Migrate Users
    try:
        sqlite_cur.execute("SELECT * FROM users")
        user_rows = sqlite_cur.fetchall()
        logger.info(f"Found {len(user_rows)} users in SQLite.")
        if not dry_run and user_rows:
            with pg_adapter._get_connection() as conn:
                with pg_adapter._get_cursor(conn) as cur:
                    for u in user_rows:
                        cur.execute("""
                            INSERT INTO users (id, email, password_hash, salt, full_name, organization, role, token_version, created_at, last_login_at)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (id) DO UPDATE SET
                                email = EXCLUDED.email,
                                password_hash = EXCLUDED.password_hash,
                                salt = EXCLUDED.salt,
                                full_name = EXCLUDED.full_name,
                                organization = EXCLUDED.organization,
                                role = EXCLUDED.role,
                                token_version = EXCLUDED.token_version,
                                last_login_at = EXCLUDED.last_login_at;
                        """, (
                            u["id"], u["email"], u["password_hash"], u["salt"],
                            u["full_name"], u["organization"], u["role"],
                            u["token_version"] if "token_version" in u.keys() else 1,
                            u["created_at"], u["last_login_at"]
                        ))
                conn.commit()
            logger.info(f"Successfully migrated {len(user_rows)} users to PostgreSQL.")
    except Exception as e:
        logger.warning(f"Error migrating users table: {e}")

    # 2. Migrate System Settings
    try:
        sqlite_cur.execute("SELECT * FROM system_settings")
        setting_rows = sqlite_cur.fetchall()
        logger.info(f"Found {len(setting_rows)} custom system settings in SQLite.")
        if not dry_run and setting_rows:
            with pg_adapter._get_connection() as conn:
                with pg_adapter._get_cursor(conn) as cur:
                    for s in setting_rows:
                        cur.execute("""
                            INSERT INTO system_settings (key, value_json, updated_at)
                            VALUES (%s, %s, %s)
                            ON CONFLICT (key) DO UPDATE SET
                                value_json = EXCLUDED.value_json,
                                updated_at = EXCLUDED.updated_at;
                        """, (s["key"], s["value_json"], s["updated_at"]))
                conn.commit()
            logger.info(f"Successfully migrated {len(setting_rows)} settings to PostgreSQL.")
    except Exception as e:
        logger.warning(f"Error migrating system_settings table: {e}")

    # 3. Migrate Schedules
    try:
        sqlite_cur.execute("SELECT * FROM schedules")
        sched_rows = sqlite_cur.fetchall()
        logger.info(f"Found {len(sched_rows)} schedules in SQLite.")
        if not dry_run and sched_rows:
            with pg_adapter._get_connection() as conn:
                with pg_adapter._get_cursor(conn) as cur:
                    for sc in sched_rows:
                        keys = sc.keys()
                        cur.execute("""
                            INSERT INTO schedules (
                                id, target, source_type, target_type, branch, interval_minutes,
                                fail_on_severity, max_allowed_pes, enabled, user_email, created_at,
                                last_run_at, last_scan_id, last_pes, last_grade, last_status
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (id) DO UPDATE SET
                                target = EXCLUDED.target,
                                source_type = EXCLUDED.source_type,
                                target_type = EXCLUDED.target_type,
                                branch = EXCLUDED.branch,
                                interval_minutes = EXCLUDED.interval_minutes,
                                fail_on_severity = EXCLUDED.fail_on_severity,
                                max_allowed_pes = EXCLUDED.max_allowed_pes,
                                enabled = EXCLUDED.enabled,
                                user_email = EXCLUDED.user_email,
                                last_run_at = EXCLUDED.last_run_at,
                                last_scan_id = EXCLUDED.last_scan_id,
                                last_pes = EXCLUDED.last_pes,
                                last_grade = EXCLUDED.last_grade,
                                last_status = EXCLUDED.last_status;
                        """, (
                            sc["id"], sc["target"], sc["source_type"],
                            sc["target_type"] if "target_type" in keys else "repository",
                            sc["branch"], sc["interval_minutes"], sc["fail_on_severity"],
                            sc["max_allowed_pes"], sc["enabled"],
                            sc["user_email"] if "user_email" in keys else None,
                            sc["created_at"], sc["last_run_at"], sc["last_scan_id"],
                            sc["last_pes"], sc["last_grade"], sc["last_status"]
                        ))
                conn.commit()
            logger.info(f"Successfully migrated {len(sched_rows)} schedules to PostgreSQL.")
    except Exception as e:
        logger.warning(f"Error migrating schedules table: {e}")

    # 4. Migrate Scans
    try:
        sqlite_cur.execute("SELECT * FROM scans")
        scan_rows = sqlite_cur.fetchall()
        logger.info(f"Found {len(scan_rows)} scans in SQLite.")
        if not dry_run and scan_rows:
            with pg_adapter._get_connection() as conn:
                with pg_adapter._get_cursor(conn) as cur:
                    for s in scan_rows:
                        keys = s.keys()
                        cur.execute("""
                            INSERT INTO scans (
                                scan_id, repo_name, target_path, repo_url, branch, source_type,
                                target_type, timestamp, total_findings, critical_count, high_count, medium_count,
                                low_count, info_count, pipeline_exposure_score, risk_grade,
                                policy_passed, scan_duration_seconds, scanned_files_count, user_email, result_json
                            ) VALUES (
                                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                            )
                            ON CONFLICT (scan_id) DO UPDATE SET
                                repo_name = EXCLUDED.repo_name,
                                target_path = EXCLUDED.target_path,
                                repo_url = EXCLUDED.repo_url,
                                branch = EXCLUDED.branch,
                                source_type = EXCLUDED.source_type,
                                target_type = EXCLUDED.target_type,
                                timestamp = EXCLUDED.timestamp,
                                total_findings = EXCLUDED.total_findings,
                                critical_count = EXCLUDED.critical_count,
                                high_count = EXCLUDED.high_count,
                                medium_count = EXCLUDED.medium_count,
                                low_count = EXCLUDED.low_count,
                                info_count = EXCLUDED.info_count,
                                pipeline_exposure_score = EXCLUDED.pipeline_exposure_score,
                                risk_grade = EXCLUDED.risk_grade,
                                policy_passed = EXCLUDED.policy_passed,
                                scan_duration_seconds = EXCLUDED.scan_duration_seconds,
                                scanned_files_count = EXCLUDED.scanned_files_count,
                                user_email = EXCLUDED.user_email,
                                result_json = EXCLUDED.result_json;
                        """, (
                            s["scan_id"], s["repo_name"], s["target_path"], s["repo_url"],
                            s["branch"], s["source_type"],
                            s["target_type"] if "target_type" in keys else "repository",
                            s["timestamp"], s["total_findings"], s["critical_count"],
                            s["high_count"], s["medium_count"], s["low_count"],
                            s["info_count"], s["pipeline_exposure_score"], s["risk_grade"],
                            s["policy_passed"], s["scan_duration_seconds"],
                            s["scanned_files_count"],
                            s["user_email"] if "user_email" in keys else None,
                            s["result_json"]
                        ))
                conn.commit()
            logger.info(f"Successfully migrated {len(scan_rows)} scans to PostgreSQL.")
    except Exception as e:
        logger.warning(f"Error migrating scans table: {e}")

    # 5. Migrate Guest Quotas
    try:
        sqlite_cur.execute("SELECT * FROM guest_quotas")
        quota_rows = sqlite_cur.fetchall()
        logger.info(f"Found {len(quota_rows)} guest quota records in SQLite.")
        if not dry_run and quota_rows:
            with pg_adapter._get_connection() as conn:
                with pg_adapter._get_cursor(conn) as cur:
                    for q in quota_rows:
                        cur.execute("""
                            INSERT INTO guest_quotas (client_ip, scan_count, reset_at)
                            VALUES (%s, %s, %s)
                            ON CONFLICT (client_ip) DO UPDATE SET
                                scan_count = EXCLUDED.scan_count,
                                reset_at = EXCLUDED.reset_at;
                        """, (q["client_ip"], q["scan_count"], q["reset_at"]))
                conn.commit()
            logger.info(f"Successfully migrated {len(quota_rows)} guest quota records to PostgreSQL.")
    except Exception as e:
        logger.warning(f"Error migrating guest_quotas table: {e}")

    sqlite_conn.close()
    logger.info("=" * 60)
    logger.info(" Migration process completed successfully! ")
    logger.info("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate ShieldCI data from SQLite to PostgreSQL.")
    parser.add_argument(
        "--sqlite-path",
        default=os.path.join(ROOT_DIR, "data", "shieldci.db"),
        help="Path to the SQLite database file (default: data/shieldci.db)"
    )
    parser.add_argument(
        "--pg-url",
        default=settings.normalized_database_url,
        help="Target PostgreSQL connection URL (e.g. postgresql://user:pass@host:5432/dbname). Defaults to DATABASE_URL in environment."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Perform a dry run to inspect SQLite records without modifying PostgreSQL."
    )

    args = parser.parse_args()

    if not args.pg_url and not args.dry_run:
        logger.error("No PostgreSQL connection URL provided. Set DATABASE_URL in .env or pass --pg-url.")
        sys.exit(1)

    migrate_data(args.sqlite_path, args.pg_url or "", dry_run=args.dry_run)
