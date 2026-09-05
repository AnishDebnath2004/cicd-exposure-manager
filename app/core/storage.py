"""
app/core/storage.py
Production storage engine supporting both PostgreSQL (Neon, Supabase, AWS RDS, Render)
and local SQLite fallback for scan history, reports, users, settings, and schedules.
Includes SARIF 2.1.0, JSON, and CSV export generators.
"""

import os
import io
import csv
import json
import uuid
import sqlite3
import logging
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Tuple
from contextlib import contextmanager

from app.config import settings
from app.models.schemas import (
    ScanResult, ScanHistorySummary, ScheduledScan, SeverityLevel, TargetCategory
)
from app.models.auth_schemas import UserResponse

logger = logging.getLogger("shieldci.storage")

# PostgreSQL Driver Resolution (Supports psycopg 3 with connection pool and psycopg2)
_HAS_PSYCOPG = False
_HAS_PSYCOPG_POOL = False
_HAS_PSYCOPG2 = False

try:
    import psycopg
    from psycopg.rows import dict_row
    _HAS_PSYCOPG = True
    try:
        from psycopg_pool import ConnectionPool
        _HAS_PSYCOPG_POOL = True
    except ImportError:
        _HAS_PSYCOPG_POOL = False
except ImportError:
    try:
        import psycopg2
        import psycopg2.extras
        _HAS_PSYCOPG2 = True
    except ImportError:
        pass


# ==============================================================
# SQLite Storage Adapter (Local Development & Fallback)
# ==============================================================
class SQLiteStorageAdapter:
    """Manages SQLite persistence for local development and offline environments."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        try:
            if os.path.dirname(self.db_path):
                os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        except OSError:
            pass

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    repo_name TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    repo_url TEXT,
                    branch TEXT,
                    source_type TEXT NOT NULL,
                    target_type TEXT NOT NULL DEFAULT 'repository',
                    timestamp TEXT NOT NULL,
                    total_findings INTEGER NOT NULL,
                    critical_count INTEGER NOT NULL,
                    high_count INTEGER NOT NULL,
                    medium_count INTEGER NOT NULL,
                    low_count INTEGER NOT NULL,
                    info_count INTEGER NOT NULL,
                    pipeline_exposure_score REAL NOT NULL,
                    risk_grade TEXT NOT NULL,
                    policy_passed INTEGER NOT NULL,
                    scan_duration_seconds REAL NOT NULL,
                    scanned_files_count INTEGER NOT NULL,
                    user_email TEXT,
                    result_json TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS schedules (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    target_type TEXT NOT NULL DEFAULT 'repository',
                    branch TEXT,
                    interval_minutes INTEGER NOT NULL,
                    fail_on_severity TEXT NOT NULL,
                    max_allowed_pes REAL NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    user_email TEXT,
                    created_at TEXT NOT NULL,
                    last_run_at TEXT,
                    last_scan_id TEXT,
                    last_pes REAL,
                    last_grade TEXT,
                    last_status TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    full_name TEXT,
                    organization TEXT,
                    role TEXT NOT NULL DEFAULT 'developer',
                    token_version INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    last_login_at TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS guest_quotas (
                    client_ip TEXT PRIMARY KEY,
                    scan_count INTEGER NOT NULL DEFAULT 0,
                    reset_at TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_settings (
                    key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)

            # Migration check: ensure target_type and user_email exist
            cursor.execute("PRAGMA table_info(scans)")
            columns = [row["name"] for row in cursor.fetchall()]
            if "target_type" not in columns:
                cursor.execute("ALTER TABLE scans ADD COLUMN target_type TEXT NOT NULL DEFAULT 'repository'")
            if "user_email" not in columns:
                cursor.execute("ALTER TABLE scans ADD COLUMN user_email TEXT")

            cursor.execute("PRAGMA table_info(schedules)")
            sched_columns = [row["name"] for row in cursor.fetchall()]
            if "target_type" not in sched_columns:
                cursor.execute("ALTER TABLE schedules ADD COLUMN target_type TEXT NOT NULL DEFAULT 'repository'")
            if "user_email" not in sched_columns:
                cursor.execute("ALTER TABLE schedules ADD COLUMN user_email TEXT")

            cursor.execute("PRAGMA table_info(users)")
            user_columns = [row["name"] for row in cursor.fetchall()]
            if "token_version" not in user_columns:
                cursor.execute("ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 1")
            if "preferred_domain" not in user_columns:
                cursor.execute("ALTER TABLE users ADD COLUMN preferred_domain TEXT DEFAULT 'domain_01'")

            conn.commit()

    def check_connection(self) -> bool:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                return cursor.fetchone() is not None
        except Exception:
            return False

    def save_scan(self, scan: ScanResult):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            s = scan.summary
            target_type_val = scan.target_type.value if hasattr(scan.target_type, "value") else str(scan.target_type)
            cursor.execute("""
                INSERT OR REPLACE INTO scans (
                    scan_id, repo_name, target_path, repo_url, branch, source_type,
                    target_type, timestamp, total_findings, critical_count, high_count, medium_count,
                    low_count, info_count, pipeline_exposure_score, risk_grade,
                    policy_passed, scan_duration_seconds, scanned_files_count, user_email, result_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan.scan_id,
                scan.repo_name,
                scan.target_path,
                scan.repo_url,
                scan.branch,
                scan.source_type.value if hasattr(scan.source_type, "value") else str(scan.source_type),
                target_type_val,
                scan.timestamp.isoformat(),
                s.total_findings,
                s.critical_count,
                s.high_count,
                s.medium_count,
                s.low_count,
                s.info_count,
                s.pipeline_exposure_score,
                s.risk_grade,
                1 if s.policy_passed else 0,
                s.scan_duration_seconds,
                s.scanned_files_count,
                scan.user_email,
                scan.model_dump_json()
            ))
            conn.commit()

    def get_scan(self, scan_id: str) -> Optional[ScanResult]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT result_json FROM scans WHERE scan_id = ?", (scan_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return ScanResult.model_validate_json(row["result_json"])

    def list_scans(
        self,
        limit: int = 50,
        offset: int = 0,
        target_type: Optional[str] = None,
        user_email: Optional[str] = None
    ) -> List[ScanHistorySummary]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query_conditions = []
            params: list = []

            if target_type:
                query_conditions.append("target_type = ?")
                params.append(target_type)

            if user_email:
                query_conditions.append("LOWER(user_email) = LOWER(?)")
                params.append(user_email.strip())
            else:
                query_conditions.append("user_email IS NULL")

            where_clause = " WHERE " + " AND ".join(query_conditions) if query_conditions else ""
            query = f"""
                SELECT scan_id, repo_name, target_path, source_type, target_type, timestamp,
                       pipeline_exposure_score, risk_grade, total_findings,
                       critical_count, high_count, policy_passed, scan_duration_seconds, user_email
                FROM scans
                {where_clause}
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
            """
            params.extend([limit, offset])
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()
            return [
                ScanHistorySummary(
                    scan_id=r["scan_id"],
                    repo_name=r["repo_name"],
                    target_path=r["target_path"],
                    source_type=r["source_type"],
                    target_type=r["target_type"] if "target_type" in r.keys() else "repository",
                    timestamp=datetime.fromisoformat(r["timestamp"]),
                    pipeline_exposure_score=r["pipeline_exposure_score"],
                    risk_grade=r["risk_grade"],
                    total_findings=r["total_findings"],
                    critical_count=r["critical_count"],
                    high_count=r["high_count"],
                    policy_passed=bool(r["policy_passed"]),
                    scan_duration_seconds=r["scan_duration_seconds"],
                    user_email=r["user_email"] if "user_email" in r.keys() else None
                )
                for r in rows
            ]

    def delete_scan(self, scan_id: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            conn.commit()
            return cursor.rowcount > 0

    def save_schedule(
        self,
        sched_id: str,
        target: str,
        source_type: str,
        target_type: str,
        branch: Optional[str],
        interval_minutes: int,
        fail_on_severity: str = "HIGH",
        max_allowed_pes: float = 60.0,
        user_email: Optional[str] = None
    ) -> ScheduledScan:
        created_at = datetime.utcnow().isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO schedules (
                    id, target, source_type, target_type, branch, interval_minutes,
                    fail_on_severity, max_allowed_pes, enabled, user_email, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            """, (
                sched_id, target, source_type, target_type, branch, interval_minutes,
                fail_on_severity, max_allowed_pes, user_email, created_at
            ))
            conn.commit()

        return ScheduledScan(
            id=sched_id,
            target=target,
            source_type=source_type, # type: ignore
            target_type=target_type, # type: ignore
            branch=branch,
            interval_minutes=interval_minutes,
            enabled=True,
            user_email=user_email,
            created_at=datetime.fromisoformat(created_at)
        )

    def get_schedules(self, user_email: Optional[str] = None) -> List[ScheduledScan]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if user_email:
                cursor.execute("SELECT * FROM schedules WHERE LOWER(user_email) = LOWER(?) ORDER BY created_at DESC", (user_email.strip(),))
            else:
                cursor.execute("SELECT * FROM schedules ORDER BY created_at DESC")
            rows = cursor.fetchall()
            return [
                ScheduledScan(
                    id=r["id"],
                    target=r["target"],
                    source_type=r["source_type"],
                    target_type=r["target_type"] if "target_type" in r.keys() else TargetCategory.REPOSITORY,
                    branch=r["branch"],
                    interval_minutes=r["interval_minutes"],
                    enabled=bool(r["enabled"]),
                    user_email=r["user_email"] if "user_email" in r.keys() else None,
                    created_at=datetime.fromisoformat(r["created_at"]),
                    last_run_at=datetime.fromisoformat(r["last_run_at"]) if r["last_run_at"] else None,
                    last_scan_id=r["last_scan_id"],
                    last_pes=r["last_pes"],
                    last_grade=r["last_grade"],
                    last_status=r["last_status"]
                )
                for r in rows
            ]

    def check_and_increment_guest_quota(self, client_ip: str, limit: int = 5) -> Tuple[bool, int, int]:
        now = datetime.utcnow()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT scan_count, reset_at FROM guest_quotas WHERE client_ip = ?", (client_ip,))
            row = cursor.fetchone()
            if not row:
                reset_at = (now + timedelta(days=1)).isoformat()
                cursor.execute("INSERT INTO guest_quotas (client_ip, scan_count, reset_at) VALUES (?, 1, ?)", (client_ip, reset_at))
                conn.commit()
                return True, 1, limit

            reset_at_dt = datetime.fromisoformat(row["reset_at"])
            if now > reset_at_dt:
                reset_at = (now + timedelta(days=1)).isoformat()
                cursor.execute("UPDATE guest_quotas SET scan_count = 1, reset_at = ? WHERE client_ip = ?", (reset_at, client_ip))
                conn.commit()
                return True, 1, limit

            current_count = int(row["scan_count"])
            if current_count >= limit:
                return False, current_count, limit

            new_count = current_count + 1
            cursor.execute("UPDATE guest_quotas SET scan_count = ? WHERE client_ip = ?", (new_count, client_ip))
            conn.commit()
            return True, new_count, limit

    def get_guest_quota(self, client_ip: str, limit: int = 5) -> Tuple[int, int]:
        now = datetime.utcnow()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT scan_count, reset_at FROM guest_quotas WHERE client_ip = ?", (client_ip,))
            row = cursor.fetchone()
            if not row:
                return 0, limit
            reset_at_dt = datetime.fromisoformat(row["reset_at"])
            if now > reset_at_dt:
                return 0, limit
            return int(row["scan_count"]), limit

    def update_schedule_execution(
        self,
        sched_id: str,
        scan_id: str,
        pes: float,
        grade: str,
        status: str
    ):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE schedules
                SET last_run_at = ?, last_scan_id = ?, last_pes = ?, last_grade = ?, last_status = ?
                WHERE id = ?
            """, (datetime.utcnow().isoformat(), scan_id, pes, grade, status, sched_id))
            conn.commit()

    def delete_schedule(self, sched_id: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM schedules WHERE id = ?", (sched_id,))
            conn.commit()
            return cursor.rowcount > 0

    def create_user(
        self,
        email: str,
        password_hash: str,
        salt: str,
        full_name: Optional[str] = None,
        organization: Optional[str] = None,
        role: str = "developer",
        preferred_domain: str = "domain_01"
    ) -> UserResponse:
        user_id = str(uuid.uuid4())
        created_at_dt = datetime.utcnow()
        created_at = created_at_dt.isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (
                    id, email, password_hash, salt, full_name, organization, role, token_version, preferred_domain, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user_id, email.lower().strip(), password_hash, salt,
                full_name.strip() if full_name else None,
                organization.strip() if organization else None,
                role, 1, preferred_domain, created_at
            ))
            conn.commit()

        return UserResponse(
            id=user_id,
            email=email.lower().strip(),
            full_name=full_name.strip() if full_name else None,
            organization=organization.strip() if organization else None,
            role=role,
            preferred_domain=preferred_domain,
            token_version=1,
            created_at=created_at_dt,
            last_login_at=None
        )

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE LOWER(email) = LOWER(?)", (email.strip(),))
            row = cursor.fetchone()
            if not row:
                return None
            return dict(row)

    def get_user_by_id(self, user_id: str) -> Optional[UserResponse]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, email, full_name, organization, role, token_version, preferred_domain, created_at, last_login_at FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            if not row:
                return None
            keys = row.keys()
            tok_ver = row["token_version"] if "token_version" in keys and row["token_version"] is not None else 1
            pref_dom = row["preferred_domain"] if "preferred_domain" in keys and row["preferred_domain"] else "domain_01"
            return UserResponse(
                id=row["id"],
                email=row["email"],
                full_name=row["full_name"],
                organization=row["organization"],
                role=row["role"] or "developer",
                preferred_domain=pref_dom,
                token_version=tok_ver,
                created_at=datetime.fromisoformat(row["created_at"]),
                last_login_at=datetime.fromisoformat(row["last_login_at"]) if row["last_login_at"] else None
            )

    def update_last_login(self, user_id: str):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (datetime.utcnow().isoformat(), user_id))
            conn.commit()

    def update_user_profile(
        self,
        user_id: str,
        full_name: Optional[str] = None,
        organization: Optional[str] = None
    ) -> Optional[UserResponse]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users
                SET full_name = ?, organization = ?
                WHERE id = ?
            """, (
                full_name.strip() if full_name is not None else None,
                organization.strip() if organization is not None else None,
                user_id
            ))
            conn.commit()
        return self.get_user_by_id(user_id)

    def update_user_password(self, user_id: str, new_password_hash: str, salt: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users
                SET password_hash = ?, salt = ?, token_version = COALESCE(token_version, 1) + 1
                WHERE id = ?
            """, (new_password_hash, salt, user_id))
            conn.commit()
            return cursor.rowcount > 0

    def list_users(self, limit: int = 100, offset: int = 0) -> List[UserResponse]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, email, full_name, organization, role, token_version, preferred_domain, created_at, last_login_at
                FROM users
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            """, (limit, offset))
            rows = cursor.fetchall()
            results = []
            for row in rows:
                keys = row.keys()
                tok_ver = row["token_version"] if "token_version" in keys and row["token_version"] is not None else 1
                pref_dom = row["preferred_domain"] if "preferred_domain" in keys and row["preferred_domain"] else "domain_01"
                results.append(UserResponse(
                    id=row["id"],
                    email=row["email"],
                    full_name=row["full_name"],
                    organization=row["organization"],
                    role=row["role"] or "developer",
                    preferred_domain=pref_dom,
                    token_version=tok_ver,
                    created_at=datetime.fromisoformat(row["created_at"]),
                    last_login_at=datetime.fromisoformat(row["last_login_at"]) if row["last_login_at"] else None
                ))
            return results

    def update_user_role(self, user_id: str, new_role: str) -> Optional[UserResponse]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users
                SET role = ?, token_version = COALESCE(token_version, 1) + 1
                WHERE id = ?
            """, (new_role, user_id))
            conn.commit()
            if cursor.rowcount > 0:
                return self.get_user_by_id(user_id)
            return None

    def update_user_preferred_domain(self, user_id: str, domain: str) -> Optional[UserResponse]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users
                SET preferred_domain = ?
                WHERE id = ?
            """, (domain, user_id))
            conn.commit()
            if cursor.rowcount > 0:
                return self.get_user_by_id(user_id)
            return None

    def get_system_settings(self, defaults: Dict[str, Any]) -> Dict[str, Any]:
        merged = dict(defaults)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT key, value_json FROM system_settings")
            rows = cursor.fetchall()
            for row in rows:
                k = row["key"]
                try:
                    merged[k] = json.loads(row["value_json"])
                except Exception:
                    pass
        return merged

    def save_system_settings(self, updates: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
        now = datetime.utcnow().isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            for key, val in updates.items():
                if val is not None:
                    if hasattr(val, "value"):
                        val = val.value
                    current[key] = val
                    cursor.execute("""
                        INSERT OR REPLACE INTO system_settings (key, value_json, updated_at)
                        VALUES (?, ?, ?)
                    """, (key, json.dumps(val), now))
            conn.commit()
        return current

    def reset_system_settings(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM system_settings")
            conn.commit()


# ==============================================================
# PostgreSQL Storage Adapter (Production, Cloud & Serverless)
# ==============================================================
class PostgresStorageAdapter:
    """Production PostgreSQL persistence engine for Supabase, Neon, AWS RDS, and Render."""

    def __init__(self, connection_url: str):
        self.connection_url = connection_url
        self._pool = None
        self._driver = "psycopg" if _HAS_PSYCOPG else ("psycopg2" if _HAS_PSYCOPG2 else None)
        if not self._driver:
            raise RuntimeError(
                "Neither 'psycopg' nor 'psycopg2' is installed. Please run: pip install psycopg[binary]"
            )
        self._init_pool()
        self._init_db()

    def _init_pool(self):
        """Initializes connection pool with sensible limits for cloud/serverless."""
        if _HAS_PSYCOPG_POOL:
            try:
                # 10s connection timeout, max 10 concurrent connections
                self._pool = ConnectionPool(
                    conninfo=self.connection_url,
                    min_size=1,
                    max_size=10,
                    timeout=15.0,
                    open=True,
                    kwargs={"prepare_threshold": None}
                )
            except Exception as e:
                logger.warning(f"Failed to open ConnectionPool: {e}. Falling back to on-demand connections.")
                self._pool = None

    def close(self):
        """Gracefully closes the connection pool if open."""
        if self._pool is not None:
            try:
                self._pool.close()
            except Exception:
                pass
            self._pool = None

    @contextmanager
    def _get_connection(self):
        """Context manager yielding an active database connection."""
        if self._pool is not None:
            with self._pool.connection() as conn:
                yield conn
        elif self._driver == "psycopg":
            conn = psycopg.connect(self.connection_url, autocommit=False, prepare_threshold=None)
            try:
                yield conn
            finally:
                conn.close()
        elif self._driver == "psycopg2":
            conn = psycopg2.connect(self.connection_url)
            try:
                yield conn
            finally:
                conn.close()
        else:
            raise RuntimeError("No available PostgreSQL driver found.")

    def _get_cursor(self, conn):
        """Returns a dictionary-row cursor based on active driver."""
        if self._driver == "psycopg":
            return conn.cursor(row_factory=dict_row)
        elif self._driver == "psycopg2":
            return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        return conn.cursor()

    def _init_db(self):
        """Ensures all PostgreSQL tables and performance indexes exist."""
        with self._get_connection() as conn:
            with self._get_cursor(conn) as cursor:
                # 1. Scans Table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scans (
                        scan_id VARCHAR(128) PRIMARY KEY,
                        repo_name VARCHAR(255) NOT NULL,
                        target_path TEXT NOT NULL,
                        repo_url TEXT,
                        branch VARCHAR(255),
                        source_type VARCHAR(64) NOT NULL,
                        target_type VARCHAR(64) NOT NULL DEFAULT 'repository',
                        timestamp VARCHAR(64) NOT NULL,
                        total_findings INTEGER NOT NULL,
                        critical_count INTEGER NOT NULL,
                        high_count INTEGER NOT NULL,
                        medium_count INTEGER NOT NULL,
                        low_count INTEGER NOT NULL,
                        info_count INTEGER NOT NULL,
                        pipeline_exposure_score DOUBLE PRECISION NOT NULL,
                        risk_grade VARCHAR(64) NOT NULL,
                        policy_passed INTEGER NOT NULL,
                        scan_duration_seconds DOUBLE PRECISION NOT NULL,
                        scanned_files_count INTEGER NOT NULL,
                        user_email VARCHAR(255),
                        result_json TEXT NOT NULL
                    );
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans (timestamp DESC);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_email ON scans (user_email);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_target_type ON scans (target_type);")

                # 2. Schedules Table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS schedules (
                        id VARCHAR(128) PRIMARY KEY,
                        target TEXT NOT NULL,
                        source_type VARCHAR(64) NOT NULL,
                        target_type VARCHAR(64) NOT NULL DEFAULT 'repository',
                        branch VARCHAR(255),
                        interval_minutes INTEGER NOT NULL,
                        fail_on_severity VARCHAR(32) NOT NULL,
                        max_allowed_pes DOUBLE PRECISION NOT NULL,
                        enabled INTEGER NOT NULL DEFAULT 1,
                        user_email VARCHAR(255),
                        created_at VARCHAR(64) NOT NULL,
                        last_run_at VARCHAR(64),
                        last_scan_id VARCHAR(128),
                        last_pes DOUBLE PRECISION,
                        last_grade VARCHAR(64),
                        last_status VARCHAR(64)
                    );
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_schedules_user_email ON schedules (user_email);")

                # 3. Users Table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id VARCHAR(128) PRIMARY KEY,
                        email VARCHAR(255) UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        salt VARCHAR(128) NOT NULL,
                        full_name VARCHAR(255),
                        organization VARCHAR(255),
                        role VARCHAR(64) NOT NULL DEFAULT 'developer',
                        token_version INTEGER NOT NULL DEFAULT 1,
                        created_at VARCHAR(64) NOT NULL,
                        last_login_at VARCHAR(64)
                    );
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users (LOWER(email));")

                # 4. Guest Quotas Table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS guest_quotas (
                        client_ip VARCHAR(128) PRIMARY KEY,
                        scan_count INTEGER NOT NULL DEFAULT 0,
                        reset_at VARCHAR(64) NOT NULL
                    );
                """)

                # 5. System Settings Table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS system_settings (
                        key VARCHAR(128) PRIMARY KEY,
                        value_json TEXT NOT NULL,
                        updated_at VARCHAR(64) NOT NULL
                    );
                """)

                # Migration checks via information_schema
                cursor.execute("""
                    SELECT column_name FROM information_schema.columns
                    WHERE table_name = 'scans' AND table_schema = current_schema();
                """)
                scan_cols = [r["column_name"] for r in cursor.fetchall()]
                if "target_type" not in scan_cols:
                    cursor.execute("ALTER TABLE scans ADD COLUMN target_type VARCHAR(64) NOT NULL DEFAULT 'repository';")
                if "user_email" not in scan_cols:
                    cursor.execute("ALTER TABLE scans ADD COLUMN user_email VARCHAR(255);")

                cursor.execute("""
                    SELECT column_name FROM information_schema.columns
                    WHERE table_name = 'schedules' AND table_schema = current_schema();
                """)
                sched_cols = [r["column_name"] for r in cursor.fetchall()]
                if "target_type" not in sched_cols:
                    cursor.execute("ALTER TABLE schedules ADD COLUMN target_type VARCHAR(64) NOT NULL DEFAULT 'repository';")
                if "user_email" not in sched_cols:
                    cursor.execute("ALTER TABLE schedules ADD COLUMN user_email VARCHAR(255);")

                cursor.execute("""
                    SELECT column_name FROM information_schema.columns
                    WHERE table_name = 'users' AND table_schema = current_schema();
                """)
                user_cols = [r["column_name"] for r in cursor.fetchall()]
                if "token_version" not in user_cols:
                    cursor.execute("ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 1;")
                if "preferred_domain" not in user_cols:
                    cursor.execute("ALTER TABLE users ADD COLUMN preferred_domain VARCHAR(64) DEFAULT 'domain_01';")

                # Ensure grade columns have sufficient capacity for descriptive grades like 'F (Critical Exposure)'
                try:
                    cursor.execute("ALTER TABLE scans ALTER COLUMN risk_grade TYPE VARCHAR(64);")
                except Exception:
                    pass
                try:
                    cursor.execute("ALTER TABLE schedules ALTER COLUMN last_grade TYPE VARCHAR(64);")
                except Exception:
                    pass

            conn.commit()

    def check_connection(self) -> bool:
        try:
            with self._get_connection() as conn:
                with self._get_cursor(conn) as cursor:
                    cursor.execute("SELECT 1 as alive;")
                    row = cursor.fetchone()
                    return row is not None
        except Exception as e:
            logger.warning(f"PostgreSQL health check failed: {e}")
            return False

    def save_scan(self, scan: ScanResult):
        with self._get_connection() as conn:
            with self._get_cursor(conn) as cursor:
                s = scan.summary
                target_type_val = scan.target_type.value if hasattr(scan.target_type, "value") else str(scan.target_type)
                cursor.execute("""
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
                    scan.scan_id,
                    scan.repo_name,
                    scan.target_path,
                    scan.repo_url,
                    scan.branch,
                    scan.source_type.value if hasattr(scan.source_type, "value") else str(scan.source_type),
                    target_type_val,
                    scan.timestamp.isoformat(),
                    s.total_findings,
                    s.critical_count,
                    s.high_count,
                    s.medium_count,
                    s.low_count,
                    s.info_count,
                    s.pipeline_exposure_score,
                    s.risk_grade,
                    1 if s.policy_passed else 0,
                    s.scan_duration_seconds,
                    s.scanned_files_count,
                    scan.user_email,
                    scan.model_dump_json()
                ))
            conn.commit()

    def get_scan(self, scan_id: str) -> Optional[ScanResult]:
        with self._get_connection() as conn:
            with self._get_cursor(conn) as cursor:
                cursor.execute("SELECT result_json FROM scans WHERE scan_id = %s", (scan_id,))
                row = cursor.fetchone()
                if not row:
                    return None
                return ScanResult.model_validate_json(row["result_json"])

    def list_scans(
        self,
        limit: int = 50,
        offset: int = 0,
        target_type: Optional[str] = None,
        user_email: Optional[str] = None
    ) -> List[ScanHistorySummary]:
        with self._get_connection() as conn:
            with self._get_cursor(conn) as cursor:
                query_conditions = []
                params: list = []

                if target_type:
                    query_conditions.append("target_type = %s")
                    params.append(target_type)

                if user_email:
                    query_conditions.append("LOWER(user_email) = LOWER(%s)")
                    params.append(user_email.strip())
                else:
                    query_conditions.append("user_email IS NULL")

                where_clause = " WHERE " + " AND ".join(query_conditions) if query_conditions else ""
                query = f"""
                    SELECT scan_id, repo_name, target_path, source_type, target_type, timestamp,
                           pipeline_exposure_score, risk_grade, total_findings,
                           critical_count, high_count, policy_passed, scan_duration_seconds, user_email
                    FROM scans
                    {where_clause}
                    ORDER BY timestamp DESC
                    LIMIT %s OFFSET %s
                """
                params.extend([limit, offset])
                cursor.execute(query, tuple(params))
                rows = cursor.fetchall()
                return [
                    ScanHistorySummary(
                        scan_id=r["scan_id"],
                        repo_name=r["repo_name"],
                        target_path=r["target_path"],
                        source_type=r["source_type"],
                        target_type=r["target_type"] if "target_type" in r else "repository",
                        timestamp=datetime.fromisoformat(r["timestamp"]),
                        pipeline_exposure_score=r["pipeline_exposure_score"],
                        risk_grade=r["risk_grade"],
                        total_findings=r["total_findings"],
                        critical_count=r["critical_count"],
                        high_count=r["high_count"],
                        policy_passed=bool(r["policy_passed"]),
                        scan_duration_seconds=r["scan_duration_seconds"],
                        user_email=r["user_email"] if "user_email" in r else None
                    )
                    for r in rows
                ]

    def delete_scan(self, scan_id: str) -> bool:
        with self._get_connection() as conn:
            with self._get_cursor(conn) as cursor:
                cursor.execute("DELETE FROM scans WHERE scan_id = %s", (scan_id,))
                rc = cursor.rowcount
            conn.commit()
            return rc > 0

    def save_schedule(
        self,
        sched_id: str,
        target: str,
        source_type: str,
        target_type: str,
        branch: Optional[str],
        interval_minutes: int,
        fail_on_severity: str = "HIGH",
        max_allowed_pes: float = 60.0,
        user_email: Optional[str] = None
    ) -> ScheduledScan:
        created_at = datetime.utcnow().isoformat()
        with self._get_connection() as conn:
            with self._get_cursor(conn) as cursor:
                cursor.execute("""
                    INSERT INTO schedules (
                        id, target, source_type, target_type, branch, interval_minutes,
                        fail_on_severity, max_allowed_pes, enabled, user_email, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 1, %s, %s)
                    ON CONFLICT (id) DO UPDATE SET
                        target = EXCLUDED.target,
                        source_type = EXCLUDED.source_type,
                        target_type = EXCLUDED.target_type,
                        branch = EXCLUDED.branch,
                        interval_minutes = EXCLUDED.interval_minutes,
                        fail_on_severity = EXCLUDED.fail_on_severity,
                        max_allowed_pes = EXCLUDED.max_allowed_pes,
                        user_email = EXCLUDED.user_email;
                """, (
                    sched_id, target, source_type, target_type, branch, interval_minutes,
                    fail_on_severity, max_allowed_pes, user_email, created_at
                ))
            conn.commit()

        return ScheduledScan(
            id=sched_id,
            target=target,
            source_type=source_type, # type: ignore
            target_type=target_type, # type: ignore
            branch=branch,
            interval_minutes=interval_minutes,
            enabled=True,
            user_email=user_email,
            created_at=datetime.fromisoformat(created_at)
        )

    def get_schedules(self, user_email: Optional[str] = None) -> List[ScheduledScan]:
        with self._get_connection() as conn:
            with self._get_cursor(conn) as cursor:
                if user_email:
                    cursor.execute("SELECT * FROM schedules WHERE LOWER(user_email) = LOWER(%s) ORDER BY created_at DESC", (user_email.strip(),))
                else:
                    cursor.execute("SELECT * FROM schedules ORDER BY created_at DESC")
                rows = cursor.fetchall()
                return [
                    ScheduledScan(
                        id=r["id"],
                        target=r["target"],
                        source_type=r["source_type"],
                        target_type=r["target_type"] if "target_type" in r else TargetCategory.REPOSITORY,
                        branch=r["branch"],
                        interval_minutes=r["interval_minutes"],
                        enabled=bool(r["enabled"]),
                        user_email=r["user_email"] if "user_email" in r else None,
                        created_at=datetime.fromisoformat(r["created_at"]),
                        last_run_at=datetime.fromisoformat(r["last_run_at"]) if r["last_run_at"] else None,
                        last_scan_id=r["last_scan_id"],
                        last_pes=r["last_pes"],
                        last_grade=r["last_grade"],
                        last_status=r["last_status"]
                    )
                    for r in rows
                ]

    def check_and_increment_guest_quota(self, client_ip: str, limit: int = 5) -> Tuple[bool, int, int]:
        now = datetime.utcnow()
        with self._get_connection() as conn:
            with self._get_cursor(conn) as cursor:
                cursor.execute("SELECT scan_count, reset_at FROM guest_quotas WHERE client_ip = %s", (client_ip,))
                row = cursor.fetchone()
                if not row:
                    reset_at = (now + timedelta(days=1)).isoformat()
                    cursor.execute("INSERT INTO guest_quotas (client_ip, scan_count, reset_at) VALUES (%s, 1, %s)", (client_ip, reset_at))
                    conn.commit()
                    return True, 1, limit

                reset_at_dt = datetime.fromisoformat(row["reset_at"])
                if now > reset_at_dt:
                    reset_at = (now + timedelta(days=1)).isoformat()
                    cursor.execute("UPDATE guest_quotas SET scan_count = 1, reset_at = %s WHERE client_ip = %s", (reset_at, client_ip))
                    conn.commit()
                    return True, 1, limit

                current_count = int(row["scan_count"])
                if current_count >= limit:
                    return False, current_count, limit

                new_count = current_count + 1
                cursor.execute("UPDATE guest_quotas SET scan_count = %s WHERE client_ip = %s", (new_count, client_ip))
            conn.commit()
            return True, new_count, limit

    def get_guest_quota(self, client_ip: str, limit: int = 5) -> Tuple[int, int]:
        now = datetime.utcnow()
        with self._get_connection() as conn:
            with self._get_cursor(conn) as cursor:
                cursor.execute("SELECT scan_count, reset_at FROM guest_quotas WHERE client_ip = %s", (client_ip,))
                row = cursor.fetchone()
                if not row:
                    return 0, limit
                reset_at_dt = datetime.fromisoformat(row["reset_at"])
                if now > reset_at_dt:
                    return 0, limit
                return int(row["scan_count"]), limit

    def update_schedule_execution(
        self,
        sched_id: str,
        scan_id: str,
        pes: float,
        grade: str,
        status: str
    ):
        with self._get_connection() as conn:
            with self._get_cursor(conn) as cursor:
                cursor.execute("""
                    UPDATE schedules
                    SET last_run_at = %s, last_scan_id = %s, last_pes = %s, last_grade = %s, last_status = %s
                    WHERE id = %s
                """, (datetime.utcnow().isoformat(), scan_id, pes, grade, status, sched_id))
            conn.commit()

    def delete_schedule(self, sched_id: str) -> bool:
        with self._get_connection() as conn:
            with self._get_cursor(conn) as cursor:
                cursor.execute("DELETE FROM schedules WHERE id = %s", (sched_id,))
                rc = cursor.rowcount
            conn.commit()
            return rc > 0

    def create_user(
        self,
        email: str,
        password_hash: str,
        salt: str,
        full_name: Optional[str] = None,
        organization: Optional[str] = None,
        role: str = "developer",
        preferred_domain: str = "domain_01"
    ) -> UserResponse:
        user_id = str(uuid.uuid4())
        created_at_dt = datetime.utcnow()
        created_at = created_at_dt.isoformat()
        with self._get_connection() as conn:
            with self._get_cursor(conn) as cursor:
                cursor.execute("""
                    INSERT INTO users (
                        id, email, password_hash, salt, full_name, organization, role, token_version, preferred_domain, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    user_id, email.lower().strip(), password_hash, salt,
                    full_name.strip() if full_name else None,
                    organization.strip() if organization else None,
                    role, 1, preferred_domain, created_at
                ))
            conn.commit()

        return UserResponse(
            id=user_id,
            email=email.lower().strip(),
            full_name=full_name.strip() if full_name else None,
            organization=organization.strip() if organization else None,
            role=role,
            preferred_domain=preferred_domain,
            token_version=1,
            created_at=created_at_dt,
            last_login_at=None
        )

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            with self._get_cursor(conn) as cursor:
                cursor.execute("SELECT * FROM users WHERE LOWER(email) = LOWER(%s)", (email.strip(),))
                row = cursor.fetchone()
                if not row:
                    return None
                return dict(row)

    def get_user_by_id(self, user_id: str) -> Optional[UserResponse]:
        with self._get_connection() as conn:
            with self._get_cursor(conn) as cursor:
                cursor.execute("SELECT id, email, full_name, organization, role, token_version, preferred_domain, created_at, last_login_at FROM users WHERE id = %s", (user_id,))
                row = cursor.fetchone()
                if not row:
                    return None
                tok_ver = row.get("token_version") or 1
                pref_dom = row.get("preferred_domain") or "domain_01"
                return UserResponse(
                    id=row["id"],
                    email=row["email"],
                    full_name=row["full_name"],
                    organization=row["organization"],
                    role=row["role"] or "developer",
                    preferred_domain=pref_dom,
                    token_version=tok_ver,
                    created_at=datetime.fromisoformat(row["created_at"]),
                    last_login_at=datetime.fromisoformat(row["last_login_at"]) if row.get("last_login_at") else None
                )

    def update_last_login(self, user_id: str):
        with self._get_connection() as conn:
            with self._get_cursor(conn) as cursor:
                cursor.execute("UPDATE users SET last_login_at = %s WHERE id = %s", (datetime.utcnow().isoformat(), user_id))
            conn.commit()

    def update_user_profile(
        self,
        user_id: str,
        full_name: Optional[str] = None,
        organization: Optional[str] = None
    ) -> Optional[UserResponse]:
        with self._get_connection() as conn:
            with self._get_cursor(conn) as cursor:
                cursor.execute("""
                    UPDATE users
                    SET full_name = %s, organization = %s
                    WHERE id = %s
                """, (
                    full_name.strip() if full_name is not None else None,
                    organization.strip() if organization is not None else None,
                    user_id
                ))
            conn.commit()
        return self.get_user_by_id(user_id)

    def update_user_password(self, user_id: str, new_password_hash: str, salt: str) -> bool:
        with self._get_connection() as conn:
            with self._get_cursor(conn) as cursor:
                cursor.execute("""
                    UPDATE users
                    SET password_hash = %s, salt = %s, token_version = COALESCE(token_version, 1) + 1
                    WHERE id = %s
                """, (new_password_hash, salt, user_id))
                rc = cursor.rowcount
            conn.commit()
            return rc > 0

    def list_users(self, limit: int = 100, offset: int = 0) -> List[UserResponse]:
        with self._get_connection() as conn:
            with self._get_cursor(conn) as cursor:
                cursor.execute("""
                    SELECT id, email, full_name, organization, role, token_version, preferred_domain, created_at, last_login_at
                    FROM users
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                """, (limit, offset))
                rows = cursor.fetchall()
                results = []
                for row in rows:
                    tok_ver = row.get("token_version") or 1
                    pref_dom = row.get("preferred_domain") or "domain_01"
                    results.append(UserResponse(
                        id=row["id"],
                        email=row["email"],
                        full_name=row["full_name"],
                        organization=row["organization"],
                        role=row["role"] or "developer",
                        preferred_domain=pref_dom,
                        token_version=tok_ver,
                        created_at=datetime.fromisoformat(row["created_at"]),
                        last_login_at=datetime.fromisoformat(row["last_login_at"]) if row.get("last_login_at") else None
                    ))
                return results

    def update_user_role(self, user_id: str, new_role: str) -> Optional[UserResponse]:
        with self._get_connection() as conn:
            with self._get_cursor(conn) as cursor:
                cursor.execute("""
                    UPDATE users
                    SET role = %s, token_version = COALESCE(token_version, 1) + 1
                    WHERE id = %s
                """, (new_role, user_id))
                rc = cursor.rowcount
            conn.commit()
            if rc > 0:
                return self.get_user_by_id(user_id)
            return None

    def update_user_preferred_domain(self, user_id: str, domain: str) -> Optional[UserResponse]:
        with self._get_connection() as conn:
            with self._get_cursor(conn) as cursor:
                cursor.execute("""
                    UPDATE users
                    SET preferred_domain = %s
                    WHERE id = %s
                """, (domain, user_id))
                rc = cursor.rowcount
            conn.commit()
            if rc > 0:
                return self.get_user_by_id(user_id)
            return None

    def get_system_settings(self, defaults: Dict[str, Any]) -> Dict[str, Any]:
        merged = dict(defaults)
        with self._get_connection() as conn:
            with self._get_cursor(conn) as cursor:
                cursor.execute("SELECT key, value_json FROM system_settings")
                rows = cursor.fetchall()
                for row in rows:
                    k = row["key"]
                    try:
                        merged[k] = json.loads(row["value_json"])
                    except Exception:
                        pass
        return merged

    def save_system_settings(self, updates: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
        now = datetime.utcnow().isoformat()
        with self._get_connection() as conn:
            with self._get_cursor(conn) as cursor:
                for key, val in updates.items():
                    if val is not None:
                        if hasattr(val, "value"):
                            val = val.value
                        current[key] = val
                        cursor.execute("""
                            INSERT INTO system_settings (key, value_json, updated_at)
                            VALUES (%s, %s, %s)
                            ON CONFLICT (key) DO UPDATE SET
                                value_json = EXCLUDED.value_json,
                                updated_at = EXCLUDED.updated_at;
                        """, (key, json.dumps(val), now))
            conn.commit()
        return current

    def reset_system_settings(self):
        with self._get_connection() as conn:
            with self._get_cursor(conn) as cursor:
                cursor.execute("DELETE FROM system_settings")
            conn.commit()


# ==============================================================
# Master Storage Engine (Dual-Engine Proxy)
# ==============================================================
class StorageEngine:
    """
    Unified Storage Engine. Automatically routes operations to PostgreSQL when
    DATABASE_URL is provided, or seamlessly falls back to SQLite for local development.
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        database_url: Optional[str] = None
    ):
        self.db_path = db_path or settings.DB_PATH
        self.database_url = database_url or settings.normalized_database_url
        self.adapter = None
        self.engine_type = "sqlite"

        self._initialize_backend()
        self._sync_runtime_settings()

    def _initialize_backend(self):
        """Attempts to initialize PostgreSQL backend; gracefully falls back to SQLite."""
        if self.database_url and (
            self.database_url.startswith("postgresql://") or self.database_url.startswith("postgres://")
        ):
            try:
                logger.info(f"Initializing PostgreSQL storage adapter...")
                self.adapter = PostgresStorageAdapter(self.database_url)
                self.engine_type = "postgresql"
                logger.info("Successfully connected to PostgreSQL storage backend.")
                return
            except Exception as e:
                logger.error(
                    f"Failed to connect to PostgreSQL ({e}). Falling back to local SQLite at {self.db_path}."
                )

        # Fallback to local SQLite
        self.adapter = SQLiteStorageAdapter(self.db_path)
        self.engine_type = "sqlite"
        logger.info(f"Using SQLite storage backend at {self.db_path}.")

    def check_connection(self) -> bool:
        """Returns True if the active database backend is responsive."""
        return self.adapter.check_connection()

    def save_scan(self, scan: ScanResult):
        return self.adapter.save_scan(scan)

    def get_scan(self, scan_id: str) -> Optional[ScanResult]:
        return self.adapter.get_scan(scan_id)

    def list_scans(
        self,
        limit: int = 50,
        offset: int = 0,
        target_type: Optional[str] = None,
        user_email: Optional[str] = None
    ) -> List[ScanHistorySummary]:
        return self.adapter.list_scans(
            limit=limit, offset=offset, target_type=target_type, user_email=user_email
        )

    def delete_scan(self, scan_id: str) -> bool:
        return self.adapter.delete_scan(scan_id)

    def save_schedule(
        self,
        sched_id: str,
        target: str,
        source_type: str,
        target_type: str,
        branch: Optional[str],
        interval_minutes: int,
        fail_on_severity: str = "HIGH",
        max_allowed_pes: float = 60.0,
        user_email: Optional[str] = None
    ) -> ScheduledScan:
        return self.adapter.save_schedule(
            sched_id=sched_id,
            target=target,
            source_type=source_type,
            target_type=target_type,
            branch=branch,
            interval_minutes=interval_minutes,
            fail_on_severity=fail_on_severity,
            max_allowed_pes=max_allowed_pes,
            user_email=user_email
        )

    def get_schedules(self, user_email: Optional[str] = None) -> List[ScheduledScan]:
        return self.adapter.get_schedules(user_email=user_email)

    def check_and_increment_guest_quota(self, client_ip: str, limit: int = 5) -> Tuple[bool, int, int]:
        return self.adapter.check_and_increment_guest_quota(client_ip=client_ip, limit=limit)

    def get_guest_quota(self, client_ip: str, limit: int = 5) -> Tuple[int, int]:
        return self.adapter.get_guest_quota(client_ip=client_ip, limit=limit)

    def update_schedule_execution(
        self,
        sched_id: str,
        scan_id: str,
        pes: float,
        grade: str,
        status: str
    ):
        return self.adapter.update_schedule_execution(
            sched_id=sched_id, scan_id=scan_id, pes=pes, grade=grade, status=status
        )

    def delete_schedule(self, sched_id: str) -> bool:
        return self.adapter.delete_schedule(sched_id)

    def create_user(
        self,
        email: str,
        password_hash: str,
        salt: str,
        full_name: Optional[str] = None,
        organization: Optional[str] = None,
        role: str = "developer",
        preferred_domain: str = "domain_01"
    ) -> UserResponse:
        return self.adapter.create_user(
            email=email,
            password_hash=password_hash,
            salt=salt,
            full_name=full_name,
            organization=organization,
            role=role,
            preferred_domain=preferred_domain
        )

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        return self.adapter.get_user_by_email(email)

    def get_user_by_id(self, user_id: str) -> Optional[UserResponse]:
        return self.adapter.get_user_by_id(user_id)

    def update_last_login(self, user_id: str):
        return self.adapter.update_last_login(user_id)

    def update_user_profile(
        self,
        user_id: str,
        full_name: Optional[str] = None,
        organization: Optional[str] = None
    ) -> Optional[UserResponse]:
        return self.adapter.update_user_profile(
            user_id=user_id, full_name=full_name, organization=organization
        )

    def update_user_password(self, user_id: str, new_password_hash: str, salt: str) -> bool:
        return self.adapter.update_user_password(
            user_id=user_id, new_password_hash=new_password_hash, salt=salt
        )

    def list_users(self, limit: int = 100, offset: int = 0) -> List[UserResponse]:
        return self.adapter.list_users(limit=limit, offset=offset)

    def update_user_role(self, user_id: str, new_role: str) -> Optional[UserResponse]:
        return self.adapter.update_user_role(user_id=user_id, new_role=new_role)

    def update_user_preferred_domain(self, user_id: str, domain: str) -> Optional[UserResponse]:
        return self.adapter.update_user_preferred_domain(user_id=user_id, domain=domain)

    def _sync_runtime_settings(self):
        """Synchronizes persisted settings into in-memory settings config."""
        try:
            stored = self.get_system_settings()
            settings.apply_settings_dict(stored)
        except Exception:
            pass

    def refresh(self) -> Dict[str, Any]:
        """Synchronizes runtime settings and verifies health of active database backend."""
        self._sync_runtime_settings()
        connected = self.check_connection()
        return {
            "engine": self.engine_type,
            "connected": connected
        }

    @staticmethod
    def get_default_settings_dict() -> Dict[str, Any]:
        """Returns factory default settings dictionary."""
        return {
            "default_fail_severity": settings.policy_gate.DEFAULT_FAIL_SEVERITY,
            "default_max_pes": settings.policy_gate.DEFAULT_MAX_PES,
            "auto_fail_on_toxic_combos": getattr(settings, "AUTO_FAIL_ON_TOXIC_COMBOS", True),
            "shannon_entropy_threshold": settings.scanner.SHANNON_ENTROPY_THRESHOLD,
            "min_token_length_for_entropy": settings.scanner.MIN_TOKEN_LENGTH_FOR_ENTROPY,
            "ignored_directories": sorted(list(settings.scanner.IGNORED_DIRECTORIES)),
            "ignored_extensions": sorted(list(settings.scanner.IGNORED_EXTENSIONS)),
            "weight_critical": settings.scoring_weights.CRITICAL,
            "weight_high": settings.scoring_weights.HIGH,
            "weight_medium": settings.scoring_weights.MEDIUM,
            "weight_low": settings.scoring_weights.LOW,
            "weight_info": settings.scoring_weights.INFO,
            "git_timeout_seconds": settings.GIT_TIMEOUT_SECONDS,
            "max_upload_size_mb": settings.MAX_UPLOAD_SIZE_MB,
            "webhook_url": getattr(settings, "WEBHOOK_URL", None),
            "webhook_enabled": getattr(settings, "WEBHOOK_ENABLED", False),
            "notify_on_gate_failure_only": getattr(settings, "NOTIFY_ON_GATE_FAILURE_ONLY", True),
        }

    def get_system_settings(self) -> Dict[str, Any]:
        defaults = self.get_default_settings_dict()
        return self.adapter.get_system_settings(defaults)

    def save_system_settings(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        current = self.get_system_settings()
        updated = self.adapter.save_system_settings(updates, current)
        settings.apply_settings_dict(updated)
        return updated

    def reset_system_settings(self) -> Dict[str, Any]:
        self.adapter.reset_system_settings()
        factory_defaults = {
            "default_fail_severity": "HIGH",
            "default_max_pes": 60.0,
            "auto_fail_on_toxic_combos": True,
            "shannon_entropy_threshold": 4.4,
            "min_token_length_for_entropy": 24,
            "ignored_directories": [
                ".git", "node_modules", "venv", ".venv", "env", "__pycache__",
                ".idea", ".vscode", "dist", "build", ".pytest_cache", ".mypy_cache"
            ],
            "ignored_extensions": [
                ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
                ".pyc", ".pyo", ".pyd", ".min.js", ".min.css",
                ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3"
            ],
            "weight_critical": 25.0,
            "weight_high": 12.0,
            "weight_medium": 4.0,
            "weight_low": 1.0,
            "weight_info": 0.0,
            "git_timeout_seconds": 60,
            "max_upload_size_mb": 50,
            "webhook_url": None,
            "webhook_enabled": False,
            "notify_on_gate_failure_only": True,
        }
        settings.apply_settings_dict(factory_defaults)
        return factory_defaults

    # Exporters
    @staticmethod
    def export_sarif(scan: ScanResult) -> Dict[str, Any]:
        """Generates standard SARIF v2.1.0 output for GitHub / GitLab Code Scanning."""
        level_map = {
            SeverityLevel.CRITICAL: "error",
            SeverityLevel.HIGH: "error",
            SeverityLevel.MEDIUM: "warning",
            SeverityLevel.LOW: "note",
            SeverityLevel.INFO: "none"
        }

        rules = []
        rule_indices = {}
        results = []

        for f in scan.findings:
            rule_id = f.title.replace(" ", "-").lower()[:64]
            if rule_id not in rule_indices:
                rule_indices[rule_id] = len(rules)
                rules.append({
                    "id": rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "help": {"text": f.remediation_advice},
                    "defaultConfiguration": {
                        "level": level_map.get(f.severity, "warning")
                    }
                })

            results.append({
                "ruleId": rule_id,
                "ruleIndex": rule_indices[rule_id],
                "level": level_map.get(f.severity, "warning"),
                "message": {"text": f.description},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file_path.replace("\\", "/")},
                        "region": {
                            "startLine": f.line_number or 1,
                            "snippet": {"text": f.snippet or ""}
                        }
                    }
                }]
            })

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": settings.PROJECT_NAME,
                        "version": settings.VERSION,
                        "informationUri": "https://github.com/DevSecOps/ShieldCI",
                        "rules": rules
                    }
                },
                "results": results
            }]
        }

    @staticmethod
    def export_csv(scan: ScanResult) -> str:
        """Generates CSV report of all findings."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "ID", "Severity", "Category", "Title", "File/Target Path", "Line Number",
            "Remediation Advice", "CVE ID", "CVSS Score", "Snippet"
        ])
        for f in scan.findings:
            writer.writerow([
                f.id,
                f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                f.category.value if hasattr(f.category, "value") else str(f.category),
                f.title,
                f.file_path,
                f.line_number or "",
                f.remediation_advice,
                f.cve_id or "",
                f.cvss_score or "",
                f.snippet or ""
            ])
        return output.getvalue()


    def close(self):
        """Closes the underlying adapter and its connection pool if open."""
        if hasattr(self.adapter, "close"):
            self.adapter.close()


# Global storage instance
storage = StorageEngine()
import atexit
atexit.register(storage.close)

