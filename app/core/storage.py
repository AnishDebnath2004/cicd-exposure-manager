"""
app/core/storage.py
Persistent storage engine using SQLite for scan history, reports, and scheduled jobs.
Supports tri-vector auditing: Repositories, Websites, and Databases.
Includes SARIF 2.1.0, JSON, and CSV export generators.
"""

import os
import io
import csv
import json
import uuid
import sqlite3
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Tuple
from app.config import settings
from app.models.schemas import (
    ScanResult, ScanHistorySummary, ScheduledScan, SeverityLevel, FindingCategory, TargetCategory
)
from app.models.auth_schemas import UserResponse


class StorageEngine:
    """Manages SQLite persistence for security scans, history, and scheduled jobs."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or settings.DB_PATH
        self._init_db()
        self._sync_runtime_settings()

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
            
            # Migration check: ensure target_type and user_email columns exist
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

            conn.commit()

    def save_scan(self, scan: ScanResult):
        """Persists a completed scan result."""
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
        """Retrieves full scan result by ID."""
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
        """Retrieves scan history list with optional target type filter and per-user privacy scoping."""
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
                # Unauthenticated guest only sees guest scans
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
        """Deletes a scan record."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            conn.commit()
            return cursor.rowcount > 0

    # Schedule management
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

    # Guest Scan Quota Management
    def check_and_increment_guest_quota(self, client_ip: str, limit: int = 5) -> Tuple[bool, int, int]:
        """
        Checks whether client_ip has exceeded daily scan quota.
        If quota remains, increments count and returns (True, current_count, limit).
        If quota exceeded, returns (False, current_count, limit).
        """
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
        """Returns (used_scans, max_limit) for a client IP."""
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

    # User Management
    def create_user(
        self,
        email: str,
        password_hash: str,
        salt: str,
        full_name: Optional[str] = None,
        organization: Optional[str] = None,
        role: str = "developer"
    ) -> UserResponse:
        user_id = str(uuid.uuid4())
        created_at_dt = datetime.utcnow()
        created_at = created_at_dt.isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (
                    id, email, password_hash, salt, full_name, organization, role, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user_id, email.lower().strip(), password_hash, salt,
                full_name.strip() if full_name else None,
                organization.strip() if organization else None,
                role, created_at
            ))
            conn.commit()

        return UserResponse(
            id=user_id,
            email=email.lower().strip(),
            full_name=full_name.strip() if full_name else None,
            organization=organization.strip() if organization else None,
            role=role,
            created_at=created_at_dt,
            last_login_at=None
        )

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Retrieves raw user record by email (including password hash and salt)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE LOWER(email) = LOWER(?)", (email.strip(),))
            row = cursor.fetchone()
            if not row:
                return None
            return dict(row)

    def get_user_by_id(self, user_id: str) -> Optional[UserResponse]:
        """Retrieves user profile by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, email, full_name, organization, role, created_at, last_login_at FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return UserResponse(
                id=row["id"],
                email=row["email"],
                full_name=row["full_name"],
                organization=row["organization"],
                role=row["role"] or "developer",
                created_at=datetime.fromisoformat(row["created_at"]),
                last_login_at=datetime.fromisoformat(row["last_login_at"]) if row["last_login_at"] else None
            )

    def update_last_login(self, user_id: str):
        """Updates user last login timestamp."""
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
        """Updates user display name and organization."""
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
        """Updates user password hash and salt."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users
                SET password_hash = ?, salt = ?
                WHERE id = ?
            """, (new_password_hash, salt, user_id))
            conn.commit()
            return cursor.rowcount > 0

    # System & Engine Settings Management
    def _sync_runtime_settings(self):
        """Synchronizes persisted SQLite settings into in-memory settings config."""
        try:
            stored = self.get_system_settings()
            settings.apply_settings_dict(stored)
        except Exception:
            pass

    @staticmethod
    def get_default_settings_dict() -> Dict[str, Any]:
        """Returns default settings dictionary."""
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
        """Retrieves active system settings from SQLite merged over defaults."""
        defaults = self.get_default_settings_dict()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT key, value_json FROM system_settings")
            rows = cursor.fetchall()
            for row in rows:
                k = row["key"]
                try:
                    v = json.loads(row["value_json"])
                    defaults[k] = v
                except Exception:
                    pass
        return defaults

    def save_system_settings(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Persists system settings updates to SQLite and synchronizes in-memory config."""
        now = datetime.utcnow().isoformat()
        current = self.get_system_settings()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for key, val in updates.items():
                if val is not None:
                    # Normalize enum instances
                    if hasattr(val, "value"):
                        val = val.value
                    current[key] = val
                    cursor.execute("""
                        INSERT OR REPLACE INTO system_settings (key, value_json, updated_at)
                        VALUES (?, ?, ?)
                    """, (key, json.dumps(val), now))
            conn.commit()

        # Synchronize runtime settings
        settings.apply_settings_dict(current)
        return current

    def reset_system_settings(self) -> Dict[str, Any]:
        """Clears custom system settings from SQLite and restores factory defaults."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM system_settings")
            conn.commit()

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


# Global storage instance
storage = StorageEngine()
