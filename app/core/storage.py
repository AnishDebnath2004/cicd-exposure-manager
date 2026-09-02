"""
app/core/storage.py
Persistent storage engine using SQLite for scan history, reports, and scheduled jobs.
Includes SARIF 2.1.0, JSON, and CSV export generators.
"""

import os
import io
import csv
import json
import sqlite3
from datetime import datetime
from typing import List, Optional, Dict, Any
from app.config import settings
from app.models.schemas import (
    ScanResult, ScanHistorySummary, ScheduledScan, SeverityLevel, FindingCategory
)


class StorageEngine:
    """Manages SQLite persistence for security scans, history, and scheduled jobs."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or settings.DB_PATH
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
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
                    result_json TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS schedules (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    branch TEXT,
                    interval_minutes INTEGER NOT NULL,
                    fail_on_severity TEXT NOT NULL,
                    max_allowed_pes REAL NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    last_run_at TEXT,
                    last_scan_id TEXT,
                    last_pes REAL,
                    last_grade TEXT,
                    last_status TEXT
                )
            """)
            conn.commit()

    def save_scan(self, scan: ScanResult):
        """Persists a completed scan result."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            s = scan.summary
            cursor.execute("""
                INSERT OR REPLACE INTO scans (
                    scan_id, repo_name, target_path, repo_url, branch, source_type,
                    timestamp, total_findings, critical_count, high_count, medium_count,
                    low_count, info_count, pipeline_exposure_score, risk_grade,
                    policy_passed, scan_duration_seconds, scanned_files_count, result_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan.scan_id,
                scan.repo_name,
                scan.target_path,
                scan.repo_url,
                scan.branch,
                scan.source_type.value if hasattr(scan.source_type, "value") else str(scan.source_type),
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

    def list_scans(self, limit: int = 50, offset: int = 0) -> List[ScanHistorySummary]:
        """Retrieves scan history list."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT scan_id, repo_name, target_path, source_type, timestamp,
                       pipeline_exposure_score, risk_grade, total_findings,
                       critical_count, high_count, policy_passed, scan_duration_seconds
                FROM scans
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
            """, (limit, offset))
            rows = cursor.fetchall()
            return [
                ScanHistorySummary(
                    scan_id=r["scan_id"],
                    repo_name=r["repo_name"],
                    target_path=r["target_path"],
                    source_type=r["source_type"],
                    timestamp=datetime.fromisoformat(r["timestamp"]),
                    pipeline_exposure_score=r["pipeline_exposure_score"],
                    risk_grade=r["risk_grade"],
                    total_findings=r["total_findings"],
                    critical_count=r["critical_count"],
                    high_count=r["high_count"],
                    policy_passed=bool(r["policy_passed"]),
                    scan_duration_seconds=r["scan_duration_seconds"]
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
        branch: Optional[str],
        interval_minutes: int,
        fail_on_severity: str = "HIGH",
        max_allowed_pes: float = 60.0
    ) -> ScheduledScan:
        created_at = datetime.utcnow().isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO schedules (
                    id, target, source_type, branch, interval_minutes,
                    fail_on_severity, max_allowed_pes, enabled, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
            """, (
                sched_id, target, source_type, branch, interval_minutes,
                fail_on_severity, max_allowed_pes, created_at
            ))
            conn.commit()

        return ScheduledScan(
            id=sched_id,
            target=target,
            source_type=source_type, # type: ignore
            branch=branch,
            interval_minutes=interval_minutes,
            enabled=True,
            created_at=datetime.fromisoformat(created_at)
        )

    def get_schedules(self) -> List[ScheduledScan]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM schedules ORDER BY created_at DESC")
            rows = cursor.fetchall()
            return [
                ScheduledScan(
                    id=r["id"],
                    target=r["target"],
                    source_type=r["source_type"],
                    branch=r["branch"],
                    interval_minutes=r["interval_minutes"],
                    enabled=bool(r["enabled"]),
                    created_at=datetime.fromisoformat(r["created_at"]),
                    last_run_at=datetime.fromisoformat(r["last_run_at"]) if r["last_run_at"] else None,
                    last_scan_id=r["last_scan_id"],
                    last_pes=r["last_pes"],
                    last_grade=r["last_grade"],
                    last_status=r["last_status"]
                )
                for r in rows
            ]

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
            "ID", "Severity", "Category", "Title", "File Path", "Line Number",
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
