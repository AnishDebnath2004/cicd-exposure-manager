"""
app/core/orchestrator.py
Unified Tri-Vector Exposure Orchestrator combining:
1. Repository & CI/CD Posture Scanners (Workflow, Secret, SCA, IaC)
2. Live Website, SSL/TLS, and API Exposure Scanner
3. Database Posture, Credential Exposure, and Network Access Scanner
"""

import os
import re
import time
import uuid
import urllib.parse
from typing import List, Optional, Dict, Any
from datetime import datetime

from app.models.schemas import ScanResult, ScanRequest, SourceType, TargetCategory, SeverityLevel
from app.scanners.workflow_scanner import WorkflowScanner
from app.scanners.secret_scanner import SecretScanner
from app.scanners.sca_scanner import SCAScanner
from app.scanners.iac_scanner import IaCScanner
from app.scanners.web_scanner import WebsiteScanner
from app.scanners.database_scanner import DatabaseScanner
from app.core.scoring import ExposureScorer
from app.core.repo_fetcher import RepoFetcher
from app.core.storage import storage
from app.core.auto_discovery import AutoDiscoveryEngine
from app.core.correlator import AttackCorrelator
from app.core.remediator import AutoRemediator
from app.config import settings


class ExposureOrchestrator:
    """Unified Orchestrator combining all security engines for Repositories, Websites, and Databases."""

    def __init__(self):
        # Codebase & CI/CD scanners
        self.workflow_scanner = WorkflowScanner()
        self.secret_scanner = SecretScanner()
        self.sca_scanner = SCAScanner()
        self.iac_scanner = IaCScanner()

        # Web & Database scanners
        self.web_scanner = WebsiteScanner()
        self.database_scanner = DatabaseScanner()

        # Advanced Posture & Attack Path Engines
        self.auto_discovery_engine = AutoDiscoveryEngine()
        self.correlator = AttackCorrelator()
        self.remediator = AutoRemediator()

    def detect_target_type(self, target: str, explicit_type: Optional[TargetCategory] = None) -> TargetCategory:
        """Determines if a target is a Repository, Website, or Database."""
        if explicit_type:
            return explicit_type

        cleaned = (target or "").strip().lower()
        if not cleaned:
            return TargetCategory.REPOSITORY

        # Database signatures
        db_schemes = ("postgres://", "postgresql://", "mysql://", "mariadb://", "redis://", "mongodb://", "mongodb+srv://", "elasticsearch://", "mssql://")
        if any(cleaned.startswith(s) for s in db_schemes):
            return TargetCategory.DATABASE
        if any(port in cleaned for port in (":5432", ":3306", ":6379", ":27017", ":9200", ":1433")):
            return TargetCategory.DATABASE

        # Git repository signatures take precedence over generic web
        if RepoFetcher.is_git_url(target) or cleaned.endswith(".git"):
            return TargetCategory.REPOSITORY

        # Live Web Application signatures
        if cleaned.startswith(("http://", "https://")) or cleaned.startswith("www."):
            return TargetCategory.WEBSITE

        return TargetCategory.REPOSITORY

    def run_scan(
        self,
        request: ScanRequest,
        is_zip_upload: bool = False,
        temp_zip_path: Optional[str] = None
    ) -> ScanResult:
        """
        Routes and executes deep exposure scans across any Repository, Website, or Database.
        """
        raw_target = temp_zip_path if is_zip_upload else (request.target or request.repo_url or request.target_path or ".")
        target_type = self.detect_target_type(raw_target, request.target_type)

        if target_type == TargetCategory.WEBSITE:
            return self.run_website_scan(
                target_url=raw_target,
                fail_severity=request.fail_on_severity,
                max_pes=request.max_allowed_pes
            )
        elif target_type == TargetCategory.DATABASE:
            return self.run_database_scan(
                target_db=raw_target,
                explicit_engine=request.db_type,
                fail_severity=request.fail_on_severity,
                max_pes=request.max_allowed_pes
            )
        else:
            return self.run_repository_scan(
                request=request,
                is_zip_upload=is_zip_upload,
                temp_zip_path=temp_zip_path
            )

    def run_repository_scan(
        self,
        request: ScanRequest,
        is_zip_upload: bool = False,
        temp_zip_path: Optional[str] = None
    ) -> ScanResult:
        """Audits repository codebases, CI/CD pipelines, secrets, dependencies, and container IaC."""
        start_time = time.time()
        scan_id = str(uuid.uuid4())
        target_input = temp_zip_path if is_zip_upload else (request.target or request.repo_url or request.target_path or ".")

        with RepoFetcher.prepare_scan_target(target_input, branch=request.branch, is_zip_upload=is_zip_upload) as (target_dir, detected_repo_name, source_type):
            repo_name = request.repo_name or detected_repo_name

            file_count = 0
            for root, dirs, files in os.walk(target_dir):
                dirs[:] = [d for d in dirs if d not in settings.scanner.IGNORED_DIRECTORIES]
                for f in files:
                    ext = os.path.splitext(f)[1].lower()
                    if ext not in settings.scanner.IGNORED_EXTENSIONS:
                        file_count += 1

            all_findings = []
            all_findings.extend(self.workflow_scanner.scan(target_dir))
            all_findings.extend(self.secret_scanner.scan(target_dir))

            sca_findings, sbom_components = self.sca_scanner.scan(target_dir)
            all_findings.extend(sca_findings)

            all_findings.extend(self.iac_scanner.scan(target_dir))

            duration = time.time() - start_time
            summary = ExposureScorer.calculate_summary(
                findings=all_findings,
                duration=duration,
                file_count=file_count,
                fail_severity=request.fail_on_severity,
                max_pes=request.max_allowed_pes
            )

            # Auto-Discovery Triangulation: extract web & DB footprints from repo code
            auto_disc = self.auto_discovery_engine.discover(target_dir)

            # Correlate findings into Toxic Combinations & construct visual Attack Graph
            toxic_combos, attack_graph = self.correlator.correlate(
                findings=all_findings,
                target_name=repo_name,
                auto_discovery=auto_disc
            )

            # Generate consolidated 1-click git patch
            unified_patch = self.remediator.bundle_repository_patch(
                findings=all_findings,
                base_dir=target_dir
            )

            result = ScanResult(
                scan_id=scan_id,
                target_path=target_input if not is_zip_upload else detected_repo_name,
                repo_name=repo_name,
                repo_url=request.repo_url or (target_input if source_type == SourceType.GIT else None),
                branch=request.branch,
                source_type=source_type,
                target_type=TargetCategory.REPOSITORY,
                timestamp=datetime.utcnow(),
                summary=summary,
                findings=all_findings,
                sbom_components=sbom_components,
                metadata={"file_count": file_count},
                toxic_combinations=toxic_combos,
                attack_graph=attack_graph,
                auto_discovery=auto_disc,
                unified_patch=unified_patch
            )

            try:
                storage.save_scan(result)
            except Exception:
                pass

            return result

    def run_website_scan(
        self,
        target_url: str,
        fail_severity: SeverityLevel = SeverityLevel.HIGH,
        max_pes: float = 60.0
    ) -> ScanResult:
        """Audits live website / API endpoints for TLS, security headers, CORS, and exposed paths."""
        start_time = time.time()
        scan_id = str(uuid.uuid4())

        findings, web_meta = self.web_scanner.scan(target_url)
        duration = time.time() - start_time

        parsed = urllib.parse.urlparse(web_meta.get("url", target_url))
        asset_name = parsed.netloc or target_url

        summary = ExposureScorer.calculate_summary(
            findings=findings,
            duration=duration,
            file_count=1,
            fail_severity=fail_severity,
            max_pes=max_pes
        )

        toxic_combos, attack_graph = self.correlator.correlate(
            findings=findings,
            target_name=asset_name
        )

        missing_headers = [f.title.replace("Missing Security Header: ", "").strip() for f in findings if "Missing Security Header" in f.title]
        web_configs = self.remediator.generate_web_security_configs(missing_headers)
        patch_str = f"# ====================================================================\n# ShieldCI Web Security Hardening Configurations\n# Target: {asset_name}\n# ====================================================================\n\n{web_configs.get('nginx', '')}\n\n{web_configs.get('caddy', '')}\n"

        result = ScanResult(
            scan_id=scan_id,
            target_path=web_meta.get("url", target_url),
            repo_name=asset_name,
            repo_url=web_meta.get("url", target_url),
            source_type=SourceType.WEB,
            target_type=TargetCategory.WEBSITE,
            timestamp=datetime.utcnow(),
            summary=summary,
            findings=findings,
            sbom_components=[],
            metadata=web_meta,
            toxic_combinations=toxic_combos,
            attack_graph=attack_graph,
            unified_patch=patch_str
        )

        try:
            storage.save_scan(result)
        except Exception:
            pass

        return result

    def run_database_scan(
        self,
        target_db: str,
        explicit_engine: Optional[str] = None,
        fail_severity: SeverityLevel = SeverityLevel.HIGH,
        max_pes: float = 60.0
    ) -> ScanResult:
        """Audits database connection strings or endpoints for network access, credentials, and TLS."""
        start_time = time.time()
        scan_id = str(uuid.uuid4())

        findings, db_meta = self.database_scanner.scan(target_db, explicit_engine)
        duration = time.time() - start_time

        engine_name = db_meta.get("engine", "database").upper()
        host = db_meta.get("host", "unknown")
        port = db_meta.get("port", "")
        asset_name = f"{engine_name} ({host}:{port})" if port else f"{engine_name} ({host})"

        summary = ExposureScorer.calculate_summary(
            findings=findings,
            duration=duration,
            file_count=1,
            fail_severity=fail_severity,
            max_pes=max_pes
        )

        toxic_combos, attack_graph = self.correlator.correlate(
            findings=findings,
            target_name=asset_name
        )

        # Mask target path password if present
        masked_target = re.sub(r"(://[^:]+):([^@]+)@", r"\1:****@", target_db)

        result = ScanResult(
            scan_id=scan_id,
            target_path=masked_target,
            repo_name=asset_name,
            repo_url=None,
            source_type=SourceType.DATABASE,
            target_type=TargetCategory.DATABASE,
            timestamp=datetime.utcnow(),
            summary=summary,
            findings=findings,
            sbom_components=[],
            metadata=db_meta,
            toxic_combinations=toxic_combos,
            attack_graph=attack_graph
        )

        try:
            storage.save_scan(result)
        except Exception:
            pass

        return result