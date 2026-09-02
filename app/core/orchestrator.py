"""
app/core/orchestrator.py
Unified Orchestrator combining all security engines with universal repository ingestion & persistence.
"""

import os
import time
import uuid
from typing import List, Optional
from datetime import datetime
from app.models.schemas import ScanResult, ScanRequest, SourceType
from app.scanners.workflow_scanner import WorkflowScanner
from app.scanners.secret_scanner import SecretScanner
from app.scanners.sca_scanner import SCAScanner
from app.scanners.iac_scanner import IaCScanner
from app.core.scoring import ExposureScorer
from app.core.repo_fetcher import RepoFetcher
from app.core.storage import storage
from app.config import settings


class ExposureOrchestrator:
    """Unified Orchestrator combining all security engines for local and remote repositories."""

    def __init__(self):
        self.workflow_scanner = WorkflowScanner()
        self.secret_scanner = SecretScanner()
        self.sca_scanner = SCAScanner()
        self.iac_scanner = IaCScanner()

    def run_scan(
        self,
        request: ScanRequest,
        is_zip_upload: bool = False,
        temp_zip_path: Optional[str] = None
    ) -> ScanResult:
        """
        Executes a deep security exposure scan against any target repository.
        Target can be a remote Git URL, local filesystem path, or uploaded ZIP archive.
        """
        start_time = time.time()
        scan_id = str(uuid.uuid4())
        
        target_input = temp_zip_path if is_zip_upload else (request.repo_url or request.target_path or ".")
        
        with RepoFetcher.prepare_scan_target(target_input, branch=request.branch, is_zip_upload=is_zip_upload) as (target_dir, detected_repo_name, source_type):
            repo_name = request.repo_name or detected_repo_name
            
            # Count scannable files
            file_count = 0
            for root, dirs, files in os.walk(target_dir):
                dirs[:] = [d for d in dirs if d not in settings.scanner.IGNORED_DIRECTORIES]
                for f in files:
                    ext = os.path.splitext(f)[1].lower()
                    if ext not in settings.scanner.IGNORED_EXTENSIONS:
                        file_count += 1

            all_findings = []

            # 1. Pipeline Misconfigurations (GitHub Actions, GitLab CI)
            all_findings.extend(self.workflow_scanner.scan(target_dir))
            
            # 2. Secret & Credential Leaks
            all_findings.extend(self.secret_scanner.scan(target_dir))
            
            # 3. SCA Dependencies & SBOM
            sca_findings, sbom_components = self.sca_scanner.scan(target_dir)
            all_findings.extend(sca_findings)
            
            # 4. Container & IaC Exposures (Docker, Terraform)
            all_findings.extend(self.iac_scanner.scan(target_dir))

            duration = time.time() - start_time
            summary = ExposureScorer.calculate_summary(
                findings=all_findings,
                duration=duration,
                file_count=file_count,
                fail_severity=request.fail_on_severity,
                max_pes=request.max_allowed_pes
            )

            result = ScanResult(
                scan_id=scan_id,
                target_path=target_input if not is_zip_upload else detected_repo_name,
                repo_name=repo_name,
                repo_url=request.repo_url or (target_input if source_type == SourceType.GIT else None),
                branch=request.branch,
                source_type=source_type,
                timestamp=datetime.utcnow(),
                summary=summary,
                findings=all_findings,
                sbom_components=sbom_components
            )

            # Persist to database
            try:
                storage.save_scan(result)
            except Exception as e:
                # Log error but don't fail scan return
                pass

            return result