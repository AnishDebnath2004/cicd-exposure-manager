"""app/scanners/iac_scanner.py"""
import os
import re
import uuid
from typing import List
from app.models.schemas import Finding, FindingCategory, SeverityLevel
from app.config import settings

class IaCScanner:
    """Scans Dockerfiles and Terraform configurations for exposure risks."""

    def __init__(self):
        self.ignore_dirs = settings.scanner.IGNORED_DIRECTORIES
        self.ignore_extensions = settings.scanner.IGNORED_EXTENSIONS

    def scan(self, base_path: str) -> List[Finding]:
        findings = []

        for root, dirs, files in os.walk(base_path):
            dirs[:] = [d for d in dirs if d not in self.ignore_dirs]
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in self.ignore_extensions:
                    continue

                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, base_path)

                if file == "Dockerfile" or file.endswith(".dockerfile"):
                    findings.extend(self._scan_dockerfile(full_path, rel_path))
                elif file.endswith(".tf"):
                    findings.extend(self._scan_terraform(full_path, rel_path))

        return findings

    def _scan_dockerfile(self, file_path: str, rel_path: str) -> List[Finding]:
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            has_user_directive = False
            for line_idx, line in enumerate(lines, 1):
                clean = line.strip().upper()

                if clean.startswith("USER "):
                    has_user_directive = True

                # Rule 1: Latest tag in FROM
                if clean.startswith("FROM ") and (":latest" in clean or ":" not in clean):
                    findings.append(Finding(
                        id=str(uuid.uuid4()),
                        category=FindingCategory.IAC_CONTAINER,
                        severity=SeverityLevel.MEDIUM,
                        title="Unpinned Base Container Image (:latest)",
                        description="Container base image uses ':latest' or is untagged, leading to unpredictable supply chain updates.",
                        file_path=rel_path,
                        line_number=line_idx,
                        snippet=line.strip(),
                        remediation_advice="Specify an explicit, immutable base image digest or specific release tag (e.g., python:3.11-slim).",
                        auto_fixable=False
                    ))

                # Rule 2: Exposed Dangerous Ports (e.g. SSH / 22, RDP / 3389)
                if clean.startswith("EXPOSE "):
                    if "22" in clean or "3389" in clean or "23" in clean:
                        findings.append(Finding(
                            id=str(uuid.uuid4()),
                            category=FindingCategory.IAC_CONTAINER,
                            severity=SeverityLevel.HIGH,
                            title="Dangerous Administrative Port Exposed in Container",
                            description="Container exposes management ports (SSH/22, RDP/3389) creating unnecessary attack surface.",
                            file_path=rel_path,
                            line_number=line_idx,
                            snippet=line.strip(),
                            remediation_advice="Remove remote access daemons and exposed management ports from container images.",
                            auto_fixable=False
                        ))

            # Rule 3: Container running as Root User
            if not has_user_directive:
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    category=FindingCategory.IAC_CONTAINER,
                    severity=SeverityLevel.HIGH,
                    title="Container Execution as Default Root User",
                    description="Dockerfile does not define a non-root 'USER', allowing container breakout attacks to escalate privileges.",
                    file_path=rel_path,
                    line_number=1,
                    snippet="Missing 'USER nonroot' directive",
                    remediation_advice="Add a dedicated non-root user (e.g., 'USER 10001:10001' or 'USER appuser').",
                    auto_fixable=True,
                    fix_patch="\nUSER 10001\n"
                ))

        except Exception:
            pass
        return findings

    def _scan_terraform(self, file_path: str, rel_path: str) -> List[Finding]:
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Rule: Overly permissive CIDR ingress (0.0.0.0/0)
            if "0.0.0.0/0" in content and ("ingress" in content or "security_group" in content):
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    category=FindingCategory.IAC_CONTAINER,
                    severity=SeverityLevel.HIGH,
                    title="Unrestricted Ingress CIDR Block (0.0.0.0/0)",
                    description="Security group allows open access from the entire public internet.",
                    file_path=rel_path,
                    line_number=1,
                    snippet="cidr_blocks = [\"0.0.0.0/0\"]",
                    remediation_advice="Restrict ingress CIDR blocks to internal VPC or specific bastion IP ranges.",
                    auto_fixable=False
                ))
        except Exception:
            pass
        return findings