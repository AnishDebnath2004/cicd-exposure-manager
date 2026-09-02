"""app/scanners/sca_scanner.py"""
import os
import re
import uuid
from typing import List, Tuple, Dict, Any
from app.models.schemas import Finding, FindingCategory, SeverityLevel

class SCAScanner:
    """Software Composition Analysis (SCA) & SBOM component analyzer."""

    # Built-in advisory database for demonstration & local auditing
    KNOWN_CVE_DB = {
        "requests": [
            {"max_version": "2.31.0", "cve": "CVE-2023-32681", "severity": SeverityLevel.MEDIUM, "cvss": 6.1, "title": "Requests Proxy-Authorization Header Leak"}
        ],
        "urllib3": [
            {"max_version": "1.26.17", "cve": "CVE-2023-45803", "severity": SeverityLevel.HIGH, "cvss": 7.5, "title": "urllib3 HTTP Request Smuggling & Stream Exposure"}
        ],
        "pyyaml": [
            {"max_version": "5.3.1", "cve": "CVE-2020-14343", "severity": SeverityLevel.CRITICAL, "cvss": 9.8, "title": "PyYAML Arbitrary Code Execution via load()"}
        ],
        "flask": [
            {"max_version": "2.2.0", "cve": "CVE-2023-30861", "severity": SeverityLevel.HIGH, "cvss": 7.5, "title": "Flask Session Cookie Exposure via Cache-Control"}
        ],
        "django": [
            {"max_version": "4.2.0", "cve": "CVE-2023-3111", "severity": SeverityLevel.HIGH, "cvss": 8.1, "title": "Django Open Redirect and DoS in Login URLs"}
        ]
    }

    def scan(self, base_path: str) -> Tuple[List[Finding], List[Dict[str, Any]]]:
        findings = []
        sbom_components = []

        req_path = os.path.join(base_path, "requirements.txt")
        if os.path.isfile(req_path):
            rel_path = os.path.relpath(req_path, base_path)
            f_list, sbom = self._scan_requirements_txt(req_path, rel_path)
            findings.extend(f_list)
            sbom_components.extend(sbom)

        return findings, sbom_components

    def _scan_requirements_txt(self, file_path: str, rel_path: str) -> Tuple[List[Finding], List[Dict[str, Any]]]:
        findings = []
        sbom = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            for line_idx, line in enumerate(lines, 1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#"):
                    continue

                # Match package==version or package>=version
                match = re.match(r"^([a-zA-Z0-9_\-]+)\s*(?:==|>=|<=)\s*([0-9\.]+)", clean_line)
                if match:
                    pkg_name = match.group(1).lower()
                    pkg_ver = match.group(2)

                    sbom.append({
                        "name": pkg_name,
                        "version": pkg_ver,
                        "purl": f"pkg:pypi/{pkg_name}@{pkg_ver}",
                        "file": rel_path
                    })

                    # Check for vulnerabilities in advisory database
                    if pkg_name in self.KNOWN_CVE_DB:
                        for vuln in self.KNOWN_CVE_DB[pkg_name]:
                            if self._is_vulnerable(pkg_ver, vuln["max_version"]):
                                findings.append(Finding(
                                    id=str(uuid.uuid4()),
                                    category=FindingCategory.SCA_VULNERABILITY,
                                    severity=vuln["severity"],
                                    title=f"{vuln['cve']}: {vuln['title']} in {pkg_name}",
                                    description=f"Package '{pkg_name}' version {pkg_ver} is vulnerable to {vuln['cve']}.",
                                    file_path=rel_path,
                                    line_number=line_idx,
                                    snippet=clean_line,
                                    remediation_advice=f"Upgrade '{pkg_name}' to version > {vuln['max_version']}.",
                                    cve_id=vuln["cve"],
                                    cvss_score=vuln["cvss"],
                                    auto_fixable=True
                                ))
        except Exception:
            pass
        return findings, sbom

    def _is_vulnerable(self, current: str, max_vuln: str) -> bool:
        try:
            curr_parts = [int(p) for p in current.split(".") if p.isdigit()]
            max_parts = [int(p) for p in max_vuln.split(".") if p.isdigit()]
            return curr_parts <= max_parts
        except Exception:
            return False