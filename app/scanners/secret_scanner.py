"""app/scanners/secret_scanner.py"""
import os
import re
import math
import uuid
from typing import List
from app.models.schemas import Finding, FindingCategory, SeverityLevel
from app.config import settings

class SecretScanner:
    """Scans for exposed credentials, tokens, and high-entropy secrets."""

    SECRET_REGEXES = {
        "AWS Access Key ID": (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), SeverityLevel.CRITICAL),
        "AWS Secret Access Key": (re.compile(r"(?i)aws_secret_access_key\s*=\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"), SeverityLevel.CRITICAL),
        "GitHub Personal Access Token": (re.compile(r"\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b"), SeverityLevel.CRITICAL),
        "Generic High-Risk API Key": (re.compile(r"(?i)(api[_-]?key|secret[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{24,})['\"]"), SeverityLevel.HIGH),
        "Private RSA/SSH Key": (re.compile(r"-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----"), SeverityLevel.CRITICAL),
        "Slack Webhook URL": (re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"), SeverityLevel.HIGH),
    }

    def __init__(self):
        self.ignore_extensions = settings.scanner.IGNORED_EXTENSIONS
        self.ignore_dirs = settings.scanner.IGNORED_DIRECTORIES
        self.entropy_threshold = settings.scanner.SHANNON_ENTROPY_THRESHOLD
        self.min_token_length = settings.scanner.MIN_TOKEN_LENGTH_FOR_ENTROPY
        self.entropy_token_pattern = re.compile(rf"['\"]([A-Za-z0-9_\-\+/=]{{{self.min_token_length},}})['\"]")

    @staticmethod
    def shannon_entropy(data: str) -> float:
        """Calculates the Shannon entropy of a string (randomness metric)."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        for x in set(data):
            p_x = float(data.count(x)) / length
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy

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
                findings.extend(self._scan_file(full_path, rel_path))

        return findings

    def _scan_file(self, file_path: str, rel_path: str) -> List[Finding]:
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            for line_idx, line in enumerate(lines, 1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#") or clean_line.startswith("//"):
                    continue

                # Pattern-based secret match
                for secret_type, (regex, severity) in self.SECRET_REGEXES.items():
                    match = regex.search(line)
                    if match:
                        matched_str = match.group(0)
                        masked_secret = matched_str[:4] + "*" * (len(matched_str) - 8) + matched_str[-4:] if len(matched_str) > 8 else "***"
                        findings.append(Finding(
                            id=str(uuid.uuid4()),
                            category=FindingCategory.SECRET_EXPOSURE,
                            severity=severity,
                            title=f"Exposed {secret_type}",
                            description=f"Potential credential exposure detected: {secret_type}.",
                            file_path=rel_path,
                            line_number=line_idx,
                            snippet=f"... {masked_secret} ...",
                            remediation_advice="Revoke the exposed key immediately and migrate credential storage to GitHub Secrets / HashiCorp Vault.",
                            auto_fixable=False
                        ))

                # Shannon Entropy secret match for generic high-randomness tokens
                tokens = self.entropy_token_pattern.findall(line)
                for token in tokens:
                    entropy = self.shannon_entropy(token)
                    if entropy > self.entropy_threshold and not any(f.file_path == rel_path and f.line_number == line_idx for f in findings):
                        findings.append(Finding(
                            id=str(uuid.uuid4()),
                            category=FindingCategory.SECRET_EXPOSURE,
                            severity=SeverityLevel.MEDIUM,
                            title="High-Entropy String / Suspected Token",
                            description=f"High Shannon entropy string detected (Entropy: {entropy:.2f}), indicating an unclassified private token or hash.",
                            file_path=rel_path,
                            line_number=line_idx,
                            snippet=f"Token: {token[:4]}...{token[-4:]}",
                            remediation_advice="Verify if this token is a secret. If so, store it in an environment secret variable.",
                            auto_fixable=False
                        ))

        except Exception:
            pass
        return findings
