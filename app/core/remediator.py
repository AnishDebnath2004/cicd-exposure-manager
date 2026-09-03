"""
app/core/remediator.py
Autonomous Remediation & Unified Patch Engine.
Generates syntactically valid unified git diff patches (consumable via `git apply`)
for Dockerfiles, CI/CD workflows, Python requirements, and server security configurations.
"""

import os
import re
import difflib
from typing import List, Dict, Optional, Tuple
from app.models.schemas import Finding, FindingCategory, SeverityLevel


class AutoRemediator:
    """Generates unified git diff patches and server configurations to fix security exposures."""

    # Recommended safe library versions for SCA bumps
    SCA_SAFE_VERSIONS = {
        "requests": "2.32.3",
        "urllib3": "2.2.2",
        "pyyaml": "6.0.1",
        "flask": "3.0.3",
        "django": "5.0.7"
    }

    @classmethod
    def generate_dockerfile_patch(cls, original_content: str, file_path: str = "Dockerfile") -> Optional[str]:
        """Generates unified diff hardening Dockerfile (adds non-root user, fixes latest tag)."""
        lines = original_content.splitlines(keepends=True)
        remediated = list(lines)
        modified = False

        # 1. Check for USER directive
        has_user = any(re.match(r"^\s*USER\s+", line, re.IGNORECASE) for line in lines)
        if not has_user:
            remediated.append("\n# [ShieldCI Remediation] Run container as non-root user (UID 10001)\nUSER 10001\n")
            modified = True

        # 2. Check for latest tag in FROM
        new_lines = []
        for line in remediated:
            if re.match(r"^\s*FROM\s+[a-zA-Z0-9_\-\./]+(?::latest|\s*$)", line, re.IGNORECASE):
                # Replace :latest with a pinned version tag or comment
                cleaned_from = line.strip()
                if ":latest" in cleaned_from:
                    fixed_from = cleaned_from.replace(":latest", ":slim-bullseye  # Pin specific tag instead of latest") + "\n"
                    new_lines.append(fixed_from)
                    modified = True
                    continue
            new_lines.append(line)

        if not modified:
            return None

        diff = difflib.unified_diff(
            lines,
            new_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm=""
        )
        return "\n".join(diff)

    @classmethod
    def generate_workflow_patch(cls, original_content: str, file_path: str) -> Optional[str]:
        """Generates unified diff for GitHub Actions (replaces pull_request_target with pull_request)."""
        lines = original_content.splitlines(keepends=True)
        new_lines = []
        modified = False

        for line in lines:
            if "pull_request_target" in line:
                new_line = line.replace("pull_request_target", "pull_request  # [ShieldCI Fix] Isolated fork context")
                new_lines.append(new_line)
                modified = True
            else:
                new_lines.append(line)

        if not modified:
            return None

        diff = difflib.unified_diff(
            lines,
            new_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm=""
        )
        return "\n".join(diff)

    @classmethod
    def generate_requirements_patch(cls, original_content: str, file_path: str = "requirements.txt") -> Optional[str]:
        """Generates unified diff bumping vulnerable dependencies to safe patched versions."""
        lines = original_content.splitlines(keepends=True)
        new_lines = []
        modified = False

        for line in lines:
            trimmed = line.strip()
            if not trimmed or trimmed.startswith("#"):
                new_lines.append(line)
                continue

            matched = False
            for pkg, safe_ver in cls.SCA_SAFE_VERSIONS.items():
                pattern = rf"(?i)^\s*{pkg}\s*([=><~]=?)\s*([0-9\.]+)"
                if re.match(pattern, trimmed):
                    new_lines.append(f"{pkg}>={safe_ver}  # [ShieldCI Fix] Upgraded for CVE remediation\n")
                    modified = True
                    matched = True
                    break

            if not matched:
                new_lines.append(line)

        if not modified:
            return None

        diff = difflib.unified_diff(
            lines,
            new_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm=""
        )
        return "\n".join(diff)

    @classmethod
    def generate_web_security_configs(cls, missing_headers: List[str]) -> Dict[str, str]:
        """Generates ready-to-use configuration blocks for Nginx, Caddy, and Apache."""
        headers_map = {
            "Strict-Transport-Security": 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
            "Content-Security-Policy": 'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\';" always;',
            "X-Frame-Options": 'add_header X-Frame-Options "DENY" always;',
            "X-Content-Type-Options": 'add_header X-Content-Type-Options "nosniff" always;',
            "Referrer-Policy": 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
            "Permissions-Policy": 'add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;'
        }

        caddy_map = {
            "Strict-Transport-Security": "header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"",
            "Content-Security-Policy": "header Content-Security-Policy \"default-src 'self';\"",
            "X-Frame-Options": "header X-Frame-Options \"DENY\"",
            "X-Content-Type-Options": "header X-Content-Type-Options \"nosniff\"",
            "Referrer-Policy": "header Referrer-Policy \"strict-origin-when-cross-origin\"",
            "Permissions-Policy": "header Permissions-Policy \"camera=(), microphone=()\""
        }

        nginx_lines = [headers_map.get(h, f'add_header {h} "1" always;') for h in missing_headers if h in headers_map]
        caddy_lines = [caddy_map.get(h, f'header {h} "1"') for h in missing_headers if h in caddy_map]

        nginx_conf = "# ShieldCI Hardened Security Headers for Nginx\n" + "\n".join(nginx_lines)
        caddy_conf = "# ShieldCI Hardened Security Headers for Caddy\n" + "\n".join(caddy_lines)

        return {
            "nginx": nginx_conf,
            "caddy": caddy_conf
        }

    @classmethod
    def bundle_repository_patch(cls, findings: List[Finding], base_dir: Optional[str] = None) -> str:
        """
        Generates a consolidated multi-file `shieldci-remediation.patch` file
        applicable with `git apply shieldci-remediation.patch`.
        """
        patch_chunks = []

        # Process each finding that is auto_fixable
        handled_files = set()
        for f in findings:
            if not f.file_path or f.file_path in handled_files:
                continue

            full_p = os.path.join(base_dir, f.file_path) if base_dir and os.path.isdir(base_dir) else None
            content = None
            if full_p and os.path.isfile(full_p):
                try:
                    with open(full_p, "r", encoding="utf-8", errors="ignore") as fp:
                        content = fp.read()
                except Exception:
                    pass

            if f.category == FindingCategory.IAC_CONTAINER and ("dockerfile" in f.file_path.lower() or f.file_path.endswith("Dockerfile")):
                if content:
                    p = cls.generate_dockerfile_patch(content, f.file_path)
                    if p:
                        patch_chunks.append(p)
                        handled_files.add(f.file_path)

            elif f.category == FindingCategory.PIPELINE_MISCONFIG and (f.file_path.endswith(".yml") or f.file_path.endswith(".yaml")):
                if content:
                    p = cls.generate_workflow_patch(content, f.file_path)
                    if p:
                        patch_chunks.append(p)
                        handled_files.add(f.file_path)

            elif f.category == FindingCategory.SCA_VULNERABILITY and "requirements.txt" in f.file_path:
                if content:
                    p = cls.generate_requirements_patch(content, f.file_path)
                    if p:
                        patch_chunks.append(p)
                        handled_files.add(f.file_path)

        if not patch_chunks:
            # Fallback informative patch header
            return (
                "# ShieldCI Automated Remediation Patch\n"
                "# No code-level patches required or source files could not be modified automatically.\n"
                "# Please refer to the individual remediation instructions in the dashboard.\n"
            )

        header = (
            "# ====================================================================\n"
            "# ShieldCI Automated Multi-File Remediation Patch\n"
            "# Apply using: git apply shieldci-remediation.patch\n"
            "# ====================================================================\n\n"
        )
        return header + "\n\n".join(patch_chunks) + "\n"