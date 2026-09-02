"""app/scanners/workflow_scanner.py"""
import os
import yaml
import re
import uuid
from typing import List
from app.models.schemas import Finding, FindingCategory, SeverityLevel

class WorkflowScanner:
    """Scans CI/CD pipeline definitions for dangerous misconfigurations."""

    def __init__(self):
        self.dangerous_triggers = ["pull_request_target", "workflow_run"]
        self.injection_pattern = re.compile(r"\$\{\{\s*(github\.event\.issue\.title|github\.event\.pull_request\.title|github\.event\.comment\.body|github\.head_ref)\s*\}\}")

    def scan(self, base_path: str) -> List[Finding]:
        findings = []
        workflow_dirs = [
            os.path.join(base_path, ".github", "workflows"),
            os.path.join(base_path, ".gitlab-ci.yml")
        ]

        for entry in workflow_dirs:
            if os.path.isdir(entry):
                for root, _, files in os.walk(entry):
                    for file in files:
                        if file.endswith((".yml", ".yaml")):
                            full_path = os.path.join(root, file)
                            rel_path = os.path.relpath(full_path, base_path)
                            findings.extend(self._scan_github_workflow(full_path, rel_path))
            elif os.path.isfile(entry):
                rel_path = os.path.relpath(entry, base_path)
                findings.extend(self._scan_gitlab_ci(entry, rel_path))

        return findings

    def _scan_github_workflow(self, file_path: str, rel_path: str) -> List[Finding]:
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
                data = yaml.safe_load(content)

            lines = content.splitlines()

            # Rule 1: Dangerous pull_request_target trigger
            triggers = data.get("on", data.get(True, []))
            is_pr_target = False
            if isinstance(triggers, list) and "pull_request_target" in triggers:
                is_pr_target = True
            elif isinstance(triggers, dict) and "pull_request_target" in triggers:
                is_pr_target = True
            elif triggers == "pull_request_target":
                is_pr_target = True

            if is_pr_target:
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    category=FindingCategory.PIPELINE_MISCONFIG,
                    severity=SeverityLevel.CRITICAL,
                    title="Insecure Workflow Trigger: 'pull_request_target'",
                    description="The workflow uses 'pull_request_target' which grants write tokens and secret access to PRs from untrusted forks.",
                    file_path=rel_path,
                    line_number=1,
                    snippet="on: pull_request_target",
                    remediation_advice="Change trigger to 'pull_request' or strictly isolate checkout and script execution.",
                    auto_fixable=True,
                    fix_patch="Replace 'pull_request_target' with 'pull_request'"
                ))

            # Rule 2: Over-permissive default GITHUB_TOKEN permissions
            permissions = data.get("permissions")
            if permissions == "write-all" or (isinstance(permissions, dict) and any(v == "write" for v in permissions.values())):
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    category=FindingCategory.PIPELINE_MISCONFIG,
                    severity=SeverityLevel.HIGH,
                    title="Excessive Pipeline Permissions (write-all)",
                    description="Workflow grants broad write permissions to GITHUB_TOKEN, violating the principle of least privilege.",
                    file_path=rel_path,
                    line_number=1,
                    snippet=f"permissions: {permissions}",
                    remediation_advice="Set explicit top-level 'permissions: read-all' or configure minimal per-job permissions.",
                    auto_fixable=True
                ))

            # Rule 3: Unpinned 3rd-Party Actions (Mutable Tags)
            jobs = data.get("jobs", {})
            if isinstance(jobs, dict):
                for job_name, job_def in jobs.items():
                    steps = job_def.get("steps", []) if isinstance(job_def, dict) else []
                    for step_idx, step in enumerate(steps):
                        if not isinstance(step, dict):
                            continue
                        uses = step.get("uses", "")
                        if uses and not uses.startswith("./") and not uses.startswith("docker://"):
                            if "@" in uses:
                                action_ref = uses.split("@")[1]
                                # SHA-1 commit hashes are 40 hex chars
                                if len(action_ref) != 40 or not all(c in "0123456789abcdefABCDEF" for c in action_ref):
                                    findings.append(Finding(
                                        id=str(uuid.uuid4()),
                                        category=FindingCategory.PIPELINE_MISCONFIG,
                                        severity=SeverityLevel.MEDIUM,
                                        title=f"Unpinned 3rd-Party Action in Job '{job_name}'",
                                        description=f"Action '{uses}' is referenced by a mutable tag/branch. Attackers who compromise the upstream repository can hijack your build.",
                                        file_path=rel_path,
                                        line_number=self._find_line_number(lines, uses),
                                        snippet=f"uses: {uses}",
                                        remediation_advice=f"Pin '{uses.split('@')[0]}' to a full 40-character commit SHA hash.",
                                        auto_fixable=False
                                    ))

                        # Rule 4: Script Injection in Run Steps
                        run_cmd = step.get("run", "")
                        if run_cmd and self.injection_pattern.search(run_cmd):
                            matched = self.injection_pattern.search(run_cmd).group(0)
                            findings.append(Finding(
                                id=str(uuid.uuid4()),
                                category=FindingCategory.PIPELINE_MISCONFIG,
                                severity=SeverityLevel.CRITICAL,
                                title=f"CI/CD Script Injection Vector in Job '{job_name}'",
                                description=f"Untrusted context '{matched}' is directly interpolated into a shell script execution.",
                                file_path=rel_path,
                                line_number=self._find_line_number(lines, matched),
                                snippet=run_cmd[:120],
                                remediation_advice="Pass untrusted context values through intermediate environment variables instead of direct inline template strings.",
                                auto_fixable=False
                            ))

        except Exception:
            pass # Skip malformed YAML gracefully
        return findings

    def _scan_gitlab_ci(self, file_path: str, rel_path: str) -> List[Finding]:
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            if "dangerouslyDisableHostKeyChecking" in content or "strictHostKeyChecking=no" in content:
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    category=FindingCategory.PIPELINE_MISCONFIG,
                    severity=SeverityLevel.HIGH,
                    title="Insecure SSH Strict Host Key Checking in GitLab CI",
                    description="Host key validation is explicitly disabled, allowing MITM attacks during code deployment.",
                    file_path=rel_path,
                    line_number=1,
                    remediation_advice="Provide known_hosts explicitly rather than disabling StrictHostKeyChecking.",
                    auto_fixable=False
                ))
        except Exception:
            pass
        return findings

    def _find_line_number(self, lines: List[str], target: str) -> int:
        for idx, line in enumerate(lines, 1):
            if target in line:
                return idx
        return 1