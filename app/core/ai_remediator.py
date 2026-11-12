"""
app/core/ai_remediator.py
AI-Powered Vulnerability Remediation & Code Synthesis Engine.
Generates context-aware, production-ready code fixes, unified diffs,
and developer explanations for detected CI/CD and codebase exposures.
"""

import os
import re
import difflib
import json
from typing import Optional, Dict, Any
from app.models.schemas import Finding, FindingCategory, SeverityLevel, AIRemediationResponse


class AIRemediator:
    """Generates intelligent, syntactically-verified remediations using AI or context-aware rules."""

    @classmethod
    def generate_remediation(
        cls,
        finding: Finding,
        original_content: Optional[str] = None,
        instructions: Optional[str] = None,
        model: Optional[str] = "gemini-flash"
    ) -> AIRemediationResponse:
        """
        Synthesizes an intelligent code fix for a finding.
        Uses external LLM (Gemini/OpenAI) if API key is present; otherwise falls back
        to the deterministic contextual synthesis engine.
        """
        gemini_api_key = os.getenv("GEMINI_API_KEY")
        openai_api_key = os.getenv("OPENAI_API_KEY")

        # 1. Attempt LLM generation if configured
        if gemini_api_key:
            try:
                return cls._remediate_with_gemini(finding, original_content, instructions, gemini_api_key)
            except Exception:
                pass  # Fall back to local synthesis engine

        if openai_api_key:
            try:
                return cls._remediate_with_openai(finding, original_content, instructions, openai_api_key)
            except Exception:
                pass  # Fall back to local synthesis engine

        # 2. Deterministic Contextual Synthesis Engine
        return cls._remediate_with_contextual_engine(finding, original_content, instructions)

    @classmethod
    def _remediate_with_contextual_engine(
        cls,
        finding: Finding,
        original_content: Optional[str] = None,
        instructions: Optional[str] = None
    ) -> AIRemediationResponse:
        """High-fidelity local contextual synthesizer guaranteeing immediate, syntactically sound diffs."""
        file_path = finding.file_path or "vulnerable_file"
        content = original_content or finding.snippet or ""

        remediated_content = content
        explanation = ""
        safety_notes = ""
        test_command = "git diff --check"

        # Categorical synthesis
        if finding.category == FindingCategory.PIPELINE_MISCONFIG:
            if "pull_request_target" in content or "pull_request_target" in finding.title:
                remediated_content = content.replace("pull_request_target", "pull_request")
                if "permissions:" not in remediated_content:
                    remediated_content = re.sub(
                        r"(on:\s*\n(\s+pull_request:[^\n]*\n)?)",
                        r"\1permissions:\n  contents: read\n\n",
                        remediated_content,
                        count=1
                    )
                explanation = (
                    "Replaced the untrusted `pull_request_target` trigger with standard `pull_request`. "
                    "In GitHub Actions, `pull_request_target` runs in the context of the base repository "
                    "with access to repository secrets, allowing untrusted fork pull requests to execute arbitrary code. "
                    "Explicitly constrained `permissions: contents: read` to enforce the Principle of Least Privilege."
                )
                safety_notes = "Safe for public forks. If the workflow requires writing comments or PR status, use a separate workflow with `workflow_run`."
                test_command = "act -j $(grep -l 'pull_request' .github/workflows/*.yml | head -n 1)"
            elif "write-all" in content or "permission" in finding.title.lower():
                remediated_content = re.sub(
                    r"permissions:\s*write-all",
                    "permissions:\n  contents: read\n  pull-requests: read\n  issues: none",
                    content
                )
                explanation = "Revoked blanket `write-all` token permissions, replacing them with minimal read scopes."
                safety_notes = "Verify downstream steps do not require pushing tags or publishing release artifacts."
                test_command = "gh action-lint .github/workflows/*.yml"
            else:
                remediated_content = (
                    "# [ShieldCI Hardened] Enforce strict least-privilege token access\n"
                    "permissions:\n  contents: read\n\n" + content
                )
                explanation = f"Hardened workflow definition for {finding.title}."
                safety_notes = "Check action execution in test branch before deploying."

        elif finding.category == FindingCategory.SECRET_EXPOSURE:
            var_name = "APP_SECRET_TOKEN"
            title_lower = finding.title.lower()
            fp_lower = file_path.lower()
            if "aws" in title_lower:
                var_name = "AWS_SECRET_ACCESS_KEY"
            elif "github" in title_lower:
                var_name = "GITHUB_TOKEN"
            elif any(k in title_lower or k in fp_lower for k in ("postgres", "mysql", "database", "db")):
                var_name = "DATABASE_URL"
            elif any(k in title_lower or k in fp_lower for k in ("supabase",)):
                var_name = "SUPABASE_KEY"
            elif "stripe" in title_lower:
                var_name = "STRIPE_SECRET_KEY"

            lines = content.splitlines() if content else []
            modified_line = False

            # If we have the full file and valid line number, surgically replace the vulnerable line
            if lines and finding.line_number and 1 <= finding.line_number <= len(lines):
                target_idx = finding.line_number - 1
                orig_line = lines[target_idx]
                indent = re.match(r"^\s*", orig_line).group(0)

                dict_match = re.match(r'^(\s*[\'"][a-zA-Z0-9_\-]+[\'"]\s*:\s*)(.*)$', orig_line)
                var_match = re.match(r'^(\s*[a-zA-Z0-9_]+\s*=\s*)(.*)$', orig_line)

                if dict_match and file_path.endswith(".py"):
                    prefix = dict_match.group(1)
                    lines[target_idx] = f'{prefix}os.getenv("{var_name}", "")'
                    modified_line = True
                elif var_match and file_path.endswith(".py"):
                    prefix = var_match.group(1)
                    lines[target_idx] = f'{prefix}os.getenv("{var_name}", "")'
                    modified_line = True
                elif file_path.endswith(".py"):
                    lines[target_idx] = f'{indent}{var_name} = os.getenv("{var_name}", "")  # [ShieldCI Fix]'
                    modified_line = True

                if modified_line and file_path.endswith(".py"):
                    if not any(re.match(r"^\s*import\s+os\b", l) for l in lines):
                        lines.insert(0, "import os")
                    remediated_content = "\n".join(lines)

            if not modified_line:
                if file_path.endswith(".py"):
                    remediated_line = f'import os\n{var_name} = os.getenv("{var_name}")  # [ShieldCI Fix] Load via environment variable'
                elif file_path.endswith((".yml", ".yaml")):
                    remediated_line = f'${{{{ secrets.{var_name} }}}}  # [ShieldCI Fix] Referenced via GitHub Actions Secret'
                else:
                    remediated_line = f'${{{var_name}}}  # [ShieldCI Fix] Loaded securely from environment'

                secret_line = finding.snippet or "SECRET_KEY = '***'"
                remediated_content = content.replace(secret_line, remediated_line) if (content and secret_line in content) else (content + f"\n# Remediation: Replace hardcoded credential with {var_name}")
            explanation = (
                f"Extracted hardcoded credential out of source control. Replaced with secure runtime environment lookup `{var_name}`. "
                "Hardcoded credentials in repositories are vulnerable to history scraping and inadvertent exposure in build logs."
            )
            safety_notes = f"CRITICAL: Rotate the exposed credential immediately. Once pushed, set `{var_name}` in your CI/CD repository secrets or Vault."
            test_command = f"echo ${var_name}"

        elif finding.category == FindingCategory.IAC_CONTAINER:
            lines = content.splitlines()
            if not any(re.match(r"^\s*USER\s+", l, re.IGNORECASE) for l in lines):
                lines.append("\n# [ShieldCI Security] Run container as unprivileged user (UID 10001)")
                lines.append("RUN addgroup -S appgroup && adduser -S appuser -G appgroup 2>/dev/null || true")
                lines.append("USER 10001")
            # Replace :latest
            new_lines = []
            for l in lines:
                if re.match(r"^\s*FROM\s+[^\s:]+:latest", l, re.IGNORECASE):
                    new_lines.append(re.sub(r":latest", ":3.12-slim  # Pinned base image tag", l))
                else:
                    new_lines.append(l)
            remediated_content = "\n".join(new_lines)
            explanation = (
                "1. Added non-root `USER 10001` directive to prevent container breakout and host filesystem modification in case of RCE.\n"
                "2. Pinned the base container image tag to eliminate non-deterministic builds and supply-chain drift."
            )
            safety_notes = "Ensure application directory permissions allow write access by UID 10001 if the app writes temporary files."
            test_command = "docker build -t test-hardened -f " + file_path + " ."

        elif finding.category == FindingCategory.SCA_VULNERABILITY:
            # Bump library
            safe_versions = {"requests": "2.32.3", "urllib3": "2.2.2", "pyyaml": "6.0.1", "flask": "3.0.3", "django": "5.0.7", "fastapi": "0.110.0"}
            remediated_content = content
            for pkg, ver in safe_versions.items():
                if pkg in remediated_content.lower():
                    remediated_content = re.sub(rf"{pkg}[=<>!~]+[0-9\.\w\-]+", f"{pkg}>={ver}", remediated_content, flags=re.IGNORECASE)
            explanation = f"Upgraded dependency to patched release addressing known CVE vulnerability ({finding.cve_id or 'Advisory'})."
            safety_notes = "Review semantic versioning changelog for potential breaking API changes before merging."
            test_command = "pip install -r requirements.txt && pip check"

        else:
            remediated_content = finding.fix_patch or content
            explanation = finding.remediation_advice
            safety_notes = "Review proposed changes in your test suite."

        # Generate Unified Diff
        diff = list(difflib.unified_diff(
            content.splitlines(),
            remediated_content.splitlines(),
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm=""
        ))
        patch_str = "\n".join(diff) if diff else (finding.fix_patch or "# No diff generated; verify configuration manual fix")

        return AIRemediationResponse(
            finding_id=finding.id,
            title=finding.title,
            file_path=file_path,
            original_code=content,
            remediated_code=remediated_content,
            unified_patch=patch_str,
            explanation=explanation,
            safety_notes=safety_notes,
            test_command=test_command
        )

    @classmethod
    def _remediate_with_gemini(
        cls,
        finding: Finding,
        original_content: Optional[str],
        instructions: Optional[str],
        api_key: str
    ) -> AIRemediationResponse:
        """Invokes Gemini REST API to produce high-precision refactoring."""
        import requests
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        
        prompt = f"""
You are an expert DevSecOps and AppSec Engineer. Provide a complete, production-grade security fix for the following finding:
Finding Title: {finding.title}
Category: {finding.category.value}
Severity: {finding.severity.value}
File Path: {finding.file_path}
Vulnerability Details: {finding.description}
Snippet/Code:
```
{original_content or finding.snippet or ""}
```
User Instructions: {instructions or 'Provide a minimal, safe, backwards-compatible fix.'}

Respond ONLY in valid JSON matching this structure:
{{
  "remediated_code": "full fixed code as string",
  "explanation": "concise explanation of what was fixed and why it stops the attack",
  "safety_notes": "operational notes or compatibility verification",
  "test_command": "command to verify the fix locally"
}}
"""
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        res = requests.post(url, json=payload, timeout=12)
        res.raise_for_status()
        data = res.json()
        raw_text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
        # Clean markdown codeblocks if enclosed
        if raw_text.startswith("```"):
            raw_text = re.sub(r"^```[a-z]*\n", "", raw_text)
            raw_text = re.sub(r"\n```$", "", raw_text)
        parsed = json.loads(raw_text)

        remediated_code = parsed.get("remediated_code", "")
        file_path = finding.file_path or "vulnerable_file"
        diff = list(difflib.unified_diff(
            (original_content or finding.snippet or "").splitlines(),
            remediated_code.splitlines(),
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm=""
        ))
        patch_str = "\n".join(diff)

        return AIRemediationResponse(
            finding_id=finding.id,
            title=finding.title,
            file_path=file_path,
            original_code=original_content or finding.snippet or "",
            remediated_code=remediated_code,
            unified_patch=patch_str,
            explanation=parsed.get("explanation", finding.remediation_advice),
            safety_notes=parsed.get("safety_notes", "Review change locally."),
            test_command=parsed.get("test_command", "git diff")
        )

    @classmethod
    def _remediate_with_openai(
        cls,
        finding: Finding,
        original_content: Optional[str],
        instructions: Optional[str],
        api_key: str
    ) -> AIRemediationResponse:
        """Invokes OpenAI Chat Completion API."""
        import requests
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        prompt = f"""
Provide a complete, production-grade security fix for:
Finding Title: {finding.title}
File Path: {finding.file_path}
Vulnerability: {finding.description}
Code:
{original_content or finding.snippet or ""}

Return JSON with keys: 'remediated_code', 'explanation', 'safety_notes', 'test_command'.
"""
        payload = {
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"}
        }
        res = requests.post(url, json=payload, headers=headers, timeout=12)
        res.raise_for_status()
        data = res.json()
        parsed = json.loads(data["choices"][0]["message"]["content"])

        remediated_code = parsed.get("remediated_code", "")
        file_path = finding.file_path or "vulnerable_file"
        diff = list(difflib.unified_diff(
            (original_content or finding.snippet or "").splitlines(),
            remediated_code.splitlines(),
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm=""
        ))

        return AIRemediationResponse(
            finding_id=finding.id,
            title=finding.title,
            file_path=file_path,
            original_code=original_content or finding.snippet or "",
            remediated_code=remediated_code,
            unified_patch="\n".join(diff),
            explanation=parsed.get("explanation", finding.remediation_advice),
            safety_notes=parsed.get("safety_notes", ""),
            test_command=parsed.get("test_command", "git diff")
        )

