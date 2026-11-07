"""
app/core/github_service.py
GitHub REST API Client for Automated Remediation Pull Requests.
Branches target repositories, commits security fixes, and opens rich Pull Requests.
"""

import os
import re
import time
import base64
import requests
from typing import Optional, Tuple, Dict, Any
from app.models.schemas import GitHubPROpenResponse


class GitHubService:
    """Manages GitHub repository operations: branching, committing fixes, and opening PRs."""

    GITHUB_API_BASE = "https://api.github.com"

    @classmethod
    def parse_repo_owner_name(cls, repo_target: str) -> Optional[Tuple[str, str]]:
        """Extracts (owner, repo) from URL or slug format."""
        if not repo_target:
            return None
        cleaned = repo_target.strip().rstrip("/")
        if cleaned.endswith(".git"):
            cleaned = cleaned[:-4]

        # Match https://github.com/owner/repo or git@github.com:owner/repo
        match = re.search(r"github\.com[/:]([a-zA-Z0-9_\-\.]+)/([a-zA-Z0-9_\-\.]+)", cleaned)
        if match:
            return match.group(1), match.group(2)

        # Match "owner/repo"
        slug_match = re.match(r"^([a-zA-Z0-9_\-\.]+)/([a-zA-Z0-9_\-\.]+)$", cleaned)
        if slug_match:
            return slug_match.group(1), slug_match.group(2)

        return None

    @classmethod
    def open_remediation_pr(
        cls,
        repo_target: str,
        file_path: str,
        remediated_content: str,
        finding_title: str,
        finding_id: str,
        github_token: Optional[str] = None,
        branch_name: Optional[str] = None,
        pr_title: Optional[str] = None,
        pr_body: Optional[str] = None
    ) -> GitHubPROpenResponse:
        """
        Creates a Git branch, commits the remediated file, and opens a Pull Request on GitHub.
        """
        token = github_token or os.getenv("GITHUB_TOKEN")
        if not token:
            return GitHubPROpenResponse(
                success=False,
                message="GitHub Personal Access Token (PAT) is required. Please supply a token with 'repo' scope."
            )

        parsed = cls.parse_repo_owner_name(repo_target)
        if not parsed:
            return GitHubPROpenResponse(
                success=False,
                message=f"Invalid GitHub repository identifier '{repo_target}'. Use 'owner/repo' or 'https://github.com/owner/repo'."
            )

        owner, repo = parsed
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ShieldCI-Exposure-Manager/2.0"
        }

        try:
            # 1. Fetch Repository Details to obtain default branch
            repo_url = f"{cls.GITHUB_API_BASE}/repos/{owner}/{repo}"
            r_repo = requests.get(repo_url, headers=headers, timeout=10)
            if r_repo.status_code == 404:
                return GitHubPROpenResponse(
                    success=False,
                    message=f"Repository '{owner}/{repo}' not found or access token lacks repository permissions."
                )
            elif r_repo.status_code == 401:
                return GitHubPROpenResponse(
                    success=False,
                    message="GitHub authentication failed. Please verify your Personal Access Token."
                )
            r_repo.raise_for_status()
            repo_info = r_repo.json()
            default_branch = repo_info.get("default_branch", "main")

            # 2. Get latest commit SHA of default branch
            ref_url = f"{cls.GITHUB_API_BASE}/repos/{owner}/{repo}/git/ref/heads/{default_branch}"
            r_ref = requests.get(ref_url, headers=headers, timeout=10)
            r_ref.raise_for_status()
            base_sha = r_ref.json()["object"]["sha"]

            # 3. Create a unique branch name
            timestamp = int(time.time())
            clean_title = re.sub(r"[^a-zA-Z0-9]+", "-", finding_title.lower()).strip("-")[:24]
            branch = branch_name or f"shieldci/fix-{clean_title}-{str(timestamp)[-5:]}"

            create_ref_url = f"{cls.GITHUB_API_BASE}/repos/{owner}/{repo}/git/refs"
            r_create_ref = requests.post(
                create_ref_url,
                headers=headers,
                json={"ref": f"refs/heads/{branch}", "sha": base_sha},
                timeout=10
            )
            # If branch already exists, proceed using it
            if r_create_ref.status_code not in (201, 422):
                r_create_ref.raise_for_status()

            # 4. Fetch existing file SHA if file exists in the repo
            file_url = f"{cls.GITHUB_API_BASE}/repos/{owner}/{repo}/contents/{file_path.lstrip('/')}?ref={branch}"
            r_file = requests.get(file_url, headers=headers, timeout=10)
            existing_file_sha = None
            if r_file.status_code == 200:
                existing_file_sha = r_file.json().get("sha")

            # 5. Commit remediated content to the new branch
            commit_payload: Dict[str, Any] = {
                "message": f"fix(security): resolve {finding_title} via ShieldCI\n\nAutomated remediation by ShieldCI Exposure Manager.",
                "content": base64.b64encode(remediated_content.encode("utf-8")).decode("utf-8"),
                "branch": branch
            }
            if existing_file_sha:
                commit_payload["sha"] = existing_file_sha

            put_file_url = f"{cls.GITHUB_API_BASE}/repos/{owner}/{repo}/contents/{file_path.lstrip('/')}"
            r_put = requests.put(put_file_url, headers=headers, json=commit_payload, timeout=10)
            r_put.raise_for_status()

            # 6. Open Pull Request
            final_pr_title = pr_title or f"🛡️ ShieldCI Security Fix: {finding_title}"
            final_pr_body = pr_body or (
                f"## 🛡️ ShieldCI Autonomous Security Remediation\n\n"
                f"### Finding Summary\n"
                f"- **Vulnerability:** {finding_title}\n"
                f"- **Target File:** `{file_path}`\n"
                f"- **Automated Remediation Engine:** ShieldCI DevSecOps Posture Manager\n\n"
                f"### What Changed?\n"
                f"This pull request applies security hardening to mitigate risk and enforce least-privilege policies.\n\n"
                f"> [!IMPORTANT]\n"
                f"> Please verify test suites and CI execution in this branch before merging to `{default_branch}`.\n"
            )

            pulls_url = f"{cls.GITHUB_API_BASE}/repos/{owner}/{repo}/pulls"
            r_pr = requests.post(
                pulls_url,
                headers=headers,
                json={
                    "title": final_pr_title,
                    "head": branch,
                    "base": default_branch,
                    "body": final_pr_body
                },
                timeout=12
            )
            r_pr.raise_for_status()
            pr_data = r_pr.json()

            return GitHubPROpenResponse(
                success=True,
                pr_url=pr_data.get("html_url"),
                pr_number=pr_data.get("number"),
                branch=branch,
                message=f"Successfully created Pull Request #{pr_data.get('number')} in {owner}/{repo}"
            )

        except requests.HTTPError as he:
            err_msg = str(he)
            try:
                err_data = he.response.json()
                err_msg = err_data.get("message", str(he))
            except Exception:
                pass
            return GitHubPROpenResponse(
                success=False,
                branch=branch if 'branch' in locals() else None,
                message=f"GitHub API Error: {err_msg}"
            )
        except Exception as e:
            return GitHubPROpenResponse(
                success=False,
                message=f"Failed to create pull request: {str(e)}"
            )

