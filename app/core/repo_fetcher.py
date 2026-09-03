"""
app/core/repo_fetcher.py
Universal repository ingestion manager: handles Git URLs, ZIP archives, and local paths.
"""

import os
import re
import stat
import shutil
import tempfile
import subprocess
import zipfile
import requests
from contextlib import contextmanager
from typing import Generator, Tuple, Optional
from app.config import settings
from app.models.schemas import SourceType


def _remove_readonly(func, path, exc_info):
    """Clear the readonly bit and reattempt file removal (critical for Windows .git dirs)."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


class RepoFetcher:
    """Manages cloning, extracting, and preparing repositories for security scanning."""

    GIT_URL_PATTERNS = [
        re.compile(r"^https?://", re.IGNORECASE),
        re.compile(r"^git@", re.IGNORECASE),
        re.compile(r"^ssh://", re.IGNORECASE),
        re.compile(r"^git://", re.IGNORECASE),
        re.compile(r"^(github\.com|gitlab\.com|bitbucket\.org)/", re.IGNORECASE),
        re.compile(r"^[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-\.]+$")  # owner/repo shorthand
    ]

    @classmethod
    def is_git_url(cls, target: str) -> bool:
        if not target or not isinstance(target, str):
            return False
        cleaned = target.strip()
        # Explicit local directory paths take precedence
        if cleaned.startswith(("./", ".\\", "../", "..\\", "/", "\\")) or os.path.exists(cleaned):
            return False
        if re.match(r"^[a-zA-Z]:[/\\]", cleaned):  # Windows drive letter C:\
            return False
        return any(pattern.search(cleaned) for pattern in cls.GIT_URL_PATTERNS)

    @classmethod
    def normalize_git_url(cls, target: str) -> str:
        url = target.strip()
        if re.match(r"^[a-zA-Z0-9_\-\.]+\/[a-zA-Z0-9_\-\.]+$", url):
            url = f"https://github.com/{url}"
        elif url.lower().startswith(("github.com/", "gitlab.com/", "bitbucket.org/")):
            url = f"https://{url}"
        
        if not url.endswith(".git") and not url.startswith("git@"):
            url = f"{url}.git"
        return url

    @classmethod
    def extract_repo_name(cls, target: str) -> str:
        if not target:
            return "Repository"
        cleaned = target.strip().rstrip("/\\")
        if cleaned.endswith(".git"):
            cleaned = cleaned[:-4]
        if cleaned.endswith(".zip"):
            cleaned = cleaned[:-4]
        
        # Take the last segment of path or URL
        parts = re.split(r"[/\\:]+", cleaned)
        return parts[-1] if parts else "Repository"

    @classmethod
    def download_repo_archive(cls, git_url: str, branch: Optional[str] = None, dest_dir: Optional[str] = None) -> str:
        """
        Downloads a remote git repository archive directly via HTTPS and extracts it.
        Allows repository scanning in environments without the git CLI (such as Vercel and serverless).
        """
        if not dest_dir:
            dest_dir = tempfile.mkdtemp(prefix="shieldci_git_", dir=settings.TEMP_SCAN_DIR)

        cleaned = git_url.strip()
        if cleaned.endswith(".git"):
            cleaned = cleaned[:-4]

        # Extract owner and repo for GitHub
        github_match = re.search(r"github\.com[/:]([^/]+)/([^/\?#]+)", cleaned)
        if not github_match and re.match(r"^[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-\.]+$", cleaned):
            parts = cleaned.split("/")
            owner, repo = parts[0], parts[1]
        elif github_match:
            owner, repo = github_match.group(1), github_match.group(2)
        else:
            owner, repo = None, None

        download_urls = []
        if owner and repo:
            if branch:
                download_urls.append(f"https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip")
                download_urls.append(f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}")
            # Default branch fallbacks (HEAD, main, master)
            download_urls.append(f"https://github.com/{owner}/{repo}/archive/HEAD.zip")
            download_urls.append(f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/main")
            download_urls.append(f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/master")
        elif "gitlab.com" in cleaned:
            gl_match = re.search(r"gitlab\.com[/:]([^/]+)/([^/\?#]+)", cleaned)
            if gl_match:
                gl_owner, gl_repo = gl_match.group(1), gl_match.group(2)
                target_branch = branch or "main"
                download_urls.append(f"https://gitlab.com/{gl_owner}/{gl_repo}/-/archive/{target_branch}/{gl_repo}-{target_branch}.zip")
                if not branch:
                    download_urls.append(f"https://gitlab.com/{gl_owner}/{gl_repo}/-/archive/master/{gl_repo}-master.zip")
        elif "bitbucket.org" in cleaned:
            bb_match = re.search(r"bitbucket\.org[/:]([^/]+)/([^/\?#]+)", cleaned)
            if bb_match:
                bb_owner, bb_repo = bb_match.group(1), bb_match.group(2)
                target_branch = branch or "HEAD"
                download_urls.append(f"https://bitbucket.org/{bb_owner}/{bb_repo}/get/{target_branch}.zip")

        if not download_urls:
            cls.safe_cleanup(dest_dir)
            raise RuntimeError(
                f"Cannot download repository archive for '{git_url}'. "
                "Supported remote providers without git CLI: GitHub, GitLab, and Bitbucket. "
                "Alternatively, upload a ZIP archive directly."
            )

        headers = {
            "User-Agent": "ShieldCI-Security-Auditor/1.0",
            "Accept": "application/zip, application/octet-stream, */*"
        }

        temp_zip_fd, temp_zip_file = tempfile.mkstemp(suffix=".zip", dir=settings.TEMP_SCAN_DIR)
        os.close(temp_zip_fd)
        download_success = False
        last_error = ""

        try:
            for url in download_urls:
                try:
                    resp = requests.get(
                        url,
                        headers=headers,
                        stream=True,
                        timeout=settings.GIT_TIMEOUT_SECONDS,
                        allow_redirects=True
                    )
                    if resp.status_code == 200:
                        with open(temp_zip_file, "wb") as f:
                            for chunk in resp.iter_content(chunk_size=128 * 1024):
                                if chunk:
                                    f.write(chunk)
                        if zipfile.is_zipfile(temp_zip_file):
                            download_success = True
                            break
                        else:
                            if os.path.exists(temp_zip_file):
                                os.remove(temp_zip_file)
                    else:
                        last_error = f"HTTP {resp.status_code} ({url})"
                except Exception as e:
                    last_error = str(e)

            if not download_success:
                cls.safe_cleanup(dest_dir)
                raise RuntimeError(
                    f"Failed to download repository archive for '{git_url}'. "
                    f"Ensure the repository is public or branch exists. ({last_error})"
                )

            scan_path = cls.extract_zip_archive(temp_zip_file, dest_dir)
            return scan_path
        finally:
            if os.path.exists(temp_zip_file):
                try:
                    os.remove(temp_zip_file)
                except Exception:
                    pass

    @classmethod
    def clone_git_repo(cls, git_url: str, branch: Optional[str] = None, dest_dir: Optional[str] = None) -> str:
        """
        Clones a remote git repository shallowly into a destination directory.
        Automatically falls back to HTTPS archive download if git CLI is absent (e.g. on Vercel).
        """
        # If git CLI is not installed on the host, seamlessly download via HTTPS
        if not shutil.which("git"):
            return cls.download_repo_archive(git_url, branch=branch, dest_dir=dest_dir)

        if not dest_dir:
            dest_dir = tempfile.mkdtemp(prefix="shieldci_git_", dir=settings.TEMP_SCAN_DIR)

        norm_url = cls.normalize_git_url(git_url)
        cmd = ["git", "clone", "--depth", "1", "--single-branch"]
        if branch:
            cmd.extend(["--branch", branch])
        cmd.extend([norm_url, dest_dir])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=settings.GIT_TIMEOUT_SECONDS,
                check=False
            )
            if result.returncode != 0:
                # If branch failed, try cloning default branch without --branch
                if branch:
                    fallback_cmd = ["git", "clone", "--depth", "1", "--single-branch", norm_url, dest_dir]
                    fb_res = subprocess.run(
                        fallback_cmd,
                        capture_output=True,
                        text=True,
                        timeout=settings.GIT_TIMEOUT_SECONDS,
                        check=False
                    )
                    if fb_res.returncode == 0:
                        return dest_dir

                # If git clone failed, fall back to HTTPS archive download
                return cls.download_repo_archive(git_url, branch=branch, dest_dir=dest_dir)

            return dest_dir
        except (FileNotFoundError, OSError):
            # git CLI not executable, download archive directly
            return cls.download_repo_archive(git_url, branch=branch, dest_dir=dest_dir)
        except subprocess.TimeoutExpired:
            cls.safe_cleanup(dest_dir)
            raise TimeoutError(f"Cloning '{git_url}' timed out after {settings.GIT_TIMEOUT_SECONDS}s")
        except Exception:
            # Final fallback to HTTPS archive download
            try:
                return cls.download_repo_archive(git_url, branch=branch, dest_dir=dest_dir)
            except Exception as ex:
                cls.safe_cleanup(dest_dir)
                raise ex

    @classmethod
    def extract_zip_archive(cls, zip_path: str, dest_dir: Optional[str] = None) -> str:
        """Extracts a ZIP archive safely with path traversal protection."""
        if not dest_dir:
            dest_dir = tempfile.mkdtemp(prefix="shieldci_zip_", dir=settings.TEMP_SCAN_DIR)

        if not os.path.isfile(zip_path):
            raise FileNotFoundError(f"ZIP file not found: {zip_path}")

        with zipfile.ZipFile(zip_path, "r") as zf:
            # Path traversal check
            for member in zf.namelist():
                norm = os.path.normpath(member)
                if norm.startswith("..") or os.path.isabs(norm):
                    raise ValueError(f"Illegal path traversal detected in ZIP: {member}")

            zf.extractall(dest_dir)

        # Check if zip unpacked into a single parent root directory (e.g. repo-main/)
        entries = os.listdir(dest_dir)
        if len(entries) == 1:
            single_entry = os.path.join(dest_dir, entries[0])
            if os.path.isdir(single_entry):
                return single_entry

        return dest_dir

    @classmethod
    def safe_cleanup(cls, path: Optional[str]):
        """Recursively removes directory handling Windows readonly files."""
        if path and os.path.exists(path):
            try:
                shutil.rmtree(path, onerror=_remove_readonly)
            except Exception:
                pass

    @classmethod
    @contextmanager
    def prepare_scan_target(
        cls,
        target_input: str,
        branch: Optional[str] = None,
        is_zip_upload: bool = False
    ) -> Generator[Tuple[str, str, SourceType], None, None]:
        """
        Prepares a target directory for scanning.
        Yields (local_scan_path, repo_name, source_type).
        Guarantees cleanup of temporary workspaces upon exit.
        """
        temp_dir_to_clean: Optional[str] = None
        cleaned_target = (target_input or "").strip()

        try:
            if is_zip_upload or (cleaned_target.endswith(".zip") and os.path.isfile(cleaned_target)):
                temp_dir = tempfile.mkdtemp(prefix="shieldci_zip_", dir=settings.TEMP_SCAN_DIR)
                temp_dir_to_clean = temp_dir
                scan_path = cls.extract_zip_archive(cleaned_target, temp_dir)
                repo_name = cls.extract_repo_name(cleaned_target)
                yield scan_path, repo_name, SourceType.UPLOAD

            elif cls.is_git_url(cleaned_target):
                temp_dir = tempfile.mkdtemp(prefix="shieldci_git_", dir=settings.TEMP_SCAN_DIR)
                temp_dir_to_clean = temp_dir
                scan_path = cls.clone_git_repo(cleaned_target, branch=branch, dest_dir=temp_dir)
                repo_name = cls.extract_repo_name(cleaned_target)
                yield scan_path, repo_name, SourceType.GIT

            else:
                # Local filesystem path
                abs_path = os.path.abspath(cleaned_target)
                if not os.path.exists(abs_path):
                    raise FileNotFoundError(f"Local repository path does not exist: {cleaned_target}")
                repo_name = os.path.basename(abs_path.rstrip("/\\")) or "Repository"
                yield abs_path, repo_name, SourceType.LOCAL

        finally:
            if temp_dir_to_clean:
                cls.safe_cleanup(temp_dir_to_clean)
