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
    def clone_git_repo(cls, git_url: str, branch: Optional[str] = None, dest_dir: Optional[str] = None) -> str:
        """Clones a remote git repository shallowly into a destination directory."""
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
                    if fb_res.returncode != 0:
                        raise RuntimeError(f"Git clone failed: {fb_res.stderr or fb_res.stdout or result.stderr}")
                else:
                    raise RuntimeError(f"Git clone failed: {result.stderr or result.stdout}")

            return dest_dir
        except subprocess.TimeoutExpired:
            cls.safe_cleanup(dest_dir)
            raise TimeoutError(f"Cloning '{git_url}' timed out after {settings.GIT_TIMEOUT_SECONDS}s")
        except Exception as e:
            cls.safe_cleanup(dest_dir)
            raise e

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
