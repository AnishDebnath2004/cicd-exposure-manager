"""app/core/remediator.py"""
import os
import difflib
from typing import Optional

class AutoRemediator:
    """Generates unified git diff patches to automatically fix safe issues."""

    @staticmethod
    def generate_dockerfile_user_patch(dockerfile_path: str) -> Optional[str]:
        if not os.path.isfile(dockerfile_path):
            return None
        with open(dockerfile_path, "r", encoding="utf-8") as f:
            original = f.read()

        lines = original.splitlines(keepends=True)
        # Add nonroot user at the end
        remediated_lines = list(lines)
        remediated_lines.append("\n# [DevSecOps Remediated] Run as non-root user\nUSER 10001\n")

        diff = difflib.unified_diff(
            lines,
            remediated_lines,
            fromfile=f"a/{os.path.basename(dockerfile_path)}",
            tofile=f"b/{os.path.basename(dockerfile_path)}"
        )
        return "".join(diff)