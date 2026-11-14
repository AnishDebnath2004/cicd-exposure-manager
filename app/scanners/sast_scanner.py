"""
app/scanners/sast_scanner.py
Static Application Security Testing (SAST) Scanner Engine for ShieldCI.
Performs AST and pattern-based static code analysis across Python, JavaScript, and HTML templates
to detect code-level security flaws, SSRF vectors, client-side DOM XSS, and unvalidated network boundaries.
"""

import ast
import os
import re
import uuid
from typing import List, Optional

from app.config import settings
from app.models.schemas import Finding, FindingCategory, SeverityLevel


class SASTScanner:
    """Scans codebases for AST and architectural vulnerabilities."""

    def __init__(self):
        self.ignore_extensions = settings.scanner.IGNORED_EXTENSIONS
        self.ignore_dirs = settings.scanner.IGNORED_DIRECTORIES

    def scan(self, base_path: str) -> List[Finding]:
        findings: List[Finding] = []

        if not os.path.exists(base_path):
            return findings

        if os.path.isfile(base_path):
            return self._scan_file(base_path, os.path.basename(base_path))

        for root, dirs, files in os.walk(base_path):
            # Prune ignored directories
            dirs[:] = [d for d in dirs if d not in self.ignore_dirs and not d.startswith(".")]

            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in self.ignore_extensions:
                    continue

                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, base_path)
                norm_rel = rel_path.replace("\\", "/").lower()

                # Skip tests directory from SAST flagging unless explicitly testing
                if "tests/" in norm_rel or norm_rel.startswith("tests/"):
                    continue

                if ext == ".py":
                    findings.extend(self._scan_python_file(full_path, rel_path))
                elif ext in (".html", ".js", ".jsx", ".ts", ".tsx"):
                    findings.extend(self._scan_frontend_file(full_path, rel_path))

        return findings

    def _scan_python_file(self, file_path: str, rel_path: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                code_content = f.read()
                lines = code_content.splitlines()
        except Exception:
            return findings

        # 1. AST-Based Analysis
        try:
            tree = ast.parse(code_content, filename=file_path)
            findings.extend(self._analyze_python_ast(tree, rel_path, lines))
        except SyntaxError:
            pass

        # 2. Pattern-Based Source-to-Sink Rules
        for line_idx, line in enumerate(lines, 1):
            clean_line = line.strip()
            if not clean_line or clean_line.startswith("#"):
                continue

            # SSRF Rule: socket.create_connection with dynamic host without safe_url check in file
            if "socket.create_connection(" in clean_line:
                if "validate_safe_url" not in code_content and "ip_address" not in code_content:
                    findings.append(Finding(
                        id=str(uuid.uuid4()),
                        category=FindingCategory.SAST_VULNERABILITY,
                        severity=SeverityLevel.HIGH,
                        title="Unvalidated Socket Connection / SSRF Boundary",
                        description=(
                            "Low-level TCP network socket created without prior SSRF / private IP range validation. "
                            "Untrusted input can be exploited to probe internal network ports or cloud instance metadata (169.254.169.254)."
                        ),
                        file_path=rel_path,
                        line_number=line_idx,
                        snippet=clean_line[:120],
                        remediation_advice="Validate host address using 'validate_safe_url()' or reject loopback and private IP subnets before opening socket.",
                        auto_fixable=False
                    ))

            # Untrusted IP Rule: X-Forwarded-For direct spoofing
            if 'request.headers.get("X-Forwarded-For")' in clean_line or "request.headers.get('X-Forwarded-For')" in clean_line:
                if "split" in clean_line or (line_idx < len(lines) and "split" in lines[line_idx]):
                    findings.append(Finding(
                        id=str(uuid.uuid4()),
                        category=FindingCategory.SAST_VULNERABILITY,
                        severity=SeverityLevel.HIGH,
                        title="Untrusted Reverse Proxy Client IP Trust (X-Forwarded-For Spoofing)",
                        description=(
                            "Client IP extraction relies directly on unvalidated 'X-Forwarded-For' header. "
                            "Attackers can forge this header to bypass IP rate limits, quotas, and geo-restrictions."
                        ),
                        file_path=rel_path,
                        line_number=line_idx,
                        snippet=clean_line[:120],
                        remediation_advice="Verify upstream reverse proxy trust or inspect trusted platform headers (e.g., 'X-Real-IP', 'CF-Connecting-IP').",
                        auto_fixable=False
                    ))

        return findings

    def _analyze_python_ast(self, tree: ast.AST, rel_path: str, lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []

        class SecurityVisitor(ast.NodeVisitor):
            def __init__(self):
                self.current_async_func: Optional[str] = None

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
                old = self.current_async_func
                self.current_async_func = node.name
                self.generic_visit(node)
                self.current_async_func = old

            def visit_Call(self, node: ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    val = getattr(node.func.value, "id", "")
                    func_name = f"{val}.{node.func.attr}" if val else node.func.attr

                line_num = getattr(node, "lineno", 1)
                snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""

                # Rule: Dangerous execution (eval, exec)
                if func_name in ("eval", "exec"):
                    findings.append(Finding(
                        id=str(uuid.uuid4()),
                        category=FindingCategory.SAST_VULNERABILITY,
                        severity=SeverityLevel.CRITICAL,
                        title=f"Dangerous Dynamic Code Execution: '{func_name}()'",
                        description=f"Execution of dynamic code using '{func_name}()' can permit Arbitrary Code Execution (RCE).",
                        file_path=rel_path,
                        line_number=line_num,
                        snippet=snippet[:120],
                        remediation_advice="Refactor code to use static dispatch tables or ast.literal_eval for data parsing.",
                        auto_fixable=False
                    ))

                # Rule: Unsafe Deserialization
                if func_name in ("pickle.loads", "pickle.load", "_pickle.loads"):
                    findings.append(Finding(
                        id=str(uuid.uuid4()),
                        category=FindingCategory.SAST_VULNERABILITY,
                        severity=SeverityLevel.CRITICAL,
                        title="Insecure Object Deserialization via 'pickle'",
                        description="Deserializing untrusted pickle byte streams allows arbitrary code execution during object construction.",
                        file_path=rel_path,
                        line_number=line_num,
                        snippet=snippet[:120],
                        remediation_advice="Use safe serialization formats like JSON, Protocol Buffers, or pydantic schemas.",
                        auto_fixable=False
                    ))

                # Rule: Insecure Hash Algorithm (MD5/SHA1 for non-crypto operations)
                if func_name in ("hashlib.md5", "hashlib.sha1"):
                    findings.append(Finding(
                        id=str(uuid.uuid4()),
                        category=FindingCategory.SAST_VULNERABILITY,
                        severity=SeverityLevel.MEDIUM,
                        title=f"Weak Cryptographic Hash Function ({func_name})",
                        description=f"Algorithm '{func_name}' is cryptographically broken and vulnerable to collision attacks.",
                        file_path=rel_path,
                        line_number=line_num,
                        snippet=snippet[:120],
                        remediation_advice="Upgrade hash function to SHA-256 ('hashlib.sha256') or BLAKE2.",
                        auto_fixable=False
                    ))

                # Rule: Synchronous blocking network I/O in async def routes
                if self.current_async_func and func_name in (
                    "requests.get", "requests.post", "requests.put", "requests.delete", "urllib.request.urlopen"
                ):
                    findings.append(Finding(
                        id=str(uuid.uuid4()),
                        category=FindingCategory.SAST_VULNERABILITY,
                        severity=SeverityLevel.MEDIUM,
                        title=f"Synchronous Network Call Blocking Asyncio Loop in '{self.current_async_func}'",
                        description=(
                            f"Synchronous network call '{func_name}' inside coroutine '{self.current_async_func}' "
                            "blocks the main asyncio event loop, causing concurrency latency spikes and request starvation."
                        ),
                        file_path=rel_path,
                        line_number=line_num,
                        snippet=snippet[:120],
                        remediation_advice="Replace synchronous requests with an asynchronous client (e.g. 'httpx.AsyncClient') or wrap in 'asyncio.to_thread()'.",
                        auto_fixable=False
                    ))

                self.generic_visit(node)

        visitor = SecurityVisitor()
        visitor.visit(tree)
        return findings

    def _scan_frontend_file(self, file_path: str, rel_path: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return findings

        # DOM XSS pattern: assigning template string with variables directly into .innerHTML without escapeHtml
        dom_xss_regex = re.compile(r"""\.innerHTML\s*=\s*[`'"].*?\$\{([^}]+)\}.*?[`'"]""")
        localstorage_token_regex = re.compile(r"""localStorage\.setItem\s*\(\s*['"][^'"]*(?:token|secret|password|pat|credential)[^'"]*['"]""", re.IGNORECASE)

        for line_idx, line in enumerate(lines, 1):
            clean_line = line.strip()
            if not clean_line or clean_line.startswith("//") or clean_line.startswith("<!--"):
                continue

            # DOM XSS Detection
            match = dom_xss_regex.search(clean_line)
            if match:
                interpolated_expr = match.group(1).strip()
                # If expression is not wrapped in escapeHtml or encodeURIComponent, flag as DOM XSS risk
                if not any(sanitizer in interpolated_expr for sanitizer in ("escapeHtml", "encodeURIComponent", "textContent", "innerText")):
                    findings.append(Finding(
                        id=str(uuid.uuid4()),
                        category=FindingCategory.SAST_VULNERABILITY,
                        severity=SeverityLevel.HIGH,
                        title="DOM-based Cross-Site Scripting (XSS) via Unescaped innerHTML",
                        description=(
                            f"Unsanitized dynamic expression '${{{interpolated_expr}}}' is written directly to '.innerHTML'. "
                            "If this value contains untrusted input or API error responses, arbitrary JavaScript can execute in the browser."
                        ),
                        file_path=rel_path,
                        line_number=line_idx,
                        snippet=clean_line[:120],
                        remediation_advice="Sanitize interpolated HTML using 'escapeHtml(expr)' or populate via 'element.textContent = expr'.",
                        auto_fixable=False
                    ))

            # Persistent sensitive token in localStorage
            if localstorage_token_regex.search(clean_line):
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    category=FindingCategory.SAST_VULNERABILITY,
                    severity=SeverityLevel.HIGH,
                    title="Insecure Credential Persistence in Browser localStorage",
                    description=(
                        "Sensitive authorization token or credential stored in 'localStorage'. "
                        "Data stored in localStorage persists indefinitely across browser tabs and sessions, making it vulnerable to exfiltration by XSS."
                    ),
                    file_path=rel_path,
                    line_number=line_idx,
                    snippet=clean_line[:120],
                    remediation_advice="Use 'sessionStorage' or keep credentials in memory with explicit user warnings.",
                    auto_fixable=False
                ))

        return findings

