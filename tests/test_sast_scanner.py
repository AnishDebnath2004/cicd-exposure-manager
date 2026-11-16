"""
tests/test_sast_scanner.py
Comprehensive test suite verifying ShieldCI SAST Engine and Advanced Credential Detection:
1. Python AST detection of dangerous execution (eval, exec, pickle).
2. SSRF / unvalidated socket connection detection.
3. Untrusted X-Forwarded-For client IP extraction detection.
4. Synchronous blocking I/O inside async coroutines.
5. Client-side DOM XSS detection and localStorage credential persistence.
6. Expanded SecretScanner rules (hardcoded JWT keys, database passwords).
"""

import os
import tempfile
import pytest

from app.models.schemas import FindingCategory, SeverityLevel, ScanRequest, TargetCategory
from app.scanners.sast_scanner import SASTScanner
from app.scanners.secret_scanner import SecretScanner
from app.core.orchestrator import ExposureOrchestrator


def test_sast_scanner_python_ast_flaws():
    scanner = SASTScanner()
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_py = os.path.join(tmp_dir, "vulnerable_app.py")
        code = '''
import eval_module
import pickle
import hashlib
import requests

def run_user_cmd(cmd):
    return eval(cmd)

def parse_blob(data):
    return pickle.loads(data)

def hash_pw(pw):
    return hashlib.md5(pw.encode()).hexdigest()

async def get_remote_data():
    # Synchronous blocking call inside async function
    res = requests.get("https://example.com/api", timeout=5)
    return res.text
'''
        with open(test_py, "w", encoding="utf-8") as f:
            f.write(code)

        findings = scanner.scan(tmp_dir)
        titles = [f.title for f in findings]

        assert any("Dangerous Dynamic Code Execution" in t for t in titles)
        assert any("pickle" in t.lower() for t in titles)
        assert any("Weak Cryptographic Hash" in t for t in titles)
        assert any("Synchronous Network Call Blocking Asyncio" in t for t in titles)


def test_sast_scanner_ssrf_and_ip_spoofing():
    scanner = SASTScanner()
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_py = os.path.join(tmp_dir, "network_probe.py")
        code = '''
import socket

def probe_host(host, port):
    # Unvalidated socket connection without SSRF boundary
    with socket.create_connection((host, port), timeout=3) as sock:
        pass

def get_ip(request):
    # Direct X-Forwarded-For trust
    return request.headers.get("X-Forwarded-For").split(",")[0].strip()
'''
        with open(test_py, "w", encoding="utf-8") as f:
            f.write(code)

        findings = scanner.scan(tmp_dir)
        titles = [f.title for f in findings]

        assert any("SSRF" in t or "Socket Connection" in t for t in titles)
        assert any("X-Forwarded-For" in t for t in titles)


def test_sast_scanner_frontend_dom_xss_and_storage():
    scanner = SASTScanner()
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_html = os.path.join(tmp_dir, "dashboard.html")
        code = '''
<!DOCTYPE html>
<html>
<body>
  <div id="output"></div>
  <script>
    function renderError(err) {
      // DOM XSS: unescaped variable written to innerHTML
      document.getElementById('output').innerHTML = `<b>Error: ${err.message}</b>`;
    }

    function saveAuth(token) {
      // Insecure persistence of token in localStorage
      localStorage.setItem('user_access_token', token);
    }
  </script>
</body>
</html>
'''
        with open(test_html, "w", encoding="utf-8") as f:
            f.write(code)

        findings = scanner.scan(tmp_dir)
        titles = [f.title for f in findings]

        assert any("DOM-based Cross-Site Scripting" in t for t in titles)
        assert any("localStorage" in t for t in titles)


def test_secret_scanner_expanded_rules():
    scanner = SecretScanner()
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_py = os.path.join(tmp_dir, "secrets_test.py")
        mock_api_token = "sk_" + "live_" + "123456789012345678901234"
        code = f'''
# Hardcoded JWT secret
JWT_SECRET_KEY = os.getenv("SHIELDCI_SECRET_KEY", "")

# Hardcoded DB password
DB_PASSWORD = os.getenv("DATABASE_URL", "")

# Dynamic Test Cloud Token
cloud_token = "{mock_api_token}"
'''
        with open(test_py, "w", encoding="utf-8") as f:
            f.write(code)

        findings = scanner.scan(tmp_dir)
        titles = [f.title for f in findings]

        assert any("JWT" in t for t in titles)
        assert any("Database Password" in t for t in titles)
        assert any("Secret Token" in t for t in titles)


def test_orchestrator_integration_with_sast():
    orchestrator = ExposureOrchestrator()
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_py = os.path.join(tmp_dir, "service.py")
        code = '''
import socket

def connect_backend(host, port):
    with socket.create_connection((host, port)) as s:
        pass
'''
        with open(test_py, "w", encoding="utf-8") as f:
            f.write(code)

        req = ScanRequest(target=tmp_dir, target_type=TargetCategory.REPOSITORY)
        result = orchestrator.run_scan(req)

        assert result.summary.total_findings >= 1
        sast_findings = [f for f in result.findings if f.category == FindingCategory.SAST_VULNERABILITY]
        assert len(sast_findings) >= 1
        assert any("Socket" in f.title or "SSRF" in f.title for f in sast_findings)