"""
app/scanners/web_scanner.py
Comprehensive Live Web Application, SSL/TLS, and API Exposure Scanner.
Audits TLS certificates, missing security headers, information disclosures, CORS, and sensitive endpoints.
"""

import ssl
import socket
import urllib.parse
from datetime import datetime
import uuid
from typing import List, Tuple, Dict, Any, Optional

# pyrefly: ignore [missing-import]
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from app.models.schemas import Finding, FindingCategory, SeverityLevel


class WebsiteScanner:
    """Non-destructive live web application & API security scanner."""

    def __init__(self, timeout_seconds: int = 8):
        self.timeout = timeout_seconds
        self.headers = {
            "User-Agent": "ShieldCI-Auditor/1.0 (DevSecOps CI/CD Exposure Manager; Security Audit Engine)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

    def scan(self, target_url: str) -> Tuple[List[Finding], Dict[str, Any]]:
        """
        Executes web security exposure scan on target URL.
        Returns list of findings and metadata dictionary.
        """
        findings: List[Finding] = []
        metadata: Dict[str, Any] = {
            "url": target_url,
            "status_code": None,
            "response_time_ms": None,
            "ssl": None,
            "server": None,
            "detected_technologies": []
        }

        # Normalize URL
        url = target_url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or url
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        is_https = parsed.scheme == "https"

        # 1. SSL/TLS Certificate Audit
        if is_https:
            ssl_findings, ssl_info = self._audit_ssl(hostname, port)
            findings.extend(ssl_findings)
            metadata["ssl"] = ssl_info
        else:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                category=FindingCategory.WEB_EXPOSURE,
                severity=SeverityLevel.HIGH,
                title="Insecure Plaintext HTTP Transport (No TLS)",
                description=f"The website '{url}' serves traffic over unencrypted HTTP. Attackers can eavesdrop, intercept credentials, or tamper with communications via Man-In-The-Middle (MITM) attacks.",
                file_path=url,
                remediation_advice="Enforce HTTPS with a valid TLS certificate and implement an automatic 301 redirect from HTTP to HTTPS.",
                auto_fixable=False
            ))

        # 2. HTTP Request & Headers Audit
        try:
            start_req = datetime.utcnow()
            resp = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=True)
            latency_ms = int((datetime.utcnow() - start_req).total_seconds() * 1000)

            metadata["status_code"] = resp.status_code
            metadata["response_time_ms"] = latency_ms
            metadata["server"] = resp.headers.get("Server")

            header_findings = self._audit_headers(resp.headers, url, is_https)
            findings.extend(header_findings)

            # 3. Information Disclosure & Fingerprint
            fingerprint_findings = self._audit_fingerprint(resp.headers, url)
            findings.extend(fingerprint_findings)

            # 4. Sensitive Path Probes
            path_findings = self._probe_sensitive_paths(url)
            findings.extend(path_findings)

        except requests.exceptions.RequestException as e:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                category=FindingCategory.WEB_EXPOSURE,
                severity=SeverityLevel.MEDIUM,
                title="Web Application Reachability / Gateway Warning",
                description=f"Failed to complete HTTP request to '{url}': {str(e)[:150]}",
                file_path=url,
                remediation_advice="Verify that the website domain resolves and is accepting public traffic.",
                auto_fixable=False
            ))

        return findings, metadata

    def _audit_ssl(self, hostname: str, port: int) -> Tuple[List[Finding], Dict[str, Any]]:
        findings = []
        ssl_info: Dict[str, Any] = {"valid": False}

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    protocol_version = ssock.version()
                    cipher = ssock.cipher()

                    ssl_info["protocol"] = protocol_version
                    ssl_info["cipher"] = cipher[0] if cipher else "Unknown"

                    # If binary cert inspection is needed when CERT_NONE
                    der_cert = ssock.getpeercert(binary_form=True)

            # Detailed cert inspection using standard verification
            verify_ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with verify_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    full_cert = ssock.getpeercert()
                    if full_cert:
                        ssl_info["valid"] = True
                        ssl_info["subject"] = dict(x[0] for x in full_cert.get("subject", []))
                        ssl_info["issuer"] = dict(x[0] for x in full_cert.get("issuer", []))
                        
                        # Expiration check
                        expire_str = full_cert.get("notAfter")
                        if expire_str:
                            expire_dt = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                            days_remaining = (expire_dt - datetime.utcnow()).days
                            ssl_info["days_remaining"] = days_remaining
                            ssl_info["expires"] = expire_dt.strftime("%Y-%m-%d")

                            if days_remaining < 0:
                                findings.append(Finding(
                                    id=str(uuid.uuid4()),
                                    category=FindingCategory.WEB_EXPOSURE,
                                    severity=SeverityLevel.CRITICAL,
                                    title="Expired SSL/TLS Certificate",
                                    description=f"The SSL certificate for '{hostname}' expired {abs(days_remaining)} days ago on {expire_dt.strftime('%Y-%m-%d')}.",
                                    file_path=hostname,
                                    remediation_advice="Renew the SSL/TLS certificate immediately via Let's Encrypt / Certbot or your Certificate Authority.",
                                    auto_fixable=False
                                ))
                            elif days_remaining <= 14:
                                findings.append(Finding(
                                    id=str(uuid.uuid4()),
                                    category=FindingCategory.WEB_EXPOSURE,
                                    severity=SeverityLevel.HIGH,
                                    title="SSL/TLS Certificate Expiring Imminently",
                                    description=f"The SSL certificate for '{hostname}' will expire in {days_remaining} days ({expire_dt.strftime('%Y-%m-%d')}).",
                                    file_path=hostname,
                                    remediation_advice="Renew certificate now to prevent automated service outage and browser security warnings.",
                                    auto_fixable=False
                                ))

            # Deprecated TLS protocols
            if protocol_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    category=FindingCategory.WEB_EXPOSURE,
                    severity=SeverityLevel.HIGH,
                    title=f"Deprecated TLS Protocol Negotiated ({protocol_version})",
                    description=f"Server negotiated connection using {protocol_version}, which suffers from known cryptographic flaws (POODLE, BEAST).",
                    file_path=hostname,
                    remediation_advice="Disable TLS 1.0/1.1 in web server or load balancer settings; require TLS 1.2 or TLS 1.3 only.",
                    auto_fixable=False
                ))

        except ssl.SSLCertVerificationError as e:
            ssl_info["error"] = str(e)
            findings.append(Finding(
                id=str(uuid.uuid4()),
                category=FindingCategory.WEB_EXPOSURE,
                severity=SeverityLevel.HIGH,
                title="Untrusted or Invalid SSL/TLS Certificate",
                description=f"SSL certificate verification failed for '{hostname}': {str(e)}",
                file_path=hostname,
                remediation_advice="Install a certificate issued by a trusted public Certificate Authority (CA) and verify intermediate certificate chain.",
                auto_fixable=False
            ))
        except Exception as e:
            ssl_info["error"] = str(e)

        return findings, ssl_info

    def _audit_headers(self, headers: Any, url: str, is_https: bool) -> List[Finding]:
        findings = []

        # 1. HSTS (Strict-Transport-Security)
        if is_https:
            hsts = headers.get("Strict-Transport-Security")
            if not hsts:
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    category=FindingCategory.WEB_EXPOSURE,
                    severity=SeverityLevel.HIGH,
                    title="Missing Strict-Transport-Security (HSTS) Header",
                    description="The server does not enforce HTTPS connections via HSTS. Users can be downgraded to plaintext HTTP via SSL stripping attacks.",
                    file_path=url,
                    snippet="Missing: Strict-Transport-Security",
                    remediation_advice="Add header: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'",
                    auto_fixable=True,
                    fix_patch="Strict-Transport-Security: max-age=31536000; includeSubDomains"
                ))

        # 2. Content-Security-Policy (CSP)
        csp = headers.get("Content-Security-Policy")
        if not csp:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                category=FindingCategory.WEB_EXPOSURE,
                severity=SeverityLevel.HIGH,
                title="Missing Content-Security-Policy (CSP) Header",
                description="No Content-Security-Policy header is configured, leaving users vulnerable to Cross-Site Scripting (XSS) and data injection attacks.",
                file_path=url,
                snippet="Missing: Content-Security-Policy",
                remediation_advice="Implement a strict CSP restricting script-src, object-src, and frame-ancestors.",
                auto_fixable=False
            ))
        elif "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                category=FindingCategory.WEB_EXPOSURE,
                severity=SeverityLevel.MEDIUM,
                title="Overly Permissive Content-Security-Policy (unsafe-inline/eval)",
                description="CSP allows 'unsafe-inline' or 'unsafe-eval' script execution, significantly diminishing protection against XSS payloads.",
                file_path=url,
                snippet=csp[:120],
                remediation_advice="Refactor inline scripts to external bundles or adopt cryptographic nonces / hashes in CSP.",
                auto_fixable=False
            ))

        # 3. X-Frame-Options (Clickjacking defense)
        xfo = headers.get("X-Frame-Options")
        if not xfo and (not csp or "frame-ancestors" not in csp):
            findings.append(Finding(
                id=str(uuid.uuid4()),
                category=FindingCategory.WEB_EXPOSURE,
                severity=SeverityLevel.MEDIUM,
                title="Missing Anti-Clickjacking Header (X-Frame-Options)",
                description="The page does not specify X-Frame-Options or CSP frame-ancestors, allowing malicious third-party sites to embed it inside an iframe for Clickjacking attacks.",
                file_path=url,
                snippet="Missing: X-Frame-Options",
                remediation_advice="Set header 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'.",
                auto_fixable=True,
                fix_patch="X-Frame-Options: SAMEORIGIN"
            ))

        # 4. X-Content-Type-Options (MIME-sniffing)
        xcto = headers.get("X-Content-Type-Options")
        if not xcto or xcto.lower() != "nosniff":
            findings.append(Finding(
                id=str(uuid.uuid4()),
                category=FindingCategory.WEB_EXPOSURE,
                severity=SeverityLevel.LOW,
                title="Missing MIME-Type Sniffing Protection (X-Content-Type-Options)",
                description="Without 'X-Content-Type-Options: nosniff', older browsers may treat non-executable MIME types as executable HTML/JS, creating XSS vectors.",
                file_path=url,
                snippet=f"Current: {xcto or 'None'}",
                remediation_advice="Set header 'X-Content-Type-Options: nosniff'.",
                auto_fixable=True,
                fix_patch="X-Content-Type-Options: nosniff"
            ))

        # 5. Referrer-Policy
        ref_pol = headers.get("Referrer-Policy")
        if not ref_pol:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                category=FindingCategory.WEB_EXPOSURE,
                severity=SeverityLevel.LOW,
                title="Missing Referrer-Policy Header",
                description="No Referrer-Policy is specified, potentially leaking sensitive query parameters or internal URLs in HTTP Referer headers to external links.",
                file_path=url,
                snippet="Missing: Referrer-Policy",
                remediation_advice="Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
                auto_fixable=True,
                fix_patch="Referrer-Policy: strict-origin-when-cross-origin"
            ))

        # 6. CORS Wildcard Check
        cors_origin = headers.get("Access-Control-Allow-Origin")
        cors_cred = headers.get("Access-Control-Allow-Credentials")
        if cors_origin == "*" and cors_cred and cors_cred.lower() == "true":
            findings.append(Finding(
                id=str(uuid.uuid4()),
                category=FindingCategory.WEB_EXPOSURE,
                severity=SeverityLevel.HIGH,
                title="Dangerous CORS Misconfiguration: Wildcard with Credentials",
                description="Server allows wildcard '*' origin while supporting Access-Control-Allow-Credentials, enabling cross-origin authenticated data theft.",
                file_path=url,
                snippet="Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true",
                remediation_advice="Explicitly whitelist trusted origins instead of wildcard '*' when credentials are required.",
                auto_fixable=False
            ))

        return findings

    def _audit_fingerprint(self, headers: Any, url: str) -> List[Finding]:
        findings = []

        server = headers.get("Server", "")
        if server and any(char.isdigit() for char in server):
            findings.append(Finding(
                id=str(uuid.uuid4()),
                category=FindingCategory.WEB_EXPOSURE,
                severity=SeverityLevel.LOW,
                title=f"Web Server Version Disclosure ({server})",
                description=f"The server exposes granular version information in the 'Server' header ('{server}'), aiding adversaries in pinpointing version-specific CVEs.",
                file_path=url,
                snippet=f"Server: {server}",
                remediation_advice="Configure web server to suppress banner versions (e.g. 'ServerTokens Prod' in Apache, 'server_tokens off;' in Nginx).",
                auto_fixable=False
            ))

        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                category=FindingCategory.WEB_EXPOSURE,
                severity=SeverityLevel.LOW,
                title=f"Backend Technology Disclosure ({powered_by})",
                description=f"The 'X-Powered-By' header exposes backend runtime framework details: '{powered_by}'.",
                file_path=url,
                snippet=f"X-Powered-By: {powered_by}",
                remediation_advice="Disable 'X-Powered-By' in your application framework settings.",
                auto_fixable=False
            ))

        return findings

    def _probe_sensitive_paths(self, base_url: str) -> List[Finding]:
        """Probes common hazardous debug / secret paths non-intrusively."""
        findings = []
        base = base_url.rstrip("/")

        probe_targets = [
            ("/.env", SeverityLevel.CRITICAL, "Publicly Exposed Environment Configuration (.env)", "A publicly accessible .env file was discovered. Attackers can extract API keys, database credentials, and secret tokens directly."),
            ("/.git/HEAD", SeverityLevel.CRITICAL, "Exposed Git Source Repository Metadata (.git/HEAD)", "The .git directory is accessible over HTTP. Attackers can dump full project source code, history, and internal commits."),
            ("/actuator/health", SeverityLevel.MEDIUM, "Exposed Spring Boot Actuator Endpoint", "Spring Boot Actuator endpoint is exposed publicly without authentication."),
            ("/actuator/env", SeverityLevel.CRITICAL, "Exposed Spring Boot Actuator Environment (/actuator/env)", "Spring Boot environment properties are exposed, allowing extraction of active environment variables and credentials.")
        ]

        for path, sev, title, desc in probe_targets:
            probe_url = f"{base}{path}"
            try:
                res = requests.get(probe_url, headers=self.headers, timeout=4, verify=False, allow_redirects=False)
                if res.status_code == 200:
                    text_sample = res.text[:120] if res.text else ""
                    # Validate content matches actual expected leak rather than a custom 404 page
                    is_valid_leak = False
                    if path == "/.env" and ("=" in text_sample or "APP_" in text_sample or "DB_" in text_sample or "KEY" in text_sample):
                        is_valid_leak = True
                    elif path == "/.git/HEAD" and ("ref:" in text_sample):
                        is_valid_leak = True
                    elif "actuator" in path and ("status" in text_sample.lower() or "profiles" in text_sample.lower()):
                        is_valid_leak = True

                    if is_valid_leak:
                        findings.append(Finding(
                            id=str(uuid.uuid4()),
                            category=FindingCategory.WEB_EXPOSURE,
                            severity=sev,
                            title=title,
                            description=desc,
                            file_path=probe_url,
                            snippet=text_sample,
                            remediation_advice=f"Block public HTTP access to '{path}' at web server / reverse proxy layer.",
                            auto_fixable=False
                        ))
            except Exception:
                pass

        return findings
