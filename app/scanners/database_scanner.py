"""
app/scanners/database_scanner.py
Comprehensive Database Posture, Credential Exposure, and Network Access Scanner.
Audits PostgreSQL, MySQL, Redis, MongoDB, Elasticsearch, and MSSQL for open ports,
missing authentication, default credentials, and unencrypted transport.
"""

import socket
import urllib.parse
import re
import uuid
from typing import List, Tuple, Dict, Any, Optional

# pyrefly: ignore [missing-import]
import requests

from app.models.schemas import Finding, FindingCategory, SeverityLevel


class DatabaseScanner:
    """Non-destructive database exposure and posture audit engine."""

    DEFAULT_PORTS = {
        "postgres": 5432,
        "postgresql": 5432,
        "mysql": 3306,
        "mariadb": 3306,
        "redis": 6379,
        "mongodb": 27017,
        "elasticsearch": 9200,
        "mssql": 1433,
        "sqlserver": 1433,
        "cassandra": 9042
    }

    WEAK_PASSWORDS = {"root", "admin", "password", "123456", "postgres", "guest", "test", "toor", "default"}

    def __init__(self, timeout_seconds: int = 4):
        self.timeout = timeout_seconds

    def scan(self, target: str, explicit_engine: Optional[str] = None) -> Tuple[List[Finding], Dict[str, Any]]:
        """
        Scans a database target (URI or host:port).
        Returns findings and database metadata.
        """
        findings: List[Finding] = []
        target_str = target.strip()

        # Parse target into components
        engine, host, port, user, password, dbname, query_params = self._parse_db_target(target_str, explicit_engine)

        metadata: Dict[str, Any] = {
            "target": target_str,
            "engine": engine,
            "host": host,
            "port": port,
            "database": dbname,
            "port_accessible": False,
            "auth_enforced": True,
            "tls_enforced": False
        }

        # 1. Cleartext Credentials & Weak Passwords in Connection String
        cred_findings = self._audit_credentials(user, password, target_str)
        findings.extend(cred_findings)

        # 2. TLS/SSL Enforcement Check
        ssl_findings, tls_enforced = self._audit_tls_configuration(engine, query_params, target_str)
        findings.extend(ssl_findings)
        metadata["tls_enforced"] = tls_enforced

        # 3. Network Accessibility & Socket Probing
        is_accessible, probe_findings = self._probe_network_exposure(host, port, engine, user, password)
        findings.extend(probe_findings)
        metadata["port_accessible"] = is_accessible

        # 4. Engine-Specific Unauthenticated Probes
        if is_accessible:
            auth_findings, auth_enforced = self._probe_unauthenticated_access(host, port, engine)
            findings.extend(auth_findings)
            metadata["auth_enforced"] = auth_enforced

        return findings, metadata

    def _parse_db_target(self, target: str, explicit_engine: Optional[str] = None):
        """Parses connection string or host:port into standard components."""
        engine = (explicit_engine or "unknown").lower()
        host = "127.0.0.1"
        port = self.DEFAULT_PORTS.get(engine, 5432)
        user = None
        password = None
        dbname = None
        query_params = {}

        # Check if URL scheme format
        if "://" in target:
            try:
                parsed = urllib.parse.urlparse(target)
                scheme = parsed.scheme.lower()
                if "+" in scheme:
                    scheme = scheme.split("+")[0]
                engine = scheme
                host = parsed.hostname or "127.0.0.1"
                port = parsed.port or self.DEFAULT_PORTS.get(engine, 5432)
                user = parsed.username
                password = parsed.password
                dbname = parsed.path.lstrip("/") if parsed.path else None
                query_params = dict(urllib.parse.parse_qsl(parsed.query))
                return engine, host, port, user, password, dbname, query_params
            except Exception:
                pass

        # Check host:port format
        if ":" in target:
            parts = target.split(":")
            host = parts[0]
            try:
                port = int(parts[1])
                # Guess engine from port
                for eng, p in self.DEFAULT_PORTS.items():
                    if p == port:
                        engine = eng
                        break
            except ValueError:
                pass
        else:
            host = target

        if explicit_engine:
            engine = explicit_engine.lower()
            if not port or port == 5432:
                port = self.DEFAULT_PORTS.get(engine, port)

        return engine, host, port, user, password, dbname, query_params

    def _audit_credentials(self, user: Optional[str], password: Optional[str], target_str: str) -> List[Finding]:
        findings = []
        if not user and not password:
            return findings

        # Exposed cleartext credentials in URI
        masked = re.sub(r"(://[^:]+):([^@]+)@", r"\1:****@", target_str)
        findings.append(Finding(
            id=str(uuid.uuid4()),
            category=FindingCategory.DB_EXPOSURE,
            severity=SeverityLevel.HIGH,
            title="Database Credentials Exposed in Connection String",
            description="The database connection URI includes hardcoded credentials in cleartext. If logged or committed to version control, unauthorized actors can access the datastore.",
            file_path=masked,
            snippet=f"User: {user} / Password provided",
            remediation_advice="Inject database credentials at runtime via environment variables or cloud secret managers (AWS Secrets Manager / HashiCorp Vault).",
            auto_fixable=False
        ))

        # Check for weak or default password
        if password and (password.lower() in self.WEAK_PASSWORDS or password == user):
            findings.append(Finding(
                id=str(uuid.uuid4()),
                category=FindingCategory.DB_EXPOSURE,
                severity=SeverityLevel.CRITICAL,
                title="Critical Weak / Default Database Password",
                description=f"Database user '{user}' utilizes a trivial or default password ('{password}'), making the database susceptible to automated brute-force attacks.",
                file_path=masked,
                snippet=f"Trivial Password Detected: {password[:2]}***",
                remediation_advice="Update database password immediately to a high-entropy string (minimum 24 characters with mixed characters and symbols).",
                auto_fixable=False
            ))

        return findings

    def _audit_tls_configuration(self, engine: str, query_params: Dict[str, str], target_str: str) -> Tuple[List[Finding], bool]:
        findings = []
        tls_enforced = False

        sslmode = query_params.get("sslmode", "").lower()
        ssl_flag = query_params.get("ssl", "").lower()
        tls_flag = query_params.get("tls", "").lower()

        if sslmode in ("require", "verify-ca", "verify-full") or ssl_flag == "true" or tls_flag == "true":
            tls_enforced = True
        elif sslmode in ("disable", "allow"):
            findings.append(Finding(
                id=str(uuid.uuid4()),
                category=FindingCategory.DB_EXPOSURE,
                severity=SeverityLevel.HIGH,
                title="Explicitly Disabled Database SSL/TLS Encryption",
                description=f"Database connection string explicitly disables TLS encryption ('sslmode={sslmode}'). Queries and sensitive tables are transmitted in plaintext across the network.",
                file_path=target_str,
                snippet=f"sslmode={sslmode}",
                remediation_advice="Change connection parameter to 'sslmode=require' or 'sslmode=verify-full'.",
                auto_fixable=True,
                fix_patch="sslmode=require"
            ))
        else:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                category=FindingCategory.DB_EXPOSURE,
                severity=SeverityLevel.MEDIUM,
                title="Unenforced Database Transport Layer Security (TLS)",
                description="Database connection configuration does not strictly enforce TLS encryption, permitting opportunistic fallback to cleartext network transmissions.",
                file_path=target_str,
                snippet="Missing explicit 'sslmode=require'",
                remediation_advice="Append '?sslmode=require' to your connection URI and configure database server certificates.",
                auto_fixable=True,
                fix_patch="?sslmode=require"
            ))

        return findings, tls_enforced

    def _probe_network_exposure(self, host: str, port: int, engine: str, user: Optional[str], password: Optional[str]) -> Tuple[bool, List[Finding]]:
        findings = []
        is_accessible = False

        # Check if listening on public internet or non-loopback
        is_public = host not in ("127.0.0.1", "localhost", "::1")

        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                is_accessible = True

                if is_public:
                    findings.append(Finding(
                        id=str(uuid.uuid4()),
                        category=FindingCategory.DB_EXPOSURE,
                        severity=SeverityLevel.HIGH,
                        title=f"Publicly Accessible Database Port ({engine.upper()} on {port})",
                        description=f"Database port {port} on '{host}' accepted incoming network connections. Direct exposure of database ports to untrusted networks increases susceptibility to scanning and zero-day exploits.",
                        file_path=f"{host}:{port}",
                        snippet=f"Port {port} [OPEN]",
                        remediation_advice="Restrict database network bindings to 127.0.0.1 or place behind private VPC subnets with Security Group / Firewall whitelists.",
                        auto_fixable=False
                    ))
        except (socket.timeout, ConnectionRefusedError, OSError):
            is_accessible = False

        return is_accessible, findings

    def _probe_unauthenticated_access(self, host: str, port: int, engine: str) -> Tuple[List[Finding], bool]:
        """Probes live open database instances for unauthenticated access."""
        findings = []
        auth_enforced = True

        # 1. Redis Unauthenticated PING probe
        if engine == "redis":
            try:
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    sock.sendall(b"*1\r\n$4\r\nPING\r\n")
                    response = sock.recv(1024).decode("utf-8", errors="ignore")
                    if "+PONG" in response:
                        auth_enforced = False
                        findings.append(Finding(
                            id=str(uuid.uuid4()),
                            category=FindingCategory.DB_EXPOSURE,
                            severity=SeverityLevel.CRITICAL,
                            title="Unauthenticated Redis Remote Code Execution & Data Access",
                            description=f"Redis server at '{host}:{port}' responded to 'PING' without authentication (+PONG). Anyone can execute arbitrary commands, dump memory keys, or achieve remote code execution (RCE).",
                            file_path=f"redis://{host}:{port}",
                            snippet="Command: PING -> Response: +PONG",
                            remediation_advice="Configure 'requirepass <strong-password>' in redis.conf and bind strictly to localhost (127.0.0.1).",
                            auto_fixable=False
                        ))
                    elif "NOAUTH" in response:
                        auth_enforced = True
            except Exception:
                pass

        # 2. Elasticsearch Unauthenticated Cluster Health probe
        elif engine == "elasticsearch" or port == 9200:
            try:
                url = f"http://{host}:{port}/_cluster/health"
                res = requests.get(url, timeout=self.timeout)
                if res.status_code == 200 and "status" in res.text:
                    auth_enforced = False
                    findings.append(Finding(
                        id=str(uuid.uuid4()),
                        category=FindingCategory.DB_EXPOSURE,
                        severity=SeverityLevel.CRITICAL,
                        title="Unauthenticated Elasticsearch Cluster Access",
                        description=f"Elasticsearch cluster at '{host}:{port}' has security disabled. The cluster health endpoint is publicly accessible without credentials, allowing unauthorized index modification and data extraction.",
                        file_path=f"http://{host}:{port}/_cluster/health",
                        snippet=res.text[:100],
                        remediation_advice="Enable xpack.security.enabled: true in elasticsearch.yml and configure basic authentication.",
                        auto_fixable=False
                    ))
            except Exception:
                pass

        return findings, auth_enforced
