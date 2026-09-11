# ShieldCI: DevSecOps CI/CD Exposure Manager

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.14-blue?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-0.110.0+-009688?logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/Architecture-Tri--Vector%20Posture-6366f1" alt="Architecture">
  <img src="https://img.shields.io/badge/Database-PostgreSQL%20%7C%20SQLite-336791?logo=postgresql&logoColor=white" alt="Database">
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/Tests-36%20Passed-success" alt="Tests">
  <img src="https://img.shields.io/badge/License-Apache%202.0-green" alt="License">
</p>

**ShieldCI** is an enterprise-grade **Universal Tri-Vector Posture Management & Pipeline Exposure Defense Platform**. It combines static codebase auditing, continuous CI/CD pipeline verification, live web perimeter analysis, and database exposure detection into a unified, actionable risk intelligence system.

Rather than treating vulnerabilities in isolation, ShieldCI automatically **triangulates infrastructure footprints**, correlates multi-stage exploit chains into **Toxic Combinations**, generates interactive **Visual Attack Graphs**, calculates a normalized **Pipeline Exposure Score (PES)**, and outputs **1-Click Self-Healing Git Patches** (`git apply`) to instantly remediate exposures.

---

## Table of Contents

- [Key Pillars & Differentiators](#key-pillars--differentiators)
- [System Architecture](#system-architecture)
- [Tri-Vector Posture Coverage](#tri-vector-posture-coverage)
- [Quickstart Guide](#quickstart-guide)
  - [Prerequisites](#prerequisites)
  - [Local Installation](#local-installation)
  - [Environment Configuration](#environment-configuration)
  - [Launching the Dashboard & API](#launching-the-dashboard--api)
  - [Running with Docker](#running-with-docker)
- [CLI Auditor & CI/CD Quality Gates](#cli-auditor--cicd-quality-gates)
  - [Command Usage](#command-usage)
  - [GitHub Actions Integration](#github-actions-integration)
  - [GitLab CI Integration](#gitlab-ci-integration)
- [Autonomous Remediation & Self-Healing Patches](#autonomous-remediation--self-healing-patches)
- [Exposure Scoring (PES) & Risk Grades](#exposure-scoring-pes--risk-grades)
- [REST API Summary](#rest-api-summary)
- [Documentation Index](#documentation-index)
- [Testing & Quality Assurance](#testing--quality-assurance)
- [Contributing & License](#contributing--license)

---

## Key Pillars & Differentiators

```
                       ┌─────────────────────────────────────────────────────────┐
                       │                     SHIELDCI ENGINE                     │
                       └────────────────────────────┬────────────────────────────┘
                                                    │
        ┌───────────────────────────────────────────┼───────────────────────────────────────────┐
        │                                           │                                           │
        ▼                                           ▼                                           ▼
 ┌──────────────┐                            ┌──────────────┐                            ┌──────────────┐
 │   VECTOR 1   │                            │   VECTOR 2   │                            │   VECTOR 3   │
 │   Codebase   │                            │  Web Perimeter│                           │   Database   │
 │   & CI/CD    │                            │    & APIs    │                            │ & Datastores │
 └──────┬───────┘                            └──────┬───────┘                            └──────┬───────┘
        │                                           │                                           │
        └───────────────────────────────────────────┼───────────────────────────────────────────┘
                                                    │
                                                    ▼
                                    ┌───────────────────────────────┐
                                    │  Auto-Discovery Triangulation │
                                    └───────────────┬───────────────┘
                                                    │
                                                    ▼
                                    ┌───────────────────────────────┐
                                    │ Attack Correlation & Toxics   │
                                    └───────────────┬───────────────┘
                                                    │
                                                    ▼
                                    ┌───────────────────────────────┐
                                    │    Interactive Attack Graph   │
                                    └───────────────┬───────────────┘
                                                    │
                                                    ▼
                                    ┌───────────────────────────────┐
                                    │  1-Click Autonomous Patching  │
                                    └───────────────────────────────┘
```

1. **Tri-Vector Attack Surface Visibility**: Single pane of glass auditing across source code repositories, live web services/APIs, and exposed databases.
2. **Automated Footprint Triangulation**: Parses Docker Compose, `.env` configurations, GitHub Actions workflows, and package manifests to automatically discover and map live web targets and database endpoints.
3. **Attack Path Correlation & Toxic Combinations**: Connects disparate low/medium findings into weaponizable exploit chains (e.g., an unpinned GitHub Actions trigger + an exposed database credential + an open database port).
4. **Autonomous Remediation Engine**: Synthesizes standard unified diff patches (`.patch`) for vulnerable Dockerfiles, CI/CD pipelines, and Python requirements, consumable via standard `git apply`.
5. **Standardized Exposure Scoring (PES / AES)**: Computes a standardized 0–100 risk score and categorical letter grade (`A+` to `F`) with customizable severity weights.
6. **Continuous Background Scheduling**: Built-in background worker periodically polls targets without requiring external cron daemons.
7. **SSRF-Hardened Outbound Alerts**: Dispatches real-time webhooks (Slack, Discord, internal webhooks) protected by strict DNS and private-range SSRF filters.
8. **Multi-Tenant RBAC & Session Security**: Role-based access control (`Admin`, `Developer`, `User`), instant session revocation via `token_version`, and guest rate limiting (5 scans/day per IP).
9. **Dual-Engine Storage Layer**: Auto-detects serverless PostgreSQL (Neon, Supabase, Render, AWS RDS) with connection pooling, gracefully falling back to local SQLite.

---

## System Architecture

ShieldCI is designed with a decoupled, modular architecture orchestrated by the `ExposureOrchestrator`:

- **FastAPI Core (`app/main.py`)**: Asynchronous REST API serving webhooks, scan triggers, user authentication, and the responsive single-page dashboard.
- **Exposure Orchestrator (`app/core/orchestrator.py`)**: Central dispatcher coordinating target preparation, scanner execution, auto-discovery, correlation, scoring, and storage.
- **Repository Fetcher (`app/core/repo_fetcher.py`)**: Handles local directories, remote Git URLs (shallow clone with timeouts), and multipart ZIP file archives.
- **Scanners Suite (`app/scanners/`)**:
  - `WorkflowScanner`: CI/CD security (GitHub Actions, GitLab CI).
  - `SecretScanner`: Pattern-based signatures and Shannon Entropy detection.
  - `SCAScanner`: Software composition analysis, CVE database, and SBOM inventory.
  - `IaCScanner`: Dockerfile security and Terraform configuration rules.
  - `WebsiteScanner`: Live SSL/TLS audits, security headers, CORS, and sensitive path probing.
  - `DatabaseScanner`: Multi-engine database posture, network reachability, and unauthenticated access probes.
- **Correlation & Attack Graph (`app/core/correlator.py`)**: Maps findings to interactive threat topology nodes (`actor`, `ingress`, `vulnerability`, `asset`, `exfiltration`).
- **Remediation Engine (`app/core/remediator.py`)**: Generates unified diff patches and server configurations (Nginx/Caddy).
- **Storage Adapter (`app/core/storage.py`)**: Dual-engine persistence supporting PostgreSQL (`psycopg3`/`psycopg2`) with connection pooling and local SQLite fallback.

---

## Tri-Vector Posture Coverage

| Vector | Target Type | Scope & Detection Capabilities |
| :--- | :--- | :--- |
| **Domain 01: Code & CI/CD** | Git Repositories, Local Folders, ZIP Archives | Insecure workflow triggers (`pull_request_target`), broad `write-all` permissions, unpinned action SHAs, script injection (`${{ github.event... }}`), leaked cloud/API tokens, high-entropy secrets, known CVEs in dependencies (SBOM), Docker root execution, and Terraform `0.0.0.0/0` ingress. |
| **Domain 02: Web Perimeter** | Web Applications, REST APIs, Microservices | SSL/TLS certificate expiration & verification, deprecated TLS 1.0/1.1 protocols, missing headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`), unsafe CORS wildcards with credentials, server banners, and exposed paths (`/.env`, `/.git/HEAD`, `/actuator/env`). |
| **Domain 03: Database Posture** | PostgreSQL, MySQL, Redis, MongoDB, Elasticsearch, MSSQL | Exposed cleartext credentials, weak/default passwords (`root`, `admin`, `password`), disabled or missing TLS (`sslmode=require`), publicly exposed network ports, and live unauthenticated access probes (Redis `PING`, Elasticsearch `_cluster/health`). |

---

## Quickstart Guide

### Prerequisites

- **Python**: 3.11 or higher (Python 3.11 – 3.14 supported).
- **Git**: Installed and available on system `PATH` (required for cloning remote Git repositories).

### Local Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/AnishDebnath2004/cicd-exposure-manager.git
   cd cicd-exposure-manager
   ```

2. **Create and activate a virtual environment**:
   ```bash
   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate

   # Windows (PowerShell)
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

### Environment Configuration

Copy the example environment configuration:
```bash
cp .env.example .env
```

Adjust parameters as needed:
```ini
# Database: Leave blank for local SQLite (data/shieldci.db), or provide PostgreSQL URI
DATABASE_URL=

# Application & Security Settings
APP_ENV=development
DEBUG=true
PORT=8000
HOST=0.0.0.0

# Optional persistent HMAC signing key for user authentication tokens
SHIELDCI_SECRET_KEY=

# Whitelist of emails permitted to self-register as Administrator
ALLOWED_ADMIN_EMAILS=debnathanish19@gmail.com,anish2004bmg@gmail.com
```

### Launching the Dashboard & API

Start the local development server:
```bash
python main.py
```
Or run directly via Uvicorn:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Once running, navigate to:
- **Interactive Web UI**: [http://localhost:8000](http://localhost:8000)
- **Interactive Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc API Documentation**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

### Running with Docker

Build and run using the optimized multi-stage Dockerfile:
```bash
# Build the Docker image
docker build -t shieldci:latest .

# Run the container (persisting data to host)
docker run -d \
  -p 8000:8000 \
  -v $(pwd)/data:/app/data \
  --name shieldci-app \
  shieldci:latest
```

---

## CLI Auditor & CI/CD Quality Gates

ShieldCI includes a full-featured CLI auditor (`app/cli.py`) powered by **Click** and **Rich** to enforce security gates directly in terminal workflows and continuous integration pipelines.

### Command Usage

```bash
# Audit a local repository directory
python -m app.cli --path ./sample_vulnerable_repo

# Audit a remote Git repository (shallow clone)
python -m app.cli --url https://github.com/octocat/Hello-World --branch main

# Audit a live web application or API endpoint
python -m app.cli --web https://example.com

# Audit a database connection or datastore host
python -m app.cli --db postgresql://postgres:postgres@localhost:5432/app

# Enforce a strict CI/CD quality gate (fail if HIGH or CRITICAL issues found)
python -m app.cli --path . --fail-on HIGH --max-pes 50.0

# Export findings to SARIF 2.1.0, JSON, and generate a 1-click self-healing patch
python -m app.cli --path . --sarif report.sarif --json-out report.json --patch-out fix.patch

# View timeline of past scans
python -m app.cli --history
```

### CLI Options Reference

| Option | Short | Description |
| :--- | :--- | :--- |
| `--path` | `-p` | Path to local directory to audit. |
| `--url` | `-u` | Remote Git repository URL to clone and audit. |
| `--web` | `-w` | Live website or API URL to audit. |
| `--db` | `-d` | Database URI or `host:port` to audit. |
| `--db-type` | | Explicit database engine (`postgres`, `mysql`, `redis`, `mongodb`, `elasticsearch`, `mssql`). |
| `--branch` | `-b` | Specific Git branch or tag to clone. |
| `--fail-on` | `-f` | Severity threshold to fail build (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`). Default: `HIGH`. |
| `--max-pes` | `-m` | Maximum allowable Exposure Score (0–100). Default: `60.0`. |
| `--sarif` | | Output path for SARIF 2.1.0 report. |
| `--json-out` | | Output path for raw JSON report. |
| `--patch-out` | | Output path for 1-click self-healing git unified patch (`.patch`). |
| `--history` | | Displays recent scan history table and exits. |

### GitHub Actions Integration

Embed ShieldCI directly in your GitHub Actions pipeline to block pull requests containing exposures and upload SARIF reports to GitHub Code Scanning:

```yaml
name: ShieldCI Security Quality Gate

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install ShieldCI
        run: |
          pip install -r requirements.txt

      - name: Run ShieldCI Exposure Auditor
        run: |
          python -m app.cli \
            --path . \
            --fail-on HIGH \
            --max-pes 50.0 \
            --sarif shieldci-results.sarif \
            --patch-out security-remediation.patch

      - name: Upload SARIF to GitHub Security Tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: shieldci-results.sarif

      - name: Upload Remediation Patch Artifact
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: security-patch
          path: security-remediation.patch
```

### GitLab CI Integration

Add to `.gitlab-ci.yml`:

```yaml
shieldci-quality-gate:
  stage: test
  image: python:3.11-slim
  before_script:
    - apt-get update && apt-get install -y git
    - pip install -r requirements.txt
  script:
    - python -m app.cli --path . --fail-on HIGH --max-pes 60.0 --patch-out remediation.patch
  artifacts:
    when: on_failure
    paths:
      - remediation.patch
```

---

## Autonomous Remediation & Self-Healing Patches

ShieldCI does not simply report issues—it generates **executable, syntactically valid unified diff patches** for identified exposures:

- **Dockerfiles**: Automatically injects a non-root `USER 10001` sandbox directive and replaces `:latest` tags with immutable tags.
- **GitHub Actions Workflows**: Replaces insecure `pull_request_target` triggers with isolated `pull_request` triggers.
- **Python Dependencies (`requirements.txt`)**: Automatically bumps known vulnerable library versions to safe patch releases (e.g. `requests>=2.32.3`, `urllib3>=2.2.2`).
- **Web Servers**: Generates production-ready security header configurations for **Nginx** (`add_header`) and **Caddy**.

### Applying the Patch

Download the patch file from the UI or CLI (`--patch-out fix.patch`) and apply it in one command:

```bash
git apply fix.patch
git commit -am "chore(security): apply autonomous ShieldCI remediation patch"
```

---

## Exposure Scoring (PES) & Risk Grades

The **Pipeline Exposure Score (PES)** is a normalized index between `0.0` (Hardened) and `100.0` (Extremely Exposed):

$$\text{PES} = \min\left(100.0, \sum (\text{Count}_i \times \text{Weight}_i)\right)$$

### Default Severity Weights

| Severity | Default Weight | Configurable Key |
| :--- | :--- | :--- |
| **CRITICAL** | 25.0 | `weight_critical` |
| **HIGH** | 12.0 | `weight_high` |
| **MEDIUM** | 4.0 | `weight_medium` |
| **LOW** | 1.0 | `weight_low` |
| **INFO** | 0.0 | `weight_info` |

### Risk Grade Scale

| Score Range | Letter Grade | Risk Level | CI/CD Quality Gate Status |
| :--- | :--- | :--- | :--- |
| `0.0` | **A+** | Hardened | Passed |
| `0.1 – 15.0` | **A** | Low Risk | Passed |
| `15.1 – 35.0` | **B** | Moderate | Passed |
| `35.1 – 60.0` | **C** | Elevated | Passed (if $\le \text{Max PES}$) |
| `60.1 – 80.0` | **D** | High Risk | Blocked |
| `80.1 – 100.0` | **F** | Critical Exposure | Blocked |

---

## REST API Summary

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/scan` | Universal router auditing repository, website, or database | Optional (Guest quota: 5/day) |
| `POST` | `/api/scan/website` | Direct live web perimeter scan | Optional |
| `POST` | `/api/scan/database` | Direct live database posture scan | Optional |
| `POST` | `/api/scan/upload` | Multipart ZIP repository upload and scan | Optional |
| `POST` | `/api/scan/triangulate` | Scan repo and recursively scan auto-discovered web & DB targets | Optional |
| `GET` | `/api/scans` | List scan history timeline | Authenticated / Scoped |
| `GET` | `/api/scans/{id}` | Retrieve complete scan report with findings and graph | Optional |
| `DELETE` | `/api/scans/{id}` | Delete a scan record | Authenticated |
| `GET` | `/api/scans/{id}/export` | Export scan in SARIF 2.1.0, JSON, or CSV format | Optional |
| `GET` | `/api/scans/{id}/patch` | Download 1-click self-healing git unified patch | Optional |
| `GET` | `/api/scans/{id}/attack-graph` | Fetch graph nodes and edges for visualization | Optional |
| `GET` | `/api/schedules` | List continuous scheduled scans | Authenticated |
| `POST` | `/api/schedules` | Create continuous scan schedule | Authenticated |
| `POST` | `/api/schedules/{id}/run` | Manually trigger an immediate run of a scheduled scan | Authenticated |
| `DELETE`| `/api/schedules/{id}` | Delete a scheduled scan | Authenticated |
| `POST` | `/api/auth/signup` | Register a new user or developer account | Public |
| `POST` | `/api/auth/login` | Authenticate and obtain signed Bearer token | Public |
| `GET` | `/api/auth/me` | Retrieve profile of currently authenticated user | Authenticated |
| `PUT` | `/api/auth/profile` | Update profile information and preferred domain | Authenticated |
| `PUT` | `/api/auth/password` | Change password with automatic session revocation | Authenticated |
| `GET` | `/api/admin/users` | List all registered users (Admin only) | Admin |
| `PUT` | `/api/admin/users/{id}/role` | Update user role and domain delegation | Admin |
| `DELETE`| `/api/admin/users/{id}` | Delete a user account | Admin |
| `GET` | `/api/settings` | Retrieve active policy gates and scanner thresholds | Optional |
| `PUT` | `/api/settings` | Update policy gates and scanner thresholds | Authenticated |
| `POST` | `/api/settings/test-webhook`| Dispatch test payload to configured webhook URL | Authenticated |
| `POST` | `/api/webhook/github` | Ingest GitHub push / pull_request webhook events | Public |
| `GET` | `/api/health` | Comprehensive system health check and DB metadata | Public |
| `GET` | `/api/stats/overview` | High-level metrics for dashboard header counters | Public |

For detailed payloads, query parameters, schemas, and curl examples, see [API Reference](docs/API_REFERENCE.md).

---

## Documentation Index

Explore our comprehensive technical guides in the `docs/` directory:

- 🏛️ **[System Architecture](docs/ARCHITECTURE.md)**: Deep dive into orchestrator internals, correlation mathematics, threat modeling graph theory, and dual-engine storage.
- 📡 **[REST API Reference](docs/API_REFERENCE.md)**: Complete endpoint catalog with request/response schemas, error codes, and curl examples.
- 💻 **[CLI Reference](docs/CLI_REFERENCE.md)**: Command line syntax, quality gate enforcement, and production CI/CD recipes for GitHub Actions and GitLab CI.
- 🔍 **[Scanner Engine Heuristics](docs/SCANNERS.md)**: Comprehensive taxonomy of all 6 scanning engines, detection rules, entropy formulas, and CVE databases.
- 🚀 **[Deployment Guide](docs/DEPLOYMENT.md)**: Zero-downtime deployment recipes for Docker, Render, Vercel Serverless, and PostgreSQL database setup.

---

## Testing & Quality Assurance

ShieldCI maintains an automated test suite verifying all security scanners, authentication barriers, domain isolation, SSRF protections, and database fallback layers.

Run tests using `pytest`:
```bash
# Execute full test suite
python -m pytest -v

# Run with test coverage
python -m pytest --cov=app tests/
```

### Verified Test Matrix

- `tests/test_universal_scan.py`: Validates repositories, websites, databases, auto-discovery, and attack graphs.
- `tests/test_auth.py`: Validates PBKDF2-HMAC password hashing, HMAC token issuance, and login flows.
- `tests/test_admin_rbac.py`: Validates administrative governance and role-based access restrictions.
- `tests/test_domain_isolation.py`: Validates multi-domain developer access across Domains 01, 02, and 03.
- `tests/test_hardening.py`: Validates SSRF protections, HTTP security headers, and session revocation.
- `tests/test_limitations.py`: Validates continuous schedule auth enforcement and guest scan quotas.
- `tests/test_settings.py`: Validates runtime settings reconfiguration and webhook test dispatches.
- `tests/test_database.py`: Validates PostgreSQL connection pooling and graceful SQLite fallback.
- `tests/test_stats_overview.py`: Validates real-time aggregation of metrics across all assets.

---

## Contributing & License

Contributions are welcome! Please follow our security guidelines when submitting pull requests:
1. Ensure all new scanners include accompanying test cases in `tests/`.
2. Verify all 36+ automated tests pass (`pytest -v`).
3. Maintain zero-dependency principles where possible for lightweight execution.

ShieldCI is licensed under the [Apache License 2.0](LICENSE).
