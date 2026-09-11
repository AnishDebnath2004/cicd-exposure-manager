# ShieldCI: Command Line Interface (CLI) & CI/CD Integration Reference

The ShieldCI Command Line Interface (`app/cli.py`) is a standalone, terminal-native security auditor designed for DevSecOps pipelines and developer workflows. Built with **Click** and **Rich**, it provides formatted console tables, exit code policy enforcement, and multi-format reporting.

---

## Table of Contents

- [CLI Invocation & Requirements](#cli-invocation--requirements)
- [Command Flags & Options](#command-flags--options)
- [Auditing Modes](#auditing-modes)
  - [1. Auditing a Local Repository](#1-auditing-a-local-repository)
  - [2. Auditing a Remote Git Repository](#2-auditing-a-remote-git-repository)
  - [3. Auditing a Live Web Application / API](#3-auditing-a-live-web-application--api)
  - [4. Auditing a Database Endpoint](#4-auditing-a-database-endpoint)
  - [5. Inspecting Past Audit History](#5-inspecting-past-audit-history)
- [Quality Gate Enforcement & Exit Codes](#quality-gate-enforcement--exit-codes)
- [Artifact Generation & 1-Click Patching](#artifact-generation--1-click-patching)
- [CI/CD Integration Recipes](#cicd-integration-recipes)
  - [GitHub Actions (with SARIF Security Tab Ingestion)](#github-actions-with-sarif-security-tab-ingestion)
  - [GitLab CI Pipeline](#gitlab-ci-pipeline)
  - [Azure DevOps Pipelines](#azure-devops-pipelines)
  - [Jenkins Pipeline (Jenkinsfile)](#jenkins-pipeline-jenkinsfile)
  - [Git Pre-Commit Hook](#git-pre-commit-hook)

---

## CLI Invocation & Requirements

The CLI can be run as a Python module:

```bash
python -m app.cli [OPTIONS]
```

### System Requirements
- Python 3.11+
- Dependencies installed from `requirements.txt` (`click`, `rich`, `pydantic`, `pyyaml`, `requests`)
- `git` on `PATH` (required when auditing remote Git repositories)

---

## Command Flags & Options

| Flag | Short | Default | Description |
| :--- | :--- | :--- | :--- |
| `--path` | `-p` | `.` | Filepath to local codebase directory to audit. |
| `--url` | `-u` | `None` | Remote Git repository URL to clone and audit (e.g., `https://github.com/org/repo`). |
| `--web` | `-w` | `None` | Live web application or API URL to audit (e.g., `https://example.com`). |
| `--db` | `-d` | `None` | Database URI or `host:port` to audit (e.g., `postgresql://user:pass@host:5432/db`). |
| `--db-type` | | `None` | Explicit database engine (`postgres`, `mysql`, `redis`, `mongodb`, `elasticsearch`, `mssql`). |
| `--branch` | `-b` | `None` | Specific Git branch or commit tag to clone and audit. |
| `--fail-on` | `-f` | `HIGH` | Minimum finding severity that causes the build to fail (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`). |
| `--max-pes` | `-m` | `60.0` | Maximum allowable Exposure Score (0.0 to 100.0) before failing the build. |
| `--sarif` | | `None` | Filepath to write SARIF 2.1.0 report. |
| `--json-out` | | `None` | Filepath to write raw JSON report. |
| `--patch-out`| | `None` | Filepath to save 1-click self-healing git unified patch (`.patch`). |
| `--history` | | `False` | Displays the recent scan history timeline and exits. |
| `--help` | | | Show command help and exit. |

---

## Auditing Modes

### 1. Auditing a Local Repository
Scans the current working directory or a specified folder:

```bash
# Audit the current directory
python -m app.cli --path .

# Audit a specific local project folder
python -m app.cli --path ./sample_vulnerable_repo
```

### 2. Auditing a Remote Git Repository
ShieldCI performs a shallow clone (`--depth 1`) into an isolated temporary directory, audits all files, and cleans up the temporary artifacts automatically:

```bash
# Audit remote public repository on the default branch
python -m app.cli --url https://github.com/octocat/Hello-World

# Audit specific branch
python -m app.cli --url https://github.com/my-org/core-service --branch staging
```

### 3. Auditing a Live Web Application / API
Conducts an external perimeter audit evaluating TLS certificates, security response headers, CORS configurations, and exposed sensitive paths:

```bash
# Audit a live website
python -m app.cli --web https://example.com

# Audit an internal web service using custom port
python -m app.cli --web https://api.internal.company.com:8443
```

### 4. Auditing a Database Endpoint
Evaluates connection string credentials, default passwords, TLS mode (`sslmode=require`), and probes socket accessibility:

```bash
# Audit PostgreSQL URI
python -m app.cli --db postgresql://postgres:postgres@localhost:5432/app

# Audit Redis server host and port
python -m app.cli --db redis://10.0.1.25:6379

# Audit Elasticsearch cluster
python -m app.cli --db 10.0.1.30:9200 --db-type elasticsearch
```

### 5. Inspecting Past Audit History
Displays a formatted timeline of recent scans stored in SQLite or PostgreSQL:

```bash
python -m app.cli --history
```

Output:
```
                             Recent Scan History Timeline                             
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━┓
┃ Scan ID  ┃ Asset Name             ┃    Type    ┃ Source ┃ Date             ┃ Exposure Score ┃ Grade ┃ Gate Result ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━┩
│ 8f3e2a0b │ sample_vulnerable_repo │ REPOSITORY │ local  │ 2026-09-09 14:30 │           82.0 │     F │ FAIL        │
│ c47192a1 │ example.com            │  WEBSITE   │  web   │ 2026-09-09 14:15 │           15.0 │     A │ PASS        │
└──────────┴────────────────────────┴────────────┴────────┴──────────────────┴────────────────┴───────┴─────────────┘
```

---

## Quality Gate Enforcement & Exit Codes

ShieldCI functions as an automated pass/fail gate in CI/CD pipelines using standard process exit codes:

- **Exit Code `0`**: Security Quality Gate **PASSED**.
  - No findings meet or exceed `--fail-on`.
  - Exposure Score (PES) is $\le$ `--max-pes`.
  - No critical Toxic Combinations detected (when `AUTO_FAIL_ON_TOXIC_COMBOS=true`).
- **Exit Code `1`**: Security Quality Gate **BLOCKED** or runtime failure.
  - One or more findings exceeded the threshold.
  - PES exceeded the allowable threshold.
  - A fatal error occurred during execution.

### Customizing Gate Strictness

```bash
# Strict: Block build if ANY Medium, High, or Critical finding exists
python -m app.cli --path . --fail-on MEDIUM --max-pes 30.0

# Lenient: Only block build on Critical severity findings
python -m app.cli --path . --fail-on CRITICAL --max-pes 80.0
```

---

## Artifact Generation & 1-Click Patching

ShieldCI can output three artifacts simultaneously in a single run:

```bash
python -m app.cli \
  --path . \
  --sarif results.sarif \
  --json-out results.json \
  --patch-out security-fix.patch
```

### Applying the 1-Click Self-Healing Patch
When `--patch-out` is supplied, ShieldCI synthesizes unified diffs for Dockerfiles, GitHub Actions triggers, and vulnerable dependencies:

```bash
# Review patch
cat security-fix.patch

# Apply patch directly to the working tree
git apply security-fix.patch

# Verify and commit
git status
git diff
```

---

## CI/CD Integration Recipes

### GitHub Actions (with SARIF Security Tab Ingestion)

Save this file as `.github/workflows/shieldci.yml`:

```yaml
name: ShieldCI Security Gate

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

permissions:
  contents: read
  security-events: write

jobs:
  audit:
    name: Exposure & Posture Gate
    runs-on: ubuntu-latest

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: 'pip'

      - name: Install Dependencies
        run: |
          pip install -r requirements.txt

      - name: Run ShieldCI Security Audit
        run: |
          python -m app.cli \
            --path . \
            --fail-on HIGH \
            --max-pes 60.0 \
            --sarif shieldci.sarif \
            --patch-out shieldci-fix.patch

      - name: Ingest SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: shieldci.sarif
          category: shieldci-exposure-manager

      - name: Archive Self-Healing Patch
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: remediation-patch
          path: shieldci-fix.patch
```

---

### GitLab CI Pipeline

Add this job to your `.gitlab-ci.yml`:

```yaml
stages:
  - test
  - security

shieldci_audit:
  stage: security
  image: python:3.11-slim
  before_script:
    - apt-get update && apt-get install -y git
    - pip install -r requirements.txt
  script:
    - python -m app.cli --path . --fail-on HIGH --max-pes 50.0 --patch-out remediation.patch --json-out gl-sast-report.json
  artifacts:
    when: on_failure
    paths:
      - remediation.patch
      - gl-sast-report.json
    expire_in: 14 days
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

---

### Azure DevOps Pipelines

Add this task to `azure-pipelines.yml`:

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: UsePythonVersion@0
  inputs:
    versionSpec: '3.11'

- script: |
    pip install -r requirements.txt
    python -m app.cli --path . --fail-on HIGH --max-pes 60.0 --patch-out fix.patch
  displayName: 'Run ShieldCI Quality Gate'

- task: PublishBuildArtifacts@1
  condition: failed()
  inputs:
    PathtoPublish: 'fix.patch'
    ArtifactName: 'SecurityRemediationPatch'
```

---

### Jenkins Pipeline (Jenkinsfile)

```groovy
pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        stage('ShieldCI Audit') {
            steps {
                sh '''
                    python3 -m venv venv
                    . venv/bin/activate
                    pip install -r requirements.txt
                    python -m app.cli --path . --fail-on HIGH --max-pes 60.0 --patch-out remediation.patch
                '''
            }
        }
    }
    post {
        failure {
            archiveArtifacts artifacts: 'remediation.patch', allowEmptyArchive: true
        }
    }
}
```

---

### Git Pre-Commit Hook

Enforce exposure audits before developers commit code locally. Add this script to `.git/hooks/pre-commit` and make it executable (`chmod +x .git/hooks/pre-commit`):

```bash
#!/bin/sh
# ShieldCI Pre-Commit Security Gate

echo "[ShieldCI] Running local exposure audit..."
python -m app.cli --path . --fail-on HIGH --max-pes 50.0

EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "[!] ShieldCI Quality Gate Blocked the commit!"
    echo "    Resolve exposures or run 'python -m app.cli --path . --patch-out fix.patch && git apply fix.patch'"
    exit 1
fi

echo "[ShieldCI] Quality gate passed. Proceeding with commit."
exit 0
```
