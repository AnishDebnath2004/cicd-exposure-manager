# ShieldCI: REST API Reference & Specification

This document provides complete documentation for the **ShieldCI REST API**. It details authentication, request/response models, error handling, status codes, and `curl` examples for every endpoint.

---

## Table of Contents

- [Overview & Base URL](#overview--base-url)
- [Authentication & Session Tokens](#authentication--session-tokens)
- [Guest Rate Limits & Quotas](#guest-rate-limits--quotas)
- [Standard Error Responses](#standard-error-responses)
- [Authentication & User Endpoints](#authentication--user-endpoints)
  - [POST /api/auth/signup](#post-apiauthsignup)
  - [POST /api/auth/login](#post-apiauthlogin)
  - [GET /api/auth/me](#get-apiauthme)
  - [PUT /api/auth/profile](#put-apiauthprofile)
  - [PUT /api/auth/password](#put-apiauthpassword)
  - [POST /api/auth/logout](#post-apiauthlogout)
  - [GET /api/auth/quota](#get-apiauthquota)
- [Administrator Governance Endpoints](#administrator-governance-endpoints)
  - [GET /api/admin/users](#get-apiadminusers)
  - [PUT /api/admin/users/{user_id}/role](#put-apiadminusersuser_idrole)
  - [DELETE /api/admin/users/{user_id}](#delete-apiadminusersuser_id)
  - [POST /api/admin/users](#post-apiadminusers)
- [Tri-Vector Exposure Scanning Endpoints](#tri-vector-exposure-scanning-endpoints)
  - [POST /api/scan (Universal Router)](#post-apiscan-universal-router)
  - [POST /api/scan/website](#post-apiscanswebsite)
  - [POST /api/scan/database](#post-apiscandatabase)
  - [POST /api/scan/upload](#post-apiscanupload)
  - [POST /api/scan/triangulate](#post-apiscantriangulate)
- [Scan Reports, Graphs & Exports](#scan-reports-graphs--exports)
  - [GET /api/scans](#get-apiscans)
  - [GET /api/scans/{scan_id}](#get-apiscansscan_id)
  - [DELETE /api/scans/{scan_id}](#delete-apiscansscan_id)
  - [GET /api/scans/{scan_id}/export](#get-apiscansscan_idexport)
  - [GET /api/scans/{scan_id}/patch](#get-apiscansscan_idpatch)
  - [GET /api/scans/{scan_id}/attack-graph](#get-apiscansscan_idattack-graph)
- [Continuous Scheduling Endpoints](#continuous-scheduling-endpoints)
  - [GET /api/schedules](#get-apischedules)
  - [POST /api/schedules](#post-apischedules)
  - [POST /api/schedules/{schedule_id}/run](#post-apischedulesschedule_idrun)
  - [DELETE /api/schedules/{schedule_id}](#delete-apischedulesschedule_id)
- [Configuration & Webhook Endpoints](#configuration--webhook-endpoints)
  - [GET /api/settings](#get-apisettings)
  - [PUT /api/settings](#put-apisettings)
  - [POST /api/settings/reset](#post-apisettingsreset)
  - [POST /api/settings/test-webhook](#post-apisettingstest-webhook)
  - [POST /api/webhook/github](#post-apiwebhookgithub)
- [System Health & Metrics](#system-health--metrics)
  - [GET /api/health](#get-apihealth)
  - [GET /api/stats/overview](#get-apistatsoverview)

---

## Overview & Base URL

The default server binds to port `8000`:
```
http://localhost:8000
```
Interactive OpenAPI UI is available at `/docs` (Swagger) and `/redoc`.

---

## Authentication & Session Tokens

ShieldCI uses cryptographically signed Bearer tokens (HMAC-SHA256).

### Sending Authentication Header
Include the token in the standard `Authorization` header:
```http
Authorization: Bearer <token_string>
```

Tokens remain valid for **7 days** by default. Tokens are immediately invalidated upon:
- Changing your account password (`PUT /api/auth/password`).
- Role elevation or revocation by an administrator.

---

## Guest Rate Limits & Quotas

- **Unauthenticated Guests**: Restricted to **5 scans per day** per IP address. Exceeding the quota returns `HTTP 429 Too Many Requests`.
- **Authenticated Users**: Receive **unlimited scans**, private scan history, and access to continuous automated schedules.

---

## Standard Error Responses

Errors follow FastAPI's standardized JSON format:

```json
{
  "detail": "Error description message"
}
```

| HTTP Status | Meaning | Typical Scenario |
| :--- | :--- | :--- |
| `400 Bad Request` | Malformed parameters | Invalid email format, passwords shorter than 8 characters. |
| `401 Unauthorized` | Authentication required | Missing, expired, or revoked Bearer token. |
| `403 Forbidden` | Insufficient permissions | Non-admin attempting to access `/api/admin/*`. |
| `404 Not Found` | Resource not found | Invalid `scan_id` or `schedule_id`. |
| `429 Too Many Requests` | Rate limit exceeded | Guest daily scan quota exceeded (5/day). |
| `500 Internal Error` | Server execution error | Remote Git clone failure, network timeout. |

---

## Authentication & User Endpoints

### POST /api/auth/signup
Registers a new user account.

- **Access**: Public
- **Request Body**:
  ```json
  {
    "email": "dev@example.com",
    "password": "SecurePassword123!",
    "full_name": "Jane Developer",
    "organization": "Engineering Sec",
    "role": "developer",
    "preferred_domain": "domain_01"
  }
  ```
  *Note: Role must be `developer` or `user`. Only emails listed in `ALLOWED_ADMIN_EMAILS` can sign up with role `admin`.*

- **Response (`201 Created`)**:
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer",
    "expires_in_seconds": 604800,
    "user": {
      "id": "u-b295f51d6a0a",
      "email": "dev@example.com",
      "full_name": "Jane Developer",
      "organization": "Engineering Sec",
      "role": "developer",
      "preferred_domain": "domain_01",
      "token_version": 1,
      "created_at": "2026-09-09T12:00:00.000Z",
      "last_login_at": null
    }
  }
  ```

- **Example**:
  ```bash
  curl -X POST http://localhost:8000/api/auth/signup \
    -H "Content-Type: application/json" \
    -d '{"email":"dev@example.com","password":"SecurePassword123!","full_name":"Jane Dev"}'
  ```

---

### POST /api/auth/login
Authenticates credentials and returns a signed Bearer token.

- **Access**: Public
- **Request Body**:
  ```json
  {
    "email": "dev@example.com",
    "password": "SecurePassword123!",
    "required_role": "developer"
  }
  ```
- **Response (`200 OK`)**: Returns `AuthTokenResponse` schema (same as signup).

---

### GET /api/auth/me
Returns the profile of the authenticated user.

- **Access**: Authenticated (`Bearer <token>`)
- **Response (`200 OK`)**: `UserResponse` object.

---

### PUT /api/auth/profile
Updates user display name, organization, or preferred domain.

- **Access**: Authenticated
- **Request Body**:
  ```json
  {
    "full_name": "Jane Lead Dev",
    "organization": "DevSecOps",
    "preferred_domain": "domain_02"
  }
  ```
- **Response (`200 OK`)**: Updated `UserResponse`.

---

### PUT /api/auth/password
Changes the user's password and immediately revokes all prior tokens.

- **Access**: Authenticated
- **Request Body**:
  ```json
  {
    "current_password": "SecurePassword123!",
    "new_password": "NewUltraSecurePassword456!"
  }
  ```
- **Response (`200 OK`)**:
  ```json
  {
    "status": "success",
    "message": "Password changed successfully. All previous sessions have been revoked."
  }
  ```

---

### POST /api/auth/logout
Logs out the current user and invalidates all active session tokens.

- **Access**: Authenticated
- **Response (`200 OK`)**:
  ```json
  {
    "status": "success",
    "message": "Logged out successfully"
  }
  ```

---

### GET /api/auth/quota
Checks remaining scan quota for guests or confirms unlimited access for logged-in users.

- **Access**: Public / Authenticated
- **Response (`200 OK`)**:
  ```json
  {
    "client_ip": "203.0.113.195",
    "is_authenticated": false,
    "limit": 5,
    "used": 2,
    "remaining": 3,
    "resets_in_hours": 18
  }
  ```

---

## Administrator Governance Endpoints

### GET /api/admin/users
Lists all registered users in the platform.

- **Access**: Admin only (`role == "admin"`)
- **Response (`200 OK`)**:
  ```json
  {
    "total": 3,
    "users": [
      {
        "id": "u-admin-001",
        "email": "admin@shieldci.io",
        "full_name": "System Administrator",
        "role": "admin",
        "preferred_domain": "domain_01",
        "token_version": 2,
        "created_at": "2026-09-01T00:00:00Z"
      }
    ]
  }
  ```

---

### PUT /api/admin/users/{user_id}/role
Updates a user's role and preferred domain.

- **Access**: Admin only
- **Request Body**:
  ```json
  {
    "role": "admin",
    "preferred_domain": "domain_03"
  }
  ```
- **Response (`200 OK`)**: Returns updated `UserResponse`.

---

### DELETE /api/admin/users/{user_id}
Permanently removes a user account. Admins cannot delete their own active account.

- **Access**: Admin only
- **Response (`200 OK`)**:
  ```json
  {
    "status": "success",
    "message": "User user_123 deleted successfully."
  }
  ```

---

## Tri-Vector Exposure Scanning Endpoints

### POST /api/scan (Universal Router)
Universal scanning endpoint. Automatically detects whether the target is a repository, website, or database based on syntax and URL schemes.

- **Access**: Public (Subject to Guest Quota) / Authenticated
- **Request Body**:
  ```json
  {
    "target": "https://github.com/octocat/Hello-World",
    "target_type": "repository",
    "branch": "main",
    "fail_on_severity": "HIGH",
    "max_allowed_pes": 60.0
  }
  ```
- **Response (`200 OK`)**:
  ```json
  {
    "scan_id": "8f3e2a0b-1934-4b55-a50d-83b62557f369",
    "target_path": "https://github.com/octocat/Hello-World",
    "repo_name": "Hello-World",
    "source_type": "git",
    "target_type": "repository",
    "timestamp": "2026-09-09T14:30:00Z",
    "summary": {
      "total_findings": 3,
      "critical_count": 0,
      "high_count": 1,
      "medium_count": 2,
      "low_count": 0,
      "info_count": 0,
      "pipeline_exposure_score": 20.0,
      "risk_grade": "B (Moderate)",
      "policy_passed": true,
      "scan_duration_seconds": 1.42,
      "scanned_files_count": 12
    },
    "findings": [
      {
        "id": "f-189a",
        "category": "Pipeline Misconfiguration",
        "severity": "HIGH",
        "title": "Excessive Pipeline Permissions (write-all)",
        "description": "Workflow grants broad write permissions to GITHUB_TOKEN.",
        "file_path": ".github/workflows/build.yml",
        "line_number": 12,
        "snippet": "permissions: write-all",
        "remediation_advice": "Set explicit read-only permissions at top-level.",
        "auto_fixable": true
      }
    ],
    "toxic_combinations": [],
    "attack_graph": {
      "nodes": [],
      "edges": [],
      "exploitability_index": 0.0
    },
    "unified_patch": "--- a/.github/workflows/build.yml\n+++ b/.github/workflows/build.yml..."
  }
  ```

---

### POST /api/scan/website
Directly invokes the Live Website & Web API Exposure Scanner.

- **Access**: Public / Authenticated
- **Request Body**:
  ```json
  {
    "target": "https://example.com",
    "fail_on_severity": "HIGH",
    "max_allowed_pes": 60.0
  }
  ```
- **SSRF Safety**: Validates target against private IP ranges (RFC 1918) and cloud metadata services.

---

### POST /api/scan/database
Directly invokes the Database Posture & Network Access Scanner.

- **Access**: Public / Authenticated
- **Request Body**:
  ```json
  {
    "target": "postgresql://postgres:postgres@localhost:5432/app",
    "db_type": "postgres",
    "fail_on_severity": "HIGH",
    "max_allowed_pes": 60.0
  }
  ```

---

### POST /api/scan/upload
Audits a codebase uploaded as a multipart ZIP file archive.

- **Access**: Public / Authenticated
- **Form Data**:
  - `file`: ZIP archive binary (`multipart/form-data`)
  - `repo_name` (optional): Display name for the uploaded asset
  - `fail_on_severity` (optional): Quality gate threshold (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
  - `max_allowed_pes` (optional): Maximum allowable score (`float`)
- **Example**:
  ```bash
  curl -X POST http://localhost:8000/api/scan/upload \
    -F "file=@my-codebase.zip" \
    -F "repo_name=PaymentMicroservice" \
    -F "fail_on_severity=HIGH"
  ```

---

### POST /api/scan/triangulate
Scans a repository codebase, extracts all discovered web URLs and database endpoints, and recursively audits them.

- **Access**: Public / Authenticated
- **Request Body**: Standard `ScanRequest` (e.g. `{"target_path": "./my_repo"}`).

---

## Scan Reports, Graphs & Exports

### GET /api/scans
Retrieves scan history timeline. Authenticated users see their own scans; admins see all scans.

- **Query Parameters**:
  - `limit` (default: 50): Maximum records to retrieve.
  - `target_type` (optional): Filter by `repository`, `website`, or `database`.
- **Response (`200 OK`)**: List of `ScanHistorySummary` items.

---

### GET /api/scans/{scan_id}
Fetches complete scan result, including all individual findings, attack graphs, and metadata.

- **Response (`200 OK`)**: `ScanResult` object.

---

### DELETE /api/scans/{scan_id}
Deletes a scan record from persistent storage.

- **Access**: Authenticated (Owner or Admin)
- **Response (`200 OK`)**:
  ```json
  {
    "status": "success",
    "message": "Scan record deleted successfully."
  }
  ```

---

### GET /api/scans/{scan_id}/export
Exports the scan findings into standard machine-readable formats.

- **Query Parameters**:
  - `format`: One of `sarif`, `json`, or `csv` (default: `sarif`).
- **Response**:
  - `format=sarif`: SARIF 2.1.0 JSON format suitable for GitHub Code Scanning.
  - `format=json`: Complete raw `ScanResult` JSON.
  - `format=csv`: Flattened tabular CSV with columns: `Finding ID`, `Severity`, `Category`, `Title`, `File Path`, `Line`, `CVE`, `Remediation`.

---

### GET /api/scans/{scan_id}/patch
Downloads the 1-click self-healing git unified patch.

- **Response (`200 OK`)**: Plaintext unified diff (`text/plain`):
  ```diff
  --- a/Dockerfile
  +++ b/Dockerfile
  @@ -8,3 +8,4 @@
   COPY . .
  +USER 10001
   CMD ["python", "main.py"]
  ```

---

### GET /api/scans/{scan_id}/attack-graph
Retrieves the graph model with node and edge schemas for rendering in Cytoscape.js or Vis.js.

- **Response (`200 OK`)**:
  ```json
  {
    "nodes": [
      {
        "id": "node-actor",
        "label": "Threat Actor",
        "category": "actor",
        "severity": "CRITICAL",
        "icon": "fa-user-secret"
      }
    ],
    "edges": [
      {
        "id": "edge-0-1",
        "source": "node-actor",
        "target": "node-finding-0",
        "label": "Exploits Insecure Trigger",
        "animated": true
      }
    ],
    "toxic_combinations": [],
    "exploitability_index": 45.0
  }
  ```

---

## Continuous Scheduling Endpoints

### GET /api/schedules
Lists all continuous scheduled jobs.

- **Access**: Authenticated
- **Response (`200 OK`)**: Array of `ScheduledScan` objects.

---

### POST /api/schedules
Creates an automated recurring background scan.

- **Access**: Authenticated
- **Request Body**:
  ```json
  {
    "target": "https://github.com/my-org/core-api",
    "target_type": "repository",
    "branch": "main",
    "interval_minutes": 120,
    "fail_on_severity": "HIGH",
    "max_allowed_pes": 60.0
  }
  ```
- **Response (`200 OK`)**: Created `ScheduledScan`.

---

### POST /api/schedules/{schedule_id}/run
Manually triggers an immediate execution of a scheduled job.

- **Access**: Authenticated
- **Response (`200 OK`)**: Returns triggered `ScanResult`.

---

### DELETE /api/schedules/{schedule_id}
Cancels and removes a scheduled job.

- **Access**: Authenticated
- **Response (`200 OK`)**: `{"status": "deleted"}`.

---

## Configuration & Webhook Endpoints

### GET /api/settings
Retrieves current runtime scanner thresholds, entropy settings, and policy gates.

---

### PUT /api/settings
Updates runtime settings dynamically (persisted to storage).

- **Access**: Authenticated
- **Request Body**:
  ```json
  {
    "default_fail_severity": "CRITICAL",
    "default_max_pes": 40.0,
    "auto_fail_on_toxic_combos": true,
    "shannon_entropy_threshold": 4.5,
    "webhook_url": "https://hooks.slack.com/services/...",
    "webhook_enabled": true,
    "notify_on_gate_failure_only": true
  }
  ```

---

### POST /api/settings/test-webhook
Dispatches an immediate diagnostic payload to the specified webhook URL.

- **Access**: Authenticated
- **Request Body**:
  ```json
  {
    "webhook_url": "https://webhook.site/your-unique-id"
  }
  ```

---

### POST /api/webhook/github
Ingests GitHub webhook events (`push` and `pull_request`). Automatically triggers an exposure scan against the commit branch and evaluates quality gates.

- **Access**: Public
- **Headers**: Standard GitHub Webhook headers (`X-GitHub-Event: push`).

---

## System Health & Metrics

### GET /api/health
Comprehensive health diagnostic.

- **Response (`200 OK`)**:
  ```json
  {
    "status": "healthy",
    "app": "DevSecOps CI/CD Exposure Manager",
    "version": "1.0.0",
    "environment": "production",
    "database": {
      "configured_engine": "postgresql",
      "active_adapter": "postgresql",
      "connected": true,
      "pool_available": true
    },
    "scheduler_running": true,
    "timestamp": "2026-09-09T15:00:00Z"
  }
  ```

---

### GET /api/stats/overview
Aggregates live posture metrics across all monitored assets.

- **Response (`200 OK`)**:
  ```json
  {
    "total_scans": 42,
    "avg_exposure_score": 28.4,
    "risk_breakdown": {
      "critical": 5,
      "high": 18,
      "medium": 32,
      "low": 12
    },
    "pass_rate_percentage": 78.5
  }
  ```
