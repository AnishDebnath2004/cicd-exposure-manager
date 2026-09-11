# ShieldCI: Production Deployment & Operations Guide

This guide covers deployment architectures, cloud platforms, database setups, migration procedures, and production security hardening for the **ShieldCI DevSecOps CI/CD Exposure Manager**.

---

## Table of Contents

- [Deployment Architectures](#deployment-architectures)
- [Environment Variables Reference](#environment-variables-reference)
- [1. Standalone Virtual Machine / Bare Metal](#1-standalone-virtual-machine--bare-metal)
  - [systemd Service Configuration](#systemd-service-configuration)
  - [Nginx Reverse Proxy with TLS](#nginx-reverse-proxy-with-tls)
- [2. Docker Container Deployment](#2-docker-container-deployment)
  - [Building and Running the Container](#building-and-running-the-container)
  - [Production Docker Compose with PostgreSQL](#production-docker-compose-with-postgresql)
- [3. Render Web Service Deployment](#3-render-web-service-deployment)
- [4. Vercel Serverless Functions Deployment](#4-vercel-serverless-functions-deployment)
- [5. Platform-as-a-Service (Railway, Fly.io, Heroku)](#5-platform-as-a-service-railway-flyio-heroku)
- [Remote PostgreSQL Database Configuration](#remote-postgresql-database-configuration)
  - [Neon (Serverless Postgres)](#neon-serverless-postgres)
  - [Supabase](#supabase)
  - [Render PostgreSQL](#render-postgresql)
  - [AWS RDS PostgreSQL](#aws-rds-postgresql)
- [Database Migrations & Administrative Utilities](#database-migrations--administrative-utilities)
  - [Migrating SQLite to PostgreSQL](#migrating-sqlite-to-postgresql)
  - [Inspecting the Database](#inspecting-the-database)
  - [Promoting an Administrator](#promoting-an-administrator)
  - [Resetting Passwords](#resetting-passwords)
- [Production Hardening Checklist](#production-hardening-checklist)

---

## Deployment Architectures

```
                    ┌────────────────────────────────────────────────────────┐
                    │               DNS / Cloudflare / CDN                   │
                    └───────────────────────────┬────────────────────────────┘
                                                │ HTTPS (Port 443)
                                                ▼
                    ┌────────────────────────────────────────────────────────┐
                    │             Nginx / Reverse Proxy / ALB                │
                    └───────────────────────────┬────────────────────────────┘
                                                │ HTTP (Port 8000)
                                                ▼
                    ┌────────────────────────────────────────────────────────┐
                    │            ShieldCI Application Instance               │
                    │         (Docker / systemd / Render / Vercel)           │
                    └───────────────┬────────────────────────┬───────────────┘
                                    │                        │
                      PostgreSQL Connection Pool             │ (Fallback / Dev)
                                    ▼                        ▼
                    ┌────────────────────────┐   ┌───────────────────────────┐
                    │   Remote PostgreSQL    │   │       Local SQLite        │
                    │ (Neon, Supabase, RDS)  │   │     (data/shieldci.db)    │
                    └────────────────────────┘   └───────────────────────────┘
```

---

## Environment Variables Reference

| Variable | Default | Description |
| :--- | :--- | :--- |
| `DATABASE_URL` | *(None / SQLite)* | PostgreSQL connection string. When omitted, ShieldCI uses SQLite at `data/shieldci.db`. |
| `APP_ENV` | `development` | Set to `production` in production environments. |
| `DEBUG` | `true` | Set to `false` in production. Disables debug stack traces in HTTP 500 responses. |
| `PORT` | `8000` | HTTP port the server binds to. Automatically set by Render/Railway/Heroku. |
| `HOST` | `0.0.0.0` | Network binding interface. |
| `SHIELDCI_SECRET_KEY` | *(Auto-generated)* | 32-byte cryptographic secret used for signing Bearer auth tokens. |
| `SHIELDCI_DATA_DIR` | `data` | Directory where scan artifacts and SQLite files are stored. |
| `SHIELDCI_CORS_ORIGINS`| `*` | Comma-separated list of allowed origins (e.g. `https://shieldci.example.com`). |
| `ALLOWED_ADMIN_EMAILS` | *(Pre-seeded)* | Comma-separated whitelist of email addresses authorized to register with role `admin`. |
| `SHIELDCI_ALLOW_PRIVATE_TARGETS` | `false` | When `false`, blocks audits against internal RFC 1918 and loopback IPs (Anti-SSRF). |
| `SHIELDCI_FAIL_ON` | `HIGH` | Default build-fail severity threshold (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`). |
| `SHIELDCI_MAX_PES` | `60.0` | Default maximum allowable Pipeline Exposure Score before policy gate blockage. |
| `SHIELDCI_GIT_TIMEOUT` | `60` | Maximum duration (seconds) allowed for remote `git clone` operations. |
| `SHIELDCI_MAX_UPLOAD_MB`| `50` | Maximum allowable ZIP archive upload size in megabytes. |

---

## 1. Standalone Virtual Machine / Bare Metal

### systemd Service Configuration

Create `/etc/systemd/system/shieldci.service`:

```ini
[Unit]
Description=ShieldCI DevSecOps CI/CD Exposure Manager
After=network.target

[Service]
Type=simple
User=shielduser
Group=shielduser
WorkingDirectory=/opt/shieldci
EnvironmentFile=/opt/shieldci/.env
ExecStart=/opt/shieldci/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 4
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable shieldci
sudo systemctl start shieldci
```

### Nginx Reverse Proxy with TLS

Create `/etc/nginx/sites-available/shieldci.conf`:

```nginx
server {
    listen 80;
    server_name shieldci.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name shieldci.example.com;

    ssl_certificate /etc/letsencrypt/live/shieldci.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/shieldci.example.com/privkey.pem;

    client_max_body_size 50M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 120s;
        proxy_connect_timeout 60s;
    }
}
```

---

## 2. Docker Container Deployment

### Building and Running the Container

The repository includes a production-ready `Dockerfile` running Python 3.11 with a non-root user (`shielduser`, UID 10001):

```bash
# Build the image
docker build -t shieldci:latest .

# Run with persistent local storage
docker run -d \
  -p 8000:8000 \
  -e APP_ENV=production \
  -e DEBUG=false \
  -e SHIELDCI_SECRET_KEY="replace_with_32_byte_secret_hex" \
  -v $(pwd)/data:/app/data \
  --name shieldci \
  shieldci:latest
```

### Production Docker Compose with PostgreSQL

Create `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    restart: always
    environment:
      POSTGRES_DB: shieldci
      POSTGRES_USER: shieldci_user
      POSTGRES_PASSWORD: StrongProductionPassword2026!
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U shieldci_user -d shieldci"]
      interval: 5s
      timeout: 5s
      retries: 5

  shieldci:
    build: .
    restart: always
    ports:
      - "8000:8000"
    environment:
      DATABASE_URL: "postgresql://shieldci_user:StrongProductionPassword2026!@postgres:5432/shieldci"
      APP_ENV: production
      DEBUG: "false"
      SHIELDCI_SECRET_KEY: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      ALLOWED_ADMIN_EMAILS: "admin@example.com"
    depends_on:
      postgres:
        condition: service_healthy
    volumes:
      - appdata:/app/data

volumes:
  pgdata:
  appdata:
```

Launch with:
```bash
docker compose -f docker-compose.prod.yml up -d
```

---

## 3. Render Web Service Deployment

ShieldCI includes a native `render.yaml` configuration:

```yaml
services:
  - type: web
    name: cicd-exposure-manager
    env: python
    region: oregon
    plan: free
    buildCommand: "pip install -r requirements.txt"
    startCommand: "uvicorn app.main:app --host 0.0.0.0 --port $PORT"
    envVars:
      - key: PYTHON_VERSION
        value: 3.11.8
      - key: APP_ENV
        value: production
```

### Steps to Deploy on Render:
1. Connect your GitHub repository to [Render Dashboard](https://dashboard.render.com).
2. Create a new **Web Service** or choose **Blueprint** to use `render.yaml`.
3. Add Environment Variables:
   - `DATABASE_URL`: Your PostgreSQL connection string.
   - `SHIELDCI_SECRET_KEY`: Generate a random 32-byte hex string.
   - `ALLOWED_ADMIN_EMAILS`: Your administrator email address.
4. Deploy! Render will build dependencies and start Uvicorn on the assigned port.

---

## 4. Vercel Serverless Functions Deployment

ShieldCI supports serverless execution on Vercel via `@vercel/python`, configured in `vercel.json` and routed through `api/index.py`:

```json
{
  "builds": [
    {
      "src": "api/index.py",
      "use": "@vercel/python"
    }
  ],
  "routes": [
    {
      "src": "/(.*)",
      "dest": "api/index.py"
    }
  ]
}
```

### Serverless Runtime Behavior:
- **Read-Only Filesystem**: Serverless runtimes have a read-only root directory. ShieldCI automatically redirects temporary scan downloads and SQLite storage to `/tmp/shieldci_data/`.
- **Database Recommendation**: Use a remote serverless database (**Neon** or **Supabase**) by setting `DATABASE_URL`. Local SQLite in `/tmp` is ephemeral and resets between cold starts.
- **Scheduler**: The background continuous scheduler (`app/core/scheduler.py`) is automatically disabled in serverless mode (`settings.IS_SERVERLESS = True`). Use Vercel Cron or GitHub Actions to trigger recurring scans via API.

---

## 5. Platform-as-a-Service (Railway, Fly.io, Heroku)

The repository includes a root `Procfile`:
```
web: uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

Deploying to Railway or Heroku automatically detects the `Procfile` and binds Uvicorn to the assigned dynamic `$PORT`.

---

## Remote PostgreSQL Database Configuration

ShieldCI supports PostgreSQL connection strings with automatic URL-encoding and connection pooling.

### Neon (Serverless Postgres)
```ini
DATABASE_URL=postgresql://neondb_owner:npg_secret@ep-cool-project-123456.us-east-2.aws.neon.tech/neondb?sslmode=require
```

### Supabase
For serverless or containerized environments, use Supabase's transaction pooler (port 6543) or direct connection (port 5432):
```ini
DATABASE_URL=postgresql://postgres:[YOUR-PASSWORD]@db.[YOUR-PROJECT-REF].supabase.co:5432/postgres?sslmode=require
```

### Render PostgreSQL
```ini
DATABASE_URL=postgresql://shieldci_user:secret@dpg-xxx-a.oregon-postgres.render.com/shieldci
```

### AWS RDS PostgreSQL
```ini
DATABASE_URL=postgresql://dbadmin:MasterPass123!@shieldci-db.c123456789.us-east-1.rds.amazonaws.com:5432/shieldci?sslmode=require
```

---

## Database Migrations & Administrative Utilities

ShieldCI includes utility scripts in the `scripts/` directory:

### Migrating SQLite to PostgreSQL
When moving from local SQLite development to production PostgreSQL:

```bash
# Ensure DATABASE_URL is defined in .env
python scripts/migrate_sqlite_to_pg.py
```
This script:
1. Connects to `data/shieldci.db`.
2. Connects to the PostgreSQL `DATABASE_URL`.
3. Auto-initializes PostgreSQL tables if missing.
4. Migrates all scans, schedules, users, and settings without data loss.

### Inspecting the Database
View table schemas and record counts:
```bash
python scripts/inspect_db.py
```

### Promoting an Administrator
Promote a registered user to the `admin` role:
```bash
# Edit target email in scripts/promote_user.py or run:
python scripts/promote_user.py
```

### Resetting Passwords
Generate a new PBKDF2-hashed password for an existing account:
```bash
python scripts/reset_password.py
```

---

## Production Hardening Checklist

Before exposing ShieldCI to public traffic, ensure the following checklist is completed:

- [ ] **Secret Key**: Set an explicit 64-character hex key for `SHIELDCI_SECRET_KEY`:
      ```bash
      python -c "import secrets; print(secrets.token_hex(32))"
      ```
- [ ] **Database**: Connect a managed PostgreSQL database with TLS (`?sslmode=require`).
- [ ] **SSRF Isolation**: Ensure `SHIELDCI_ALLOW_PRIVATE_TARGETS` is set to `false`.
- [ ] **CORS Restrictions**: Set `SHIELDCI_CORS_ORIGINS` to your production frontend domain (e.g. `https://shieldci.company.com`).
- [ ] **Reverse Proxy**: Place behind Nginx, Cloudflare, or AWS ALB with HTTP $\rightarrow$ HTTPS redirects and TLS 1.3.
- [ ] **Guest Scans**: Verify guest quota (5 scans/day per IP) is enforced on unauthenticated endpoints.
- [ ] **Admin Allowlist**: Configure `ALLOWED_ADMIN_EMAILS` to restrict who can self-provision administrative privileges.
