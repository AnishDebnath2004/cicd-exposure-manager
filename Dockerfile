# ShieldCI Production Multi-Vector Exposure Platform Dockerfile
FROM python:3.11-slim

# Install system dependencies (git is required for shallow cloning remote repos)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source tree
COPY . .

# Ensure data directories exist and set non-root user
RUN mkdir -p /app/data /app/data/temp_scans && \
    useradd -u 10001 -m shielduser && \
    chown -R shielduser:shielduser /app

USER shielduser

ENV HOST=0.0.0.0
ENV PORT=8000
ENV APP_ENV=production

EXPOSE 8000

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
