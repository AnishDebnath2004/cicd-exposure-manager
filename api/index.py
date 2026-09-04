"""
api/index.py
Vercel Serverless Function Entry Point for ShieldCI CI/CD Exposure Manager.
Exposes the FastAPI ASGI 'app' instance to Vercel's Python runtime with
automatic path normalization for Vercel routing layers.
"""

import os
import sys

# Ensure root directory is present in sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app.main import app as fastapi_app


class VercelPathNormalizer:
    """
    ASGI middleware ensuring reliable routing under Vercel Serverless Functions.
    Handles URL rewrites, stripped /api prefixes, and /api/index.py entry paths.
    """
    def __init__(self, asgi_app):
        self.asgi_app = asgi_app

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http":
            path = scope.get("path", "")

            # 1. Normalize if Vercel passed the serverless filename as path
            if path in ("/api/index.py", "/api/index.py/", "/api/index", "/api/index/"):
                scope["path"] = "/"
            elif path.startswith("/api/index.py/"):
                scope["path"] = path[len("/api/index.py"):]
            elif path.startswith("/api/index/"):
                scope["path"] = path[len("/api/index"):]

            # 2. Normalize if Vercel stripped the /api prefix for API routes
            cur_path = scope.get("path", "")
            if cur_path in ("/health", "/scans", "/scan", "/schedules", "/settings") or \
               cur_path.startswith(("/scans/", "/scan/", "/schedules/", "/webhook/", "/auth/", "/settings/")):
                scope["path"] = "/api" + cur_path

        await self.asgi_app(scope, receive, send)


app = VercelPathNormalizer(fastapi_app)

__all__ = ["app"]
