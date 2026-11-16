"""
api/index.py
Vercel Serverless Function Entry Point for ShieldCI CI/CD Exposure Manager.
Exposes the FastAPI ASGI 'app' instance to Vercel's Python runtime with
resilient path normalization and startup exception reporting.
"""

import os
import sys
import traceback

# Ensure root directory is present in sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

try:
    from app.main import app as fastapi_app

    class VercelPathNormalizer:
        """
        ASGI middleware ensuring robust routing under Vercel Serverless Functions.
        Handles Vercel path rewrites, stripped prefixes, and static asset mapping.
        """
        def __init__(self, asgi_app):
            self.asgi_app = asgi_app

        async def __call__(self, scope, receive, send):
            if scope.get("type") == "http":
                path = scope.get("path", "") or "/"

                # 1. Normalize if Vercel passed the serverless filename as path
                if path in ("/api/index.py", "/api/index.py/", "/api/index", "/api/index/"):
                    scope["path"] = "/"
                elif path.startswith("/api/index.py/"):
                    scope["path"] = path[len("/api/index.py"):]
                elif path.startswith("/api/index/"):
                    scope["path"] = path[len("/api/index"):]

                cur_path = scope.get("path", "")
                # 2. If path doesn't start with /api and isn't root, index.html, qrcode, or static,
                # normalize to /api/ (handles cases where Vercel strips /api from request path)
                if not cur_path.startswith(("/api", "/static")) and cur_path not in ("/", "/index.html", "/qrcode.min.js"):
                    scope["path"] = "/api" + (cur_path if cur_path.startswith("/") else "/" + cur_path)

            await self.asgi_app(scope, receive, send)

    app = VercelPathNormalizer(fastapi_app)

except Exception:
    err_tb = traceback.format_exc()
    print("CRITICAL STARTUP ERROR IN VERCEL SERVERLESS FUNCTION:\n", err_tb, file=sys.stderr)

    async def app(scope, receive, send):
        if scope.get("type") == "http":
            body = (
                f"<!DOCTYPE html><html><head><title>ShieldCI Startup Error</title></head>"
                f"<body style='font-family:sans-serif;background:#090d16;color:#f8fafc;padding:2.5rem;'>"
                f"<h2 style='color:#ef4444;'>ShieldCI Serverless Function Invocation Error</h2>"
                f"<p style='color:#94a3b8;'>An unhandled exception occurred during serverless container initialization:</p>"
                f"<pre style='background:#1e293b;color:#fca5a5;padding:1.5rem;border-radius:0.75rem;overflow:auto;font-size:13px;line-height:1.5;'>{err_tb}</pre>"
                f"</body></html>"
            ).encode("utf-8")
            await send({
                "type": "http.response.start",
                "status": 500,
                "headers": [
                    (b"content-type", b"text/html; charset=utf-8"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            })
            await send({
                "type": "http.response.body",
                "body": body,
            })

__all__ = ["app"]
