"""
api/index.py
Vercel Serverless Function Entry Point for ShieldCI CI/CD Exposure Manager.
Exposes the FastAPI ASGI 'app' instance to Vercel's Python runtime with
clean URL rewrite resolution and resilient error handling.
"""

import os
import sys
import traceback
import urllib.parse

# Ensure root directory is present in sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

try:
    from app.main import app

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
