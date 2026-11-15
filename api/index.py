"""
api/index.py
Vercel Serverless Function Entry Point for ShieldCI CI/CD Exposure Manager.
Exposes the FastAPI ASGI 'app' instance to Vercel's Python runtime with
automatic path normalization for Vercel routing layers.
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
                raw_path = scope.get("path", "")
                qs = scope.get("query_string", b"").decode("utf-8", "ignore")
                if "debug" in raw_path or "debug" in qs:
                    import json
                    headers_dict = {k.decode("latin1"): v.decode("latin1") for k, v in scope.get("headers", [])}
                    body = json.dumps({
                        "scope_path": raw_path,
                        "query_string": qs,
                        "headers": headers_dict
                    }, indent=2).encode("utf-8")
                    await send({
                        "type": "http.response.start",
                        "status": 200,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode("ascii")),
                        ],
                    })
                    await send({
                        "type": "http.response.body",
                        "body": body,
                    })
                    return
                qs = scope.get("query_string", b"").decode("utf-8", "ignore")
                orig_path = None
                if "__orig_path__=" in qs:
                    pairs = urllib.parse.parse_qsl(qs, keep_blank_values=True)
                    remaining = []
                    for k, v in pairs:
                        if k == "__orig_path__":
                            orig_path = v
                        else:
                            remaining.append((k, v))
                    scope["query_string"] = urllib.parse.urlencode(remaining).encode("utf-8")

                if orig_path:
                    while orig_path.startswith("//"):
                        orig_path = orig_path[1:]
                    if not orig_path.startswith("/"):
                        orig_path = "/" + orig_path
                    scope["path"] = orig_path
                else:
                    path = scope.get("path", "")
                    if path in ("/api/index.py", "/api/index.py/", "/api/index", "/api/index/"):
                        scope["path"] = "/"
                    elif path.startswith("/api/index.py/"):
                        scope["path"] = path[len("/api/index.py"):]
                    elif path.startswith("/api/index/"):
                        scope["path"] = path[len("/api/index"):]

                cur_path = scope.get("path", "")
                if cur_path in ("/health", "/scans", "/scan", "/schedules", "/settings", "/remediation", "/copilot", "/stats/overview") or \
                   cur_path.startswith(("/scans/", "/scan/", "/schedules/", "/webhook/", "/auth/", "/settings/", "/remediation/", "/copilot/", "/stats/", "/admin/", "/database/")):
                    scope["path"] = "/api" + cur_path

            await self.asgi_app(scope, receive, send)

    app = VercelPathNormalizer(fastapi_app)

except Exception as e:
    err_tb = traceback.format_exc()

    async def app(scope, receive, send):
        if scope.get("type") == "http":
            body = (
                f"<!DOCTYPE html><html><head><title>Startup Error</title></head>"
                f"<body style='font-family:sans-serif;background:#0f172a;color:#f8fafc;padding:2rem;'>"
                f"<h1 style='color:#ef4444;'>ShieldCI Startup Exception</h1>"
                f"<pre style='background:#1e293b;color:#fca5a5;padding:1.5rem;border-radius:0.75rem;overflow:auto;font-size:14px;'>{err_tb}</pre>"
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
