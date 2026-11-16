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
    from app.main import app as fastapi_app

    class VercelPathNormalizer:
        """
        ASGI middleware ensuring robust routing under Vercel Serverless Functions.
        Resolves rewritten request paths and cleans up query strings.
        """
        def __init__(self, asgi_app):
            self.asgi_app = asgi_app

        async def __call__(self, scope, receive, send):
            if scope.get("type") == "http":
                headers = dict(scope.get("headers", []))
                raw_matched = headers.get(b"x-matched-path", b"").decode("utf-8", "ignore")
                qs = scope.get("query_string", b"").decode("utf-8", "ignore")
                orig_path = None

                # 1. Check if Vercel passed path via query string rewrite parameter
                if "__path__=" in qs:
                    pairs = urllib.parse.parse_qsl(qs, keep_blank_values=True)
                    remaining = []
                    for k, v in pairs:
                        if k == "__path__":
                            orig_path = v
                        else:
                            remaining.append((k, v))
                    scope["query_string"] = urllib.parse.urlencode(remaining).encode("utf-8")
                # 2. Check if Vercel passed original matched path in x-matched-path header
                elif raw_matched and not raw_matched.startswith(("/api/index", "/api/index.py")):
                    orig_path = raw_matched.split("?")[0]

                if orig_path:
                    while orig_path.startswith("//"):
                        orig_path = orig_path[1:]
                    if not orig_path.startswith("/"):
                        orig_path = "/" + orig_path
                    scope["path"] = orig_path
                else:
                    path = scope.get("path", "")
                    if path in ("/api/index.py", "/api/index.py/", "/api/index", "/api/index/", "/api", "/api/"):
                        scope["path"] = "/"
                    elif path.startswith("/api/index.py/"):
                        scope["path"] = path[len("/api/index.py"):]
                    elif path.startswith("/api/index/"):
                        scope["path"] = path[len("/api/index"):]

                cur_path = scope.get("path", "")
                # 3. If path is an API endpoint without /api prefix, prefix it
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
