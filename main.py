"""
main.py
Root entrypoint for DevSecOps CI/CD Exposure Manager (ShieldCI).
Allows seamless zero-config deployment on Vercel, Render, Railway, and local uvicorn.
"""

import os
import sys

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app.main import app

if __name__ == "__main__":
    # pyrefly: ignore [missing-import]
    import uvicorn
    from app.config import settings
    uvicorn.run("main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
