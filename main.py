"""
main.py
Root entrypoint for DevSecOps CI/CD Exposure Manager (ShieldCI).
Allows seamless zero-config deployment on Vercel, Render, Railway, and local uvicorn.
"""

from app.main import app

if __name__ == "__main__":
    import uvicorn
    from app.config import settings
    uvicorn.run("main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
