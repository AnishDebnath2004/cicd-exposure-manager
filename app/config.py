"""
app/config.py
Configuration and global settings for the DevSecOps CI/CD Exposure Manager (ShieldCI).
Supports environment variable overrides for CI/CD integration and deployment.
"""

import os
import shutil
import tempfile
from typing import Set, Dict
from pydantic import BaseModel, Field


class ExposureScoringWeights(BaseModel):
    """Weight multipliers used to calculate the Pipeline Exposure Score (PES)."""
    CRITICAL: float = 25.0
    HIGH: float = 12.0
    MEDIUM: float = 4.0
    LOW: float = 1.0
    INFO: float = 0.0


class ScannerSettings(BaseModel):
    """Configuration thresholds and ignore rules for scanner engines."""
    
    # Shannon Entropy threshold (higher = stricter randomness required to flag as secret)
    SHANNON_ENTROPY_THRESHOLD: float = Field(
        default=float(os.getenv("SHIELDCI_ENTROPY_THRESHOLD", "4.4")),
        description="Minimum Shannon entropy for flagging unclassified secret tokens"
    )
    
    # Minimum token string length to evaluate for entropy
    MIN_TOKEN_LENGTH_FOR_ENTROPY: int = 24
    
    # Directories excluded from deep security scans
    IGNORED_DIRECTORIES: Set[str] = {
        ".git",
        "node_modules",
        "venv",
        ".venv",
        "env",
        "__pycache__",
        ".idea",
        ".vscode",
        "dist",
        "build",
        ".pytest_cache",
        ".mypy_cache"
    }
    
    # Non-code binary or asset file extensions to bypass
    IGNORED_EXTENSIONS: Set[str] = {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
        ".pyc", ".pyo", ".pyd", ".min.js", ".min.css",
        ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3"
    }


class PolicyGateDefaults(BaseModel):
    """Default CI/CD Quality Gate enforcement rules."""
    
    # Default severity that blocks a pull request or pipeline run
    DEFAULT_FAIL_SEVERITY: str = os.getenv("SHIELDCI_FAIL_ON", "HIGH")
    
    # Maximum allowable Pipeline Exposure Score before build blockage (0-100)
    DEFAULT_MAX_PES: float = float(os.getenv("SHIELDCI_MAX_PES", "60.0"))


class AppConfig(BaseModel):
    """Master Application Configuration."""
    
    PROJECT_NAME: str = "DevSecOps CI/CD Exposure Manager"
    VERSION: str = "1.0.0"
    APP_ENV: str = os.getenv("APP_ENV", "development")
    DEBUG: bool = os.getenv("DEBUG", "true").lower() in ("true", "1", "yes")

    # Serverless runtime detection (Vercel, AWS Lambda, Google Cloud Functions)
    IS_SERVERLESS: bool = Field(
        default_factory=lambda: bool(
            os.getenv("VERCEL")
            or os.getenv("AWS_LAMBDA_FUNCTION_NAME")
            or os.getenv("LAMBDA_TASK_ROOT")
        )
    )
    
    # Server Binding
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    
    # File Paths
    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    STATIC_DIR: str = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
    
    # In serverless environments, root is read-only; use /tmp for writable data and temp files
    DATA_DIR: str = Field(
        default_factory=lambda: os.getenv(
            "SHIELDCI_DATA_DIR",
            os.path.join(tempfile.gettempdir(), "shieldci_data")
            if bool(os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME") or os.getenv("LAMBDA_TASK_ROOT"))
            else os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
        )
    )
    TEMP_SCAN_DIR: str = Field(
        default_factory=lambda: os.getenv(
            "SHIELDCI_TEMP_DIR",
            os.path.join(
                os.getenv(
                    "SHIELDCI_DATA_DIR",
                    os.path.join(tempfile.gettempdir(), "shieldci_data")
                    if bool(os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME") or os.getenv("LAMBDA_TASK_ROOT"))
                    else os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
                ),
                "temp_scans"
            )
        )
    )
    DB_PATH: str = Field(
        default_factory=lambda: os.getenv(
            "SHIELDCI_DB_PATH",
            os.path.join(
                os.getenv(
                    "SHIELDCI_DATA_DIR",
                    os.path.join(tempfile.gettempdir(), "shieldci_data")
                    if bool(os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME") or os.getenv("LAMBDA_TASK_ROOT"))
                    else os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
                ),
                "shieldci.db"
            )
        )
    )

    # Ingestion & Timeout Settings
    GIT_TIMEOUT_SECONDS: int = int(os.getenv("SHIELDCI_GIT_TIMEOUT", "60"))
    MAX_UPLOAD_SIZE_MB: int = int(os.getenv("SHIELDCI_MAX_UPLOAD_MB", "50"))
    MAX_CONCURRENT_SCANS: int = int(os.getenv("SHIELDCI_MAX_CONCURRENT_SCANS", "5"))

    # Modular sub-configs
    scoring_weights: ExposureScoringWeights = ExposureScoringWeights()
    scanner: ScannerSettings = ScannerSettings()
    policy_gate: PolicyGateDefaults = PolicyGateDefaults()


# Global config instance for import across all modules
settings = AppConfig()

def _ensure_directories():
    """Ensures necessary writable directories exist and pre-seeds DB if in serverless."""
    try:
        os.makedirs(settings.DATA_DIR, exist_ok=True)
    except OSError:
        pass

    try:
        os.makedirs(settings.TEMP_SCAN_DIR, exist_ok=True)
    except OSError:
        pass

    # If running in serverless, copy packaged database to writable /tmp if it doesn't already exist
    if settings.IS_SERVERLESS:
        bundled_db = os.path.join(settings.BASE_DIR, "data", "shieldci.db")
        if os.path.isfile(bundled_db) and not os.path.isfile(settings.DB_PATH):
            try:
                shutil.copy2(bundled_db, settings.DB_PATH)
            except Exception:
                pass

_ensure_directories()