"""
app/config.py
Configuration and global settings for the DevSecOps CI/CD Exposure Manager (ShieldCI).
Supports environment variable overrides for CI/CD integration and deployment.
"""

import os
import shutil
import tempfile
from typing import Set, Dict, Optional
from pydantic import BaseModel, Field


def _load_env_file():
    """Loads key=value pairs from root .env file into os.environ if present."""
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env_path = os.path.join(root_dir, ".env")
    if os.path.isfile(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, val = line.partition("=")
                    key = key.strip()
                    val = val.strip().strip("'\"")
                    if key and key not in os.environ:
                        os.environ[key] = val
        except Exception:
            pass

_load_env_file()


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

    # Remote Database URL (PostgreSQL / Supabase / Neon / RDS / Render)
    # When provided, ShieldCI connects to PostgreSQL with connection pooling.
    # When absent, ShieldCI defaults to local SQLite at DB_PATH.
    DATABASE_URL: Optional[str] = Field(
        default_factory=lambda: (
            os.getenv("DATABASE_URL")
            or os.getenv("POSTGRES_URL")
            or os.getenv("POSTGRESQL_URL")
            or os.getenv("POSTGRES_PRISMA_URL")
        )
    )

    @property
    def normalized_database_url(self) -> Optional[str]:
        """Normalizes postgres:// -> postgresql:// and automatically URL-encodes special characters in credentials."""
        if not self.DATABASE_URL:
            return None
        url = self.DATABASE_URL.strip()
        if url.startswith("postgres://"):
            url = "postgresql://" + url[len("postgres://"):]

        # Handle passwords with unencoded '@' characters (e.g., postgresql://user:p@ss@host:5432/db)
        try:
            if "://" in url and "@" in url:
                scheme, rest = url.split("://", 1)
                if rest.count("@") > 1 and "/" in rest:
                    auth_part, host_part = rest.rsplit("@", 1)
                    if ":" in auth_part:
                        user, password = auth_part.split(":", 1)
                        import urllib.parse
                        if "@" in password:
                            encoded_pw = urllib.parse.quote_plus(password)
                            url = f"{scheme}://{user}:{encoded_pw}@{host_part}"
        except Exception:
            pass

        return url

    @property
    def is_postgres(self) -> bool:
        """Returns True if a PostgreSQL connection string is configured."""
        url = self.normalized_database_url
        return bool(url and (url.startswith("postgresql://") or url.startswith("postgres://")))

    # Ingestion & Timeout Settings
    GIT_TIMEOUT_SECONDS: int = int(os.getenv("SHIELDCI_GIT_TIMEOUT", "60"))
    MAX_UPLOAD_SIZE_MB: int = int(os.getenv("SHIELDCI_MAX_UPLOAD_MB", "50"))
    MAX_CONCURRENT_SCANS: int = int(os.getenv("SHIELDCI_MAX_CONCURRENT_SCANS", "5"))

    # Modular sub-configs
    scoring_weights: ExposureScoringWeights = ExposureScoringWeights()
    scanner: ScannerSettings = ScannerSettings()
    policy_gate: PolicyGateDefaults = PolicyGateDefaults()

    # Outbound Webhook Alerts & Policy Toggles
    WEBHOOK_URL: Optional[str] = None
    WEBHOOK_ENABLED: bool = False
    NOTIFY_ON_GATE_FAILURE_ONLY: bool = True
    AUTO_FAIL_ON_TOXIC_COMBOS: bool = True

    def apply_settings_dict(self, data: dict):
        """Dynamically applies persisted settings updates to runtime configuration."""
        if not data:
            return
        if "default_fail_severity" in data and data["default_fail_severity"]:
            val = data["default_fail_severity"]
            self.policy_gate.DEFAULT_FAIL_SEVERITY = val.value if hasattr(val, "value") else str(val)
        if "default_max_pes" in data and data["default_max_pes"] is not None:
            self.policy_gate.DEFAULT_MAX_PES = float(data["default_max_pes"])
        if "auto_fail_on_toxic_combos" in data and data["auto_fail_on_toxic_combos"] is not None:
            self.AUTO_FAIL_ON_TOXIC_COMBOS = bool(data["auto_fail_on_toxic_combos"])

        if "shannon_entropy_threshold" in data and data["shannon_entropy_threshold"] is not None:
            self.scanner.SHANNON_ENTROPY_THRESHOLD = float(data["shannon_entropy_threshold"])
        if "min_token_length_for_entropy" in data and data["min_token_length_for_entropy"] is not None:
            self.scanner.MIN_TOKEN_LENGTH_FOR_ENTROPY = int(data["min_token_length_for_entropy"])
        if "ignored_directories" in data and data["ignored_directories"] is not None:
            self.scanner.IGNORED_DIRECTORIES = set(data["ignored_directories"])
        if "ignored_extensions" in data and data["ignored_extensions"] is not None:
            self.scanner.IGNORED_EXTENSIONS = set(data["ignored_extensions"])

        if "weight_critical" in data and data["weight_critical"] is not None:
            self.scoring_weights.CRITICAL = float(data["weight_critical"])
        if "weight_high" in data and data["weight_high"] is not None:
            self.scoring_weights.HIGH = float(data["weight_high"])
        if "weight_medium" in data and data["weight_medium"] is not None:
            self.scoring_weights.MEDIUM = float(data["weight_medium"])
        if "weight_low" in data and data["weight_low"] is not None:
            self.scoring_weights.LOW = float(data["weight_low"])
        if "weight_info" in data and data["weight_info"] is not None:
            self.scoring_weights.INFO = float(data["weight_info"])

        if "git_timeout_seconds" in data and data["git_timeout_seconds"] is not None:
            self.GIT_TIMEOUT_SECONDS = int(data["git_timeout_seconds"])
        if "max_upload_size_mb" in data and data["max_upload_size_mb"] is not None:
            self.MAX_UPLOAD_SIZE_MB = int(data["max_upload_size_mb"])

        if "webhook_url" in data:
            self.WEBHOOK_URL = str(data["webhook_url"]).strip() if data["webhook_url"] else None
        if "webhook_enabled" in data and data["webhook_enabled"] is not None:
            self.WEBHOOK_ENABLED = bool(data["webhook_enabled"])
        if "notify_on_gate_failure_only" in data and data["notify_on_gate_failure_only"] is not None:
            self.NOTIFY_ON_GATE_FAILURE_ONLY = bool(data["notify_on_gate_failure_only"])



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