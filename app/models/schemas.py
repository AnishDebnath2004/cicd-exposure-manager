"""app/models/schemas.py"""
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime
from app.config import settings

class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class FindingCategory(str, Enum):
    PIPELINE_MISCONFIG = "Pipeline Misconfiguration"
    SECRET_EXPOSURE = "Secret & Credential Leak"
    SCA_VULNERABILITY = "Vulnerable Dependency"
    IAC_CONTAINER = "Container & IaC Exposure"
    WEB_EXPOSURE = "Web & API Security Exposure"
    DB_EXPOSURE = "Database Posture & Access Exposure"

class TargetCategory(str, Enum):
    REPOSITORY = "repository"
    WEBSITE = "website"
    DATABASE = "database"

class SourceType(str, Enum):
    LOCAL = "local"
    GIT = "git"
    UPLOAD = "upload"
    WEB = "web"
    DATABASE = "database"

class Finding(BaseModel):
    id: str
    category: FindingCategory
    severity: SeverityLevel
    title: str
    description: str
    file_path: str
    line_number: Optional[int] = None
    snippet: Optional[str] = None
    remediation_advice: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    auto_fixable: bool = False
    fix_patch: Optional[str] = None

class AttackGraphNode(BaseModel):
    id: str
    label: str
    category: str = Field("vulnerability", description="actor, ingress, vulnerability, asset, exfiltration")
    severity: SeverityLevel = SeverityLevel.INFO
    detail: Optional[str] = None
    icon: Optional[str] = None
    finding_id: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    remediation_patch: Optional[str] = None

class AttackGraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str
    animated: bool = True
    severity: SeverityLevel = SeverityLevel.MEDIUM

class ToxicCombination(BaseModel):
    id: str
    title: str
    severity: SeverityLevel
    likelihood: str = "High"
    exploit_chain: List[str]
    finding_ids: List[str] = []
    impact: str
    remediation_advice: str
    unified_patch: Optional[str] = None

class AttackGraph(BaseModel):
    nodes: List[AttackGraphNode] = []
    edges: List[AttackGraphEdge] = []
    toxic_combinations: List[ToxicCombination] = []
    exploitability_index: float = Field(0.0, description="0 to 100 metric of how weaponizable the attack surface is")

class DiscoveredService(BaseModel):
    name: str
    service_type: str = "service"
    image_or_source: Optional[str] = None
    ports: List[str] = []
    connection_hint: Optional[str] = None

class AutoDiscoveryResult(BaseModel):
    discovered_web_targets: List[str] = []
    discovered_db_targets: List[str] = []
    discovered_services: List[DiscoveredService] = []
    source_files: List[str] = []

class ScanSummary(BaseModel):
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    pipeline_exposure_score: float = Field(..., description="PES between 0 (Safe) and 100 (Extremely Exposed)")
    risk_grade: str = Field(..., description="Grade: A (Safe), B, C, D, F (Critical Risk)")
    policy_passed: bool
    scan_duration_seconds: float
    scanned_files_count: int

class ScanResult(BaseModel):
    scan_id: str
    target_path: str
    repo_name: str = "Asset"
    repo_url: Optional[str] = None
    branch: Optional[str] = None
    source_type: SourceType = SourceType.LOCAL
    target_type: TargetCategory = TargetCategory.REPOSITORY
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    summary: ScanSummary
    findings: List[Finding]
    sbom_components: List[Dict[str, Any]] = []
    metadata: Dict[str, Any] = Field(default_factory=dict)
    toxic_combinations: List[ToxicCombination] = []
    attack_graph: Optional[AttackGraph] = None
    auto_discovery: Optional[AutoDiscoveryResult] = None
    unified_patch: Optional[str] = None
    user_email: Optional[str] = None

class ScanRequest(BaseModel):
    target: Optional[str] = None
    target_type: Optional[TargetCategory] = None
    target_path: Optional[str] = None
    repo_url: Optional[str] = None
    branch: Optional[str] = None
    repo_name: Optional[str] = None
    db_type: Optional[str] = None
    auto_triangulate: bool = True
    user_email: Optional[str] = None
    fail_on_severity: SeverityLevel = Field(
        default_factory=lambda: SeverityLevel(settings.policy_gate.DEFAULT_FAIL_SEVERITY)
    )
    max_allowed_pes: float = Field(
        default_factory=lambda: settings.policy_gate.DEFAULT_MAX_PES
    )

class ScheduledScan(BaseModel):
    id: str
    target: str
    source_type: SourceType = SourceType.GIT
    target_type: TargetCategory = TargetCategory.REPOSITORY
    branch: Optional[str] = None
    interval_minutes: int = 60
    enabled: bool = True
    user_email: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_run_at: Optional[datetime] = None
    last_scan_id: Optional[str] = None
    last_pes: Optional[float] = None
    last_grade: Optional[str] = None
    last_status: Optional[str] = None

class ScheduleCreateRequest(BaseModel):
    target: str
    target_type: TargetCategory = TargetCategory.REPOSITORY
    branch: Optional[str] = None
    interval_minutes: int = 60
    fail_on_severity: SeverityLevel = SeverityLevel.HIGH
    max_allowed_pes: float = 60.0
    user_email: Optional[str] = None

class ScanHistorySummary(BaseModel):
    scan_id: str
    repo_name: str
    target_path: str
    source_type: str
    target_type: str = "repository"
    timestamp: datetime
    pipeline_exposure_score: float
    risk_grade: str
    total_findings: int
    critical_count: int
    high_count: int
    policy_passed: bool
    scan_duration_seconds: float
    user_email: Optional[str] = None


class SettingsSchema(BaseModel):
    # Quality Gates
    default_fail_severity: SeverityLevel = SeverityLevel.HIGH
    default_max_pes: float = 60.0
    auto_fail_on_toxic_combos: bool = True

    # Scanner & Entropy Engine
    shannon_entropy_threshold: float = 4.4
    min_token_length_for_entropy: int = 24
    ignored_directories: List[str] = Field(default_factory=lambda: [
        ".git", "node_modules", "venv", ".venv", "env", "__pycache__",
        ".idea", ".vscode", "dist", "build", ".pytest_cache", ".mypy_cache"
    ])
    ignored_extensions: List[str] = Field(default_factory=lambda: [
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
        ".pyc", ".pyo", ".pyd", ".min.js", ".min.css",
        ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3"
    ])

    # Exposure Scoring Weights
    weight_critical: float = 25.0
    weight_high: float = 12.0
    weight_medium: float = 4.0
    weight_low: float = 1.0
    weight_info: float = 0.0

    # System & Ingestion
    git_timeout_seconds: int = 60
    max_upload_size_mb: int = 50

    # Outbound Webhook Alerts
    webhook_url: Optional[str] = None
    webhook_enabled: bool = False
    notify_on_gate_failure_only: bool = True


class SettingsUpdateRequest(BaseModel):
    default_fail_severity: Optional[SeverityLevel] = None
    default_max_pes: Optional[float] = None
    auto_fail_on_toxic_combos: Optional[bool] = None

    shannon_entropy_threshold: Optional[float] = None
    min_token_length_for_entropy: Optional[int] = None
    ignored_directories: Optional[List[str]] = None
    ignored_extensions: Optional[List[str]] = None

    weight_critical: Optional[float] = None
    weight_high: Optional[float] = None
    weight_medium: Optional[float] = None
    weight_low: Optional[float] = None
    weight_info: Optional[float] = None

    git_timeout_seconds: Optional[int] = None
    max_upload_size_mb: Optional[int] = None

    webhook_url: Optional[str] = None
    webhook_enabled: Optional[bool] = None
    notify_on_gate_failure_only: Optional[bool] = None


class WebhookTestRequest(BaseModel):
    webhook_url: Optional[str] = None


class WebhookTestResponse(BaseModel):
    status: str
    message: str
    target_url: str
    response_code: Optional[int] = None