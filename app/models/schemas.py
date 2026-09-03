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

class ScanRequest(BaseModel):
    target: Optional[str] = None
    target_type: Optional[TargetCategory] = None
    target_path: Optional[str] = None
    repo_url: Optional[str] = None
    branch: Optional[str] = None
    repo_name: Optional[str] = None
    db_type: Optional[str] = None
    auto_triangulate: bool = True
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