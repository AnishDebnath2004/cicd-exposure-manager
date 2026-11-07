"""
tests/test_advanced_features.py
Tests for Advanced Platform Features:
- Feature 2: AI Remediation Engine, GitHub PR Publisher, and Security Copilot
- Feature 4: Interactive Exploit Simulator, Attack Steps, and Blast Radius Visualizer
"""

import asyncio
import pytest
from app.models.schemas import (
    Finding, FindingCategory, SeverityLevel, ScanResult, ScanSummary,
    SourceType, TargetCategory, AIRemediationRequest, CopilotChatRequest
)
from app.core.correlator import AttackCorrelator
from app.core.ai_remediator import AIRemediator
from app.core.github_service import GitHubService
from app.core.copilot import SecurityCopilot
from app.core.storage import storage
from app.main import generate_ai_remediation, copilot_chat_interaction


def test_correlator_generates_simulation_steps_and_blast_radius():
    """Verifies that the enriched AttackCorrelator produces kill chain simulation steps & blast radius."""
    correlator = AttackCorrelator()

    findings = [
        Finding(
            id="f-wf-1",
            category=FindingCategory.PIPELINE_MISCONFIG,
            severity=SeverityLevel.CRITICAL,
            title="Dangerous pull_request_target Trigger",
            description="Untrusted fork pull requests can execute malicious code with access to secrets.",
            file_path=".github/workflows/ci.yml",
            remediation_advice="Replace with pull_request"
        ),
        Finding(
            id="f-sec-1",
            category=FindingCategory.SECRET_EXPOSURE,
            severity=SeverityLevel.CRITICAL,
            title="AWS Access Key Secret Leak",
            description="High entropy AWS secret key exposed in environment script.",
            file_path="deploy/secrets.env",
            remediation_advice="Move credentials to AWS Secrets Manager"
        ),
        Finding(
            id="f-db-1",
            category=FindingCategory.DB_EXPOSURE,
            severity=SeverityLevel.HIGH,
            title="PostgreSQL Default Port Exposed",
            description="PostgreSQL port 5432 bound to 0.0.0.0 without SSL requirement.",
            file_path="docker-compose.yml",
            remediation_advice="Bind port to 127.0.0.1"
        )
    ]

    toxic_combos, graph = correlator.correlate(findings, target_name="test-payment-service")

    # 1. Verify Toxic Combinations
    assert len(toxic_combos) > 0
    assert graph.exploitability_index > 50.0

    # 2. Verify Blast Radius Assessment
    assert graph.blast_radius is not None
    br = graph.blast_radius
    assert br.score >= 60.0
    assert br.risk_tier in ("High Blast Radius", "Catastrophic Breach")
    assert "test-payment-service" in br.compromised_assets
    assert any("AWS" in c for c in br.cloud_impact)
    assert br.stolen_credentials_count == 1
    assert len(br.mitre_attack_techniques) > 0
    assert len(br.compliance_violations) > 0

    # 3. Verify Sequential Simulation Steps
    assert len(graph.simulation_steps) >= 3
    step1 = graph.simulation_steps[0]
    assert step1.step_number == 1
    assert "Initial Access" in step1.phase
    assert step1.technique_id in ("T1190", "T1195")

    # Final step exfiltration
    last_step = graph.simulation_steps[-1]
    assert "Exfiltration" in last_step.phase or "Crown Jewel" in last_step.title


def test_ai_remediator_workflow_hardening():
    """Verifies AI remediation produces valid code fix and unified diff for workflow exposures."""
    finding = Finding(
        id="f-wf-test",
        category=FindingCategory.PIPELINE_MISCONFIG,
        severity=SeverityLevel.CRITICAL,
        title="Dangerous pull_request_target Trigger",
        description="Untrusted fork pull requests can execute malicious code.",
        file_path=".github/workflows/deploy.yml",
        remediation_advice="Replace with pull_request"
    )

    original_workflow = """name: Deploy
on:
  pull_request_target:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
"""
    res = AIRemediator.generate_remediation(finding, original_content=original_workflow)

    assert res.finding_id == "f-wf-test"
    assert "pull_request_target" not in res.remediated_code
    assert "pull_request" in res.remediated_code
    assert "permissions:" in res.remediated_code
    assert "--- a/.github/workflows/deploy.yml" in res.unified_patch
    assert "+++ b/.github/workflows/deploy.yml" in res.unified_patch
    assert len(res.explanation) > 20
    assert res.test_command is not None


def test_ai_remediator_container_hardening():
    """Verifies AI remediation for Dockerfile adds unprivileged user and replaces :latest."""
    finding = Finding(
        id="f-iac-test",
        category=FindingCategory.IAC_CONTAINER,
        severity=SeverityLevel.HIGH,
        title="Container Runs as Root UID 0",
        description="Missing USER directive allows potential host escape.",
        file_path="Dockerfile",
        remediation_advice="Add USER 10001"
    )

    original_dockerfile = """FROM python:latest
WORKDIR /app
COPY . .
CMD ["python", "app.py"]
"""
    res = AIRemediator.generate_remediation(finding, original_content=original_dockerfile)

    assert "USER 10001" in res.remediated_code
    assert "latest" not in res.remediated_code or "Pinned" in res.remediated_code
    assert "diff" in res.unified_patch or "--- a/Dockerfile" in res.unified_patch


def test_github_service_repo_parsing():
    """Verifies parsing of various GitHub repository URL formats."""
    assert GitHubService.parse_repo_owner_name("owner/repo") == ("owner", "repo")
    assert GitHubService.parse_repo_owner_name("https://github.com/my-org/backend-api") == ("my-org", "backend-api")
    assert GitHubService.parse_repo_owner_name("https://github.com/my-org/backend-api.git") == ("my-org", "backend-api")
    assert GitHubService.parse_repo_owner_name("git@github.com:secure-team/service.git") == ("secure-team", "service")
    assert GitHubService.parse_repo_owner_name("invalid-url-format") is None


def test_security_copilot_contextual_qa():
    """Verifies that SecurityCopilot answers questions regarding blast radius, toxic combos, and fixes."""
    finding = Finding(
        id="f-secret-sample",
        category=FindingCategory.SECRET_EXPOSURE,
        severity=SeverityLevel.CRITICAL,
        title="Production Stripe API Secret Key Leaked",
        description="Secret key found in payments.py",
        file_path="src/payments.py",
        snippet="STRIPE_KEY = 'sk_live_12345'",
        remediation_advice="Load from STRIPE_API_KEY environment variable"
    )

    correlator = AttackCorrelator()
    toxic, graph = correlator.correlate([finding], target_name="payment-gateway")

    scan = ScanResult(
        scan_id="scan-copilot-test-1",
        target_path="payment-gateway",
        repo_name="payment-gateway",
        summary=ScanSummary(
            total_findings=1,
            critical_count=1,
            high_count=0,
            medium_count=0,
            low_count=0,
            info_count=0,
            pipeline_exposure_score=78.0,
            risk_grade="D",
            policy_passed=False,
            scan_duration_seconds=1.2,
            scanned_files_count=15
        ),
        findings=[finding],
        toxic_combinations=toxic,
        attack_graph=graph
    )

    # 1. Ask about blast radius
    res_blast = SecurityCopilot.chat("What is our blast radius?", scan=scan)
    assert "Blast Radius Assessment" in res_blast.reply
    assert len(res_blast.suggested_actions) > 0

    # 2. Ask about fixing
    res_fix = SecurityCopilot.chat("How do I fix this issue?", scan=scan)
    assert "payments.py" in res_fix.reply or "Remediation" in res_fix.reply

    # 3. Ask about specific finding
    res_finding = SecurityCopilot.chat("Tell me more", scan=scan, finding_id="f-secret-sample")
    assert "Finding Analysis: Production Stripe API Secret Key Leaked" in res_finding.reply


def test_remediation_and_copilot_rest_api_endpoints():
    """Tests the /api/remediation/ai-fix and /api/copilot/chat FastAPI endpoints."""
    # Create and save a mock scan
    finding = Finding(
        id="f-api-test-1",
        category=FindingCategory.PIPELINE_MISCONFIG,
        severity=SeverityLevel.HIGH,
        title="Unpinned GitHub Action in CI",
        description="Action does not pin a specific commit SHA.",
        file_path=".github/workflows/test.yml",
        remediation_advice="Pin action to full 40-character SHA"
    )
    correlator = AttackCorrelator()
    toxic, graph = correlator.correlate([finding], target_name="api-test-repo")

    scan = ScanResult(
        scan_id="scan-api-test-12345",
        target_path="/tmp/fake-repo",
        repo_name="api-test-repo",
        source_type=SourceType.LOCAL,
        target_type=TargetCategory.REPOSITORY,
        summary=ScanSummary(
            total_findings=1,
            critical_count=0,
            high_count=1,
            medium_count=0,
            low_count=0,
            info_count=0,
            pipeline_exposure_score=45.0,
            risk_grade="C",
            policy_passed=False,
            scan_duration_seconds=0.5,
            scanned_files_count=5
        ),
        findings=[finding],
        toxic_combinations=toxic,
        attack_graph=graph
    )
    storage.save_scan(scan)

    # 1. Test POST /api/remediation/ai-fix
    req_fix = AIRemediationRequest(
        scan_id=scan.scan_id,
        finding_id=finding.id
    )
    fix_res = asyncio.run(generate_ai_remediation(req_fix))
    assert fix_res.finding_id == finding.id
    assert fix_res.unified_patch is not None
    assert fix_res.explanation is not None

    # 2. Test POST /api/copilot/chat
    req_copilot = CopilotChatRequest(
        scan_id=scan.scan_id,
        message="What is our blast radius score?"
    )
    copilot_res = asyncio.run(copilot_chat_interaction(req_copilot))
    assert copilot_res.reply is not None
    assert "Blast Radius" in copilot_res.reply
