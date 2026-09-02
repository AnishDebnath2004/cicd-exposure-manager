"""app/core/scoring.py"""
from typing import List
from app.models.schemas import Finding, SeverityLevel, ScanSummary
from app.config import settings

class ExposureScorer:
    """Calculates the Pipeline Exposure Score (PES: 0-100) and risk grades."""

    @classmethod
    def get_severity_weights(cls):
        return {
            SeverityLevel.CRITICAL: settings.scoring_weights.CRITICAL,
            SeverityLevel.HIGH: settings.scoring_weights.HIGH,
            SeverityLevel.MEDIUM: settings.scoring_weights.MEDIUM,
            SeverityLevel.LOW: settings.scoring_weights.LOW,
            SeverityLevel.INFO: settings.scoring_weights.INFO
        }

    @classmethod
    def calculate_summary(cls, findings: List[Finding], duration: float, file_count: int, fail_severity: SeverityLevel, max_pes: float) -> ScanSummary:
        crit = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
        high = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
        med = sum(1 for f in findings if f.severity == SeverityLevel.MEDIUM)
        low = sum(1 for f in findings if f.severity == SeverityLevel.LOW)
        info = sum(1 for f in findings if f.severity == SeverityLevel.INFO)

        weights = cls.get_severity_weights()

        # Raw Score calculation
        raw_score = (
            crit * weights.get(SeverityLevel.CRITICAL, 25.0) +
            high * weights.get(SeverityLevel.HIGH, 12.0) +
            med * weights.get(SeverityLevel.MEDIUM, 4.0) +
            low * weights.get(SeverityLevel.LOW, 1.0)
        )

        # Normalized Pipeline Exposure Score (0 to 100)
        pes = min(100.0, round(raw_score, 1))

        # Risk Grade Assignment
        if pes == 0:
            grade = "A+ (Hardened)"
        elif pes <= 15:
            grade = "A (Low Risk)"
        elif pes <= 35:
            grade = "B (Moderate)"
        elif pes <= 60:
            grade = "C (Elevated)"
        elif pes <= 80:
            grade = "D (High Risk)"
        else:
            grade = "F (Critical Exposure)"

        # Policy Gate Determination
        policy_passed = True
        if pes > max_pes:
            policy_passed = False

        if fail_severity == SeverityLevel.CRITICAL and crit > 0:
            policy_passed = False
        elif fail_severity == SeverityLevel.HIGH and (crit > 0 or high > 0):
            policy_passed = False
        elif fail_severity == SeverityLevel.MEDIUM and (crit > 0 or high > 0 or med > 0):
            policy_passed = False

        return ScanSummary(
            total_findings=len(findings),
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low,
            info_count=info,
            pipeline_exposure_score=pes,
            risk_grade=grade,
            policy_passed=policy_passed,
            scan_duration_seconds=round(duration, 3),
            scanned_files_count=file_count
        )