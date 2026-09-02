"""
app/core/scheduler.py
Background task scheduler for automated continuous and recurring repository scans.
"""

import time
import uuid
import threading
import logging
from datetime import datetime, timedelta
from typing import Optional
from app.models.schemas import ScanRequest, ScheduledScan, SeverityLevel
from app.core.storage import storage

logger = logging.getLogger("ShieldCI.Scheduler")


class ScanScheduler:
    """Manages periodic, automated background scans for repositories."""

    def __init__(self, orchestrator=None):
        self.orchestrator = orchestrator
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def set_orchestrator(self, orchestrator):
        self.orchestrator = orchestrator

    def start(self):
        with self._lock:
            if not self._running:
                self._running = True
                self._thread = threading.Thread(target=self._run_loop, daemon=True, name="ShieldCIScheduler")
                self._thread.start()
                logger.info("Continuous scan scheduler started.")

    def stop(self):
        with self._lock:
            self._running = False

    def _run_loop(self):
        while self._running:
            try:
                self._check_and_run_schedules()
            except Exception as e:
                logger.error(f"Scheduler loop error: {e}")
            
            # Sleep in short increments to allow quick shutdown
            for _ in range(15):
                if not self._running:
                    break
                time.sleep(1)

    def _check_and_run_schedules(self):
        if not self.orchestrator:
            return

        schedules = storage.get_schedules()
        now = datetime.utcnow()

        for s in schedules:
            if not s.enabled:
                continue

            should_run = False
            if s.last_run_at is None:
                should_run = True
            else:
                elapsed = now - s.last_run_at
                if elapsed >= timedelta(minutes=s.interval_minutes):
                    should_run = True

            if should_run:
                self.run_scheduled_job(s.id)

    def run_scheduled_job(self, schedule_id: str):
        """Executes a single scheduled scan job in background."""
        schedules = storage.get_schedules()
        matched = next((s for s in schedules if s.id == schedule_id), None)
        if not matched or not self.orchestrator:
            return

        target = matched.target
        req = ScanRequest(
            target_path=target,
            repo_url=target if target.startswith(("http://", "https://", "git@", "ssh://", "github.com", "gitlab.com")) else None,
            branch=matched.branch
        )

        try:
            result = self.orchestrator.run_scan(req)
            status = "PASSED" if result.summary.policy_passed else "FAILED"
            storage.update_schedule_execution(
                sched_id=schedule_id,
                scan_id=result.scan_id,
                pes=result.summary.pipeline_exposure_score,
                grade=result.summary.risk_grade,
                status=status
            )
            logger.info(f"Scheduled scan completed for {target}: PES {result.summary.pipeline_exposure_score}")
        except Exception as e:
            logger.error(f"Scheduled scan failed for {target}: {e}")
            storage.update_schedule_execution(
                sched_id=schedule_id,
                scan_id="",
                pes=0.0,
                grade="ERROR",
                status=f"Error: {str(e)[:60]}"
            )

    def create_schedule(
        self,
        target: str,
        branch: Optional[str] = None,
        interval_minutes: int = 60,
        fail_on_severity: SeverityLevel = SeverityLevel.HIGH,
        max_allowed_pes: float = 60.0
    ) -> ScheduledScan:
        sched_id = str(uuid.uuid4())[:8]
        is_git = target.startswith(("http", "git@", "github", "gitlab", "bitbucket"))
        source_type = "git" if is_git else "local"

        saved = storage.save_schedule(
            sched_id=sched_id,
            target=target,
            source_type=source_type,
            branch=branch,
            interval_minutes=max(1, interval_minutes),
            fail_on_severity=fail_on_severity.value if hasattr(fail_on_severity, "value") else str(fail_on_severity),
            max_allowed_pes=max_allowed_pes
        )
        return saved

    def delete_schedule(self, sched_id: str) -> bool:
        return storage.delete_schedule(sched_id)


scheduler = ScanScheduler()
