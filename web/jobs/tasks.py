"""Celery tasks for scan execution"""

from celery import Task
from sqlalchemy.orm import Session
from datetime import datetime
import logging
import json

from web.jobs.celery_app import celery_app
from web.jobs.scanner_wrapper import run_scan_job
from web.database import SessionLocal
from web.models.scan_run import ScanRun, ScanStatus
from web.models.artifact import Artifact
from web.models.schedule import Schedule
from web.models.target import Target

logger = logging.getLogger(__name__)


class DatabaseTask(Task):
    """Base task that provides database session"""
    _db = None

    @property
    def db(self) -> Session:
        if self._db is None:
            self._db = SessionLocal()
        return self._db

    def after_return(self, *args, **kwargs):
        if self._db is not None:
            self._db.close()
            self._db = None


@celery_app.task(base=DatabaseTask, bind=True)
def execute_scan(self, scan_run_id: int):
    """
    Execute a scan job

    Args:
        scan_run_id: ScanRun database ID
    """
    db = self.db

    logger.info(f"[scan:{scan_run_id}] Starting scan execution")

    # Load scan run
    scan_run = db.query(ScanRun).filter(ScanRun.id == scan_run_id).first()
    if not scan_run:
        logger.error(f"[scan:{scan_run_id}] Scan run not found")
        return

    # Update status
    scan_run.status = ScanStatus.RUNNING
    scan_run.started_at = datetime.utcnow()
    db.commit()

    try:
        # Load targets from schedule's target list
        if scan_run.schedule_id:
            schedule = db.query(Schedule).filter(Schedule.id == scan_run.schedule_id).first()
            targets = [item.target for item in schedule.target_list.items]

            # Build overrides from schedule
            overrides = {}
            if schedule.masscan_rate_override:
                overrides['masscan_rate'] = schedule.masscan_rate_override
            if schedule.max_concurrent_override:
                overrides['max_concurrent'] = schedule.max_concurrent_override
            if schedule.host_timeout_override:
                overrides['host_timeout'] = schedule.host_timeout_override

            # Email configuration
            email_override = {
                'send_email': schedule.send_email,
                'recipients': schedule.email_recipients_override.split(',') if schedule.email_recipients_override else None,
                'from_address': schedule.email_from_override
            }

            schedule_meta = {
                'schedule_id': schedule.id,
                'schedule_name': schedule.name
            }
        else:
            # Ad-hoc scan - targets from config snapshot
            config = json.loads(scan_run.config_snapshot or '{}')
            target_ids = config.get('target_ids', [])
            targets = db.query(Target).filter(Target.id.in_(target_ids)).all()
            overrides = config.get('overrides', {})
            email_override = config.get('email', {})
            schedule_meta = {}

        # Execute scan
        result = run_scan_job(
            targets=targets,
            overrides=overrides,
            schedule_meta=schedule_meta,
            email_override=email_override
        )

        if result.success:
            # Update scan run
            scan_run.status = ScanStatus.SUCCESS
            scan_run.output_dir = str(result.output_dir)
            scan_run.html_report_path = str(result.html_report_path)
            scan_run.legacy_run_id = result.legacy_run_id
            scan_run.run_uuid = result.run_uuid

            # Create artifact records
            for artifact_data in result.artifacts:
                artifact = Artifact(
                    scan_run_id=scan_run.id,
                    kind=artifact_data['kind'],
                    path=artifact_data['path'],
                    size_bytes=artifact_data['size_bytes']
                )
                db.add(artifact)
        else:
            scan_run.status = ScanStatus.ERROR
            scan_run.error_message = result.error_message

        scan_run.finished_at = datetime.utcnow()
        db.commit()

        logger.info(f"[scan:{scan_run_id}] Completed with status={scan_run.status}")

    except Exception as e:
        logger.error(f"[scan:{scan_run_id}] Failed: {e}", exc_info=True)
        scan_run.status = ScanStatus.ERROR
        scan_run.error_message = str(e)
        scan_run.finished_at = datetime.utcnow()
        db.commit()


@celery_app.task(base=DatabaseTask, bind=True)
def process_schedules(self):
    """
    Process due schedules and enqueue scans

    Called by Celery Beat every minute
    """
    db = self.db

    now = datetime.utcnow()

    # Find enabled schedules that are due
    schedules = db.query(Schedule).filter(
        Schedule.enabled == True,
        Schedule.next_run_utc <= now
    ).all()

    for schedule in schedules:
        logger.info(f"[schedule:{schedule.id}] Processing due schedule: {schedule.name}")

        # Create scan run
        scan_run = ScanRun(
            schedule_id=schedule.id,
            initiated_by_id=schedule.created_by_id,
            status=ScanStatus.QUEUED,
            config_snapshot="{}"  # Schedule has overrides built-in
        )
        db.add(scan_run)
        db.flush()  # Get scan_run.id

        # Enqueue scan
        execute_scan.delay(scan_run.id)

        # Update schedule
        schedule.last_run_utc = now

        # Calculate next_run_utc based on cron/interval + timezone
        from web.jobs.scheduler import calculate_next_run
        schedule.next_run_utc = calculate_next_run(schedule)

        db.commit()

        logger.info(f"[schedule:{schedule.id}] Enqueued scan_run {scan_run.id}")
