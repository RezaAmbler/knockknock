"""Celery application configuration"""

from celery import Celery
from celery.schedules import crontab

from web.config import settings

celery_app = Celery(
    "knockknock",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["web.jobs.tasks"]
)

# Configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=7200,  # 2 hours max per scan
    worker_prefetch_multiplier=1,
)

# Celery Beat schedule (for recurring scans)
celery_app.conf.beat_schedule = {
    'process-schedules': {
        'task': 'web.jobs.tasks.process_schedules',
        'schedule': crontab(minute='*'),  # Every minute
    },
}
