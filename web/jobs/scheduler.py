"""Schedule calculation utilities"""

from datetime import datetime, timedelta
from croniter import croniter
from web.models.schedule import Schedule, ScheduleType


def calculate_next_run(schedule: Schedule) -> datetime:
    """
    Calculate next run time for a schedule

    Args:
        schedule: Schedule object

    Returns:
        Next run time in UTC
    """
    now = datetime.utcnow()

    if schedule.type == ScheduleType.CRON:
        # Use croniter to calculate next run from cron expression
        if not schedule.cron_expression:
            return now + timedelta(days=1)  # Default to daily

        cron = croniter(schedule.cron_expression, now)
        return cron.get_next(datetime)

    elif schedule.type == ScheduleType.INTERVAL:
        # Simple interval-based scheduling
        if not schedule.interval_seconds:
            return now + timedelta(days=1)  # Default to daily

        return now + timedelta(seconds=schedule.interval_seconds)

    else:
        # Default to daily
        return now + timedelta(days=1)
