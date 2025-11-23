"""Schedule schemas"""

from pydantic import BaseModel
from datetime import datetime
from typing import Optional


class ScheduleBase(BaseModel):
    name: str
    description: Optional[str] = None
    type: str = "cron"  # cron or interval
    cron_expression: Optional[str] = None
    interval_seconds: Optional[int] = None
    timezone: str = "UTC"
    target_list_id: int
    masscan_rate_override: Optional[int] = None
    max_concurrent_override: Optional[int] = None
    host_timeout_override: Optional[int] = None
    nuclei_enabled: bool = False
    nuclei_severity: Optional[str] = None
    nuclei_templates_path: Optional[str] = None
    send_email: bool = False
    email_recipients_override: Optional[str] = None
    email_from_override: Optional[str] = None
    enabled: bool = True


class ScheduleCreate(ScheduleBase):
    pass


class ScheduleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    cron_expression: Optional[str] = None
    interval_seconds: Optional[int] = None
    timezone: Optional[str] = None
    enabled: Optional[bool] = None


class ScheduleResponse(ScheduleBase):
    id: int
    created_at: datetime
    updated_at: datetime
    next_run_utc: Optional[datetime] = None
    last_run_utc: Optional[datetime] = None

    class Config:
        from_attributes = True
