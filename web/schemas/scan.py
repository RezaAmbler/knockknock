"""Scan schemas"""

from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List


class ScanOverrides(BaseModel):
    masscan_rate: Optional[int] = None
    max_concurrent: Optional[int] = None
    host_timeout: Optional[int] = None


class ScanCreate(BaseModel):
    target_ids: List[int]
    overrides: Optional[ScanOverrides] = None
    send_email: bool = False
    email_recipients: Optional[List[str]] = None
    email_from: Optional[str] = None


class ScanResponse(BaseModel):
    id: int
    run_uuid: str
    status: str
    schedule_id: Optional[int] = None
    initiated_by_id: int
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error_message: Optional[str] = None
    output_dir: Optional[str] = None
    html_report_path: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    total: int
    scans: List[ScanResponse]
