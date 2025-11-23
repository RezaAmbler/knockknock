"""Schedule model for recurring scans"""

from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey, Enum as SQLEnum
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

from web.database import Base


class ScheduleType(str, enum.Enum):
    CRON = "cron"
    INTERVAL = "interval"


class Schedule(Base):
    __tablename__ = "schedules"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)

    # Schedule configuration
    type = Column(SQLEnum(ScheduleType), default=ScheduleType.CRON, nullable=False)
    cron_expression = Column(String(100), nullable=True)  # "0 2 * * 0"
    interval_seconds = Column(Integer, nullable=True)      # For interval type
    timezone = Column(String(50), default="UTC", nullable=False)

    # Target configuration
    target_list_id = Column(Integer, ForeignKey("target_lists.id"), nullable=False)

    # Scan parameter overrides
    masscan_rate_override = Column(Integer, nullable=True)
    max_concurrent_override = Column(Integer, nullable=True)
    host_timeout_override = Column(Integer, nullable=True)

    # Nuclei configuration (per-schedule)
    nuclei_enabled = Column(Boolean, default=False)
    nuclei_severity = Column(String(50), nullable=True)  # "critical,high"
    nuclei_templates_path = Column(String(500), nullable=True)

    # Email configuration (per-schedule override)
    send_email = Column(Boolean, default=False)
    email_recipients_override = Column(Text, nullable=True)  # Comma-separated
    email_from_override = Column(String(200), nullable=True)

    # Schedule metadata
    enabled = Column(Boolean, default=True)
    next_run_utc = Column(DateTime, nullable=True)
    last_run_utc = Column(DateTime, nullable=True)

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Relationships
    target_list = relationship("TargetList", back_populates="schedules")
    created_by_user = relationship("User", back_populates="schedules")
    scan_runs = relationship("ScanRun", back_populates="schedule")
