"""Scan run model - extends existing storage.py runs table"""

from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Enum as SQLEnum
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
import uuid as uuid_lib

from web.database import Base


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCESS = "success"
    ERROR = "error"
    CANCELLED = "cancelled"


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(Integer, primary_key=True)
    run_uuid = Column(String(36), unique=True, nullable=False, index=True, default=lambda: str(uuid_lib.uuid4()))

    # Source
    schedule_id = Column(Integer, ForeignKey("schedules.id"), nullable=True)  # Null = ad-hoc
    initiated_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Status
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.QUEUED, nullable=False)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    # Configuration snapshot (JSON)
    config_snapshot = Column(Text, nullable=True)

    # File paths
    output_dir = Column(String(500), nullable=True)
    html_report_path = Column(String(500), nullable=True)
    log_path = Column(String(500), nullable=True)

    # Link to existing storage.py runs table
    legacy_run_id = Column(Integer, nullable=True)  # FK to runs.id from storage.py

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    schedule = relationship("Schedule", back_populates="scan_runs")
    initiated_by_user = relationship("User", back_populates="scan_runs")
    artifacts = relationship("Artifact", back_populates="scan_run", cascade="all, delete-orphan")
