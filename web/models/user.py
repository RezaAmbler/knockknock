"""User model with authentication"""

from sqlalchemy import Column, Integer, String, DateTime, Enum as SQLEnum
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

from web.database import Base


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    USER = "user"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(SQLEnum(UserRole), default=UserRole.USER, nullable=False)
    timezone = Column(String(50), default="UTC", nullable=False)  # IANA timezone
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    scan_runs = relationship("ScanRun", back_populates="initiated_by_user")
    schedules = relationship("Schedule", back_populates="created_by_user")
