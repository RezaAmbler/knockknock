"""Target list - group targets together"""

from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime

from web.database import Base


class TargetList(Base):
    __tablename__ = "target_lists"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    items = relationship("TargetListItem", back_populates="target_list", cascade="all, delete-orphan")
    schedules = relationship("Schedule", back_populates="target_list")


class TargetListItem(Base):
    """Many-to-many association between target lists and targets"""
    __tablename__ = "target_list_items"

    id = Column(Integer, primary_key=True)
    target_list_id = Column(Integer, ForeignKey("target_lists.id"), nullable=False)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    added_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    target_list = relationship("TargetList", back_populates="items")
    target = relationship("Target", back_populates="target_list_items")
