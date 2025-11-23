"""Target model with IP/DNS/friendly name support"""

from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime

from web.database import Base


class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True)

    # Address fields (at least one required)
    ip_address = Column(String(45), nullable=True, index=True)  # IPv4/IPv6
    dns_name = Column(String(255), nullable=True, index=True)

    # Display information
    friendly_name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    tags = Column(Text, nullable=True)  # JSON array: ["production", "firewall"]

    # Validation
    is_valid = Column(Boolean, default=True)
    last_validated_at = Column(DateTime, nullable=True)
    validation_error = Column(String(500), nullable=True)

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    target_list_items = relationship("TargetListItem", back_populates="target")
