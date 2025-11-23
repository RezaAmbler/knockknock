"""Artifact model - track scan output files"""

from sqlalchemy import Column, Integer, String, ForeignKey, BigInteger, Enum as SQLEnum
from sqlalchemy.orm import relationship
import enum

from web.database import Base


class ArtifactKind(str, enum.Enum):
    HTML = "html"
    MASSCAN_JSON = "masscan_json"
    NMAP_XML = "nmap_xml"
    NUCLEI_JSONL = "nuclei_jsonl"
    LOG = "log"
    SSH_AUDIT_JSON = "ssh_audit_json"


class Artifact(Base):
    __tablename__ = "artifacts"

    id = Column(Integer, primary_key=True)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id"), nullable=False)
    kind = Column(SQLEnum(ArtifactKind), nullable=False)
    path = Column(String(500), nullable=False)
    size_bytes = Column(BigInteger, nullable=True)

    # Relationships
    scan_run = relationship("ScanRun", back_populates="artifacts")
