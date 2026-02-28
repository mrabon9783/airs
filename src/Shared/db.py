from datetime import datetime
from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

from .config import settings

Base = declarative_base()
engine = create_engine(settings.database_url, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(Integer, primary_key=True)
    started_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(32), nullable=False, default="running")
    summary = Column(JSON, nullable=False, default=dict)
    warnings = Column(JSON, nullable=False, default=list)

    findings = relationship("Finding", back_populates="scan_run", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False)
    entity_kind = Column(String(32), nullable=False)  # app|servicePrincipal
    entity_id = Column(String(128), nullable=False)
    display_name = Column(String(256), nullable=True)
    severity = Column(String(16), nullable=False)
    category = Column(String(64), nullable=False)
    type = Column(String(64), nullable=False)
    description = Column(Text, nullable=False)
    metadata_json = Column("metadata", JSON, nullable=False, default=dict)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    scan_run = relationship("ScanRun", back_populates="findings")


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
