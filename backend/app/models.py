from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey, Index
from sqlalchemy.orm import relationship
from app.database import Base

def utcnow():
    return datetime.now(timezone.utc)

class DnsAnalysis(Base):
    __tablename__ = "dns_analyses"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(512), index=True, nullable=False)
    is_suspicious = Column(Boolean, default=False, nullable=False, index=True)
    risk_score = Column(Float, nullable=False, index=True) # 0.0 to 100.0
    severity = Column(String(32), nullable=False, index=True) # LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(Float, default=0.0) # ML probability
    
    # Serialized JSON fields
    features_json = Column(Text, nullable=False) # JSON dict of lexical features
    reasons_json = Column(Text, nullable=True) # JSON list of explanation factors
    enrichment_json = Column(Text, nullable=True) # JSON dict of DNS records (A, AAAA, MX, etc.)
    
    source = Column(String(64), default="MANUAL", index=True) # MANUAL, BATCH, DEMO_STREAM, CSV_REPLAY, API_INGESTION
    query_type = Column(String(16), default="A")
    client_ip = Column(String(64), nullable=True)
    timestamp = Column(DateTime, default=utcnow, index=True)

    alerts = relationship("ThreatAlert", back_populates="analysis", cascade="all, delete-orphan")


class ThreatAlert(Base):
    __tablename__ = "threat_alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_uid = Column(String(64), unique=True, index=True, nullable=False)
    analysis_id = Column(Integer, ForeignKey("dns_analyses.id", ondelete="SET NULL"), nullable=True)
    hostname = Column(String(512), index=True, nullable=False)
    risk_score = Column(Float, nullable=False)
    severity = Column(String(32), nullable=False, index=True)
    status = Column(String(32), default="OPEN", index=True) # OPEN, ACKNOWLEDGED, RESOLVED
    
    source = Column(String(64), default="MANUAL")
    reasons_json = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)
    
    timestamp = Column(DateTime, default=utcnow, index=True)
    acknowledged_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)

    analysis = relationship("DnsAnalysis", back_populates="alerts")


class SystemSetting(Base):
    __tablename__ = "system_settings"

    key = Column(String(64), primary_key=True, index=True)
    value = Column(String(512), nullable=False)
    description = Column(String(256), nullable=True)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class MonitoringSession(Base):
    __tablename__ = "monitoring_sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(64), unique=True, index=True)
    mode = Column(String(32), nullable=False) # DEMO_STREAM, CSV_REPLAY, EXTERNAL_INGEST
    status = Column(String(32), default="STOPPED") # RUNNING, PAUSED, STOPPED
    total_events = Column(Integer, default=0)
    suspicious_events = Column(Integer, default=0)
    started_at = Column(DateTime, default=utcnow)
    stopped_at = Column(DateTime, nullable=True)
