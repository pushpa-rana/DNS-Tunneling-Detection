import uuid
import json
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models import ThreatAlert, DnsAnalysis, SystemSetting

def get_alert_threshold(db: Session) -> float:
    setting = db.query(SystemSetting).filter(SystemSetting.key == "alert_threshold").first()
    if setting:
        try:
            return float(setting.value)
        except ValueError:
            pass
    return 50.0

def get_dedup_window_mins(db: Session) -> int:
    setting = db.query(SystemSetting).filter(SystemSetting.key == "deduplication_window_mins").first()
    if setting:
        try:
            return int(setting.value)
        except ValueError:
            pass
    return 15

def maybe_create_alert(
    db: Session,
    analysis: DnsAnalysis,
    reasons: list
) -> Optional[ThreatAlert]:
    """
    Evaluates whether the analysis warrants a security alert based on the configured threshold.
    Applies configurable deduplication so identical hostnames in a time window update rather than duplicate.
    """
    threshold = get_alert_threshold(db)
    if analysis.risk_score < threshold:
        return None

    dedup_window_mins = get_dedup_window_mins(db)
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=dedup_window_mins)

    # Check for existing open or acknowledged alert for the same hostname within deduplication window
    existing_alert = (
        db.query(ThreatAlert)
        .filter(
            ThreatAlert.hostname == analysis.hostname,
            ThreatAlert.status.in_(["OPEN", "ACKNOWLEDGED"]),
            ThreatAlert.timestamp >= cutoff
        )
        .order_by(desc(ThreatAlert.timestamp))
        .first()
    )

    if existing_alert:
        # Update existing alert with higher risk score if applicable and link new analysis
        if analysis.risk_score > existing_alert.risk_score:
            existing_alert.risk_score = analysis.risk_score
            existing_alert.severity = analysis.severity
        existing_alert.analysis_id = analysis.id
        db.commit()
        db.refresh(existing_alert)
        return existing_alert

    # Create new alert
    alert = ThreatAlert(
        alert_uid=f"ALT-{uuid.uuid4().hex[:8].upper()}",
        analysis_id=analysis.id,
        hostname=analysis.hostname,
        risk_score=analysis.risk_score,
        severity=analysis.severity,
        status="OPEN",
        source=analysis.source,
        reasons_json=json.dumps(reasons),
        timestamp=datetime.now(timezone.utc)
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert
