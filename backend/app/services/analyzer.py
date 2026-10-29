import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models import DnsAnalysis, SystemSetting
from app.ml.model import model_manager
from app.services.dns_enrichment import resolve_dns_records
from app.services.alert_service import maybe_create_alert

def is_dns_enrichment_enabled(db: Session) -> bool:
    setting = db.query(SystemSetting).filter(SystemSetting.key == "dns_enrichment_enabled").first()
    if setting:
        return setting.value.lower() in ("true", "1", "yes")
    return False

from app.schemas import DnsAnalysisRequest

def analyze_and_record(
    db: Session,
    hostname: str,
    enable_enrichment: bool = False,
    query_type: str = "A",
    source: str = "MANUAL",
    client_ip: Optional[str] = "127.0.0.1"
) -> Dict[str, Any]:
    """
    Executes lexical feature extraction, Gradient-Boosted classification,
    optional real DNS resolution with TTLs, database persistence, and threat alerts.
    """
    # Validate hostname syntax
    validated_hostname = DnsAnalysisRequest.validate_and_normalize_hostname(hostname)

    # 1. Gradient-Boosted Classification & Feature Extraction
    pred = model_manager.predict(validated_hostname)

    # 2. Real DNS Record Resolution (if requested or enabled in settings)
    enrichment_result = None
    system_enrichment = is_dns_enrichment_enabled(db)
    if enable_enrichment or system_enrichment:
        enrichment_result = resolve_dns_records(pred["normalized_hostname"])

    # 3. Persist to Database
    now = datetime.now(timezone.utc)
    analysis = DnsAnalysis(
        hostname=pred["submitted_hostname"],
        is_suspicious=pred["is_suspicious"],
        risk_score=pred["risk_score"],
        severity=pred["severity"],
        confidence=pred["confidence"],
        features_json=json.dumps(pred["features"]),
        reasons_json=json.dumps(pred["reasons"]),
        enrichment_json=json.dumps(enrichment_result) if enrichment_result else None,
        source=source,
        query_type=query_type,
        client_ip=client_ip,
        timestamp=now
    )
    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    # 4. Threat Alert Trigger (Alert created if risk meets threshold, e.g. >= 50 High or >= 75 Critical)
    maybe_create_alert(db, analysis, pred["reasons"])

    return {
        "id": analysis.id,
        "submitted_hostname": pred["submitted_hostname"],
        "normalized_hostname": pred["normalized_hostname"],
        "is_suspicious": analysis.is_suspicious,
        "risk_score": analysis.risk_score,
        "severity": analysis.severity,
        "classification": pred["classification"],
        "confidence": pred["confidence"],
        "confidence_display": pred["confidence_display"],
        "uncertainty_status": pred["uncertainty_status"],
        "features": pred["features"],
        "reasons": pred["reasons"],
        "enrichment": enrichment_result,
        "flow_features_available": False,
        "flow_features_notice": (
            "Flow features (inter-arrival timing, query burst frequency, total octet variance) "
            "require packet stream logs (Zeek/Syslog) and are not inferred from static hostnames alone."
        ),
        "limitations": (
            "Lexical classification provides indicative scoring. "
            "Attribution requires correlation with authoritative DNS answers, IP reputation, and traffic volume."
        ),
        "timestamp": analysis.timestamp,
        "source": analysis.source,
        "query_type": analysis.query_type,
        "client_ip": analysis.client_ip,
        "model_version": pred["model_version"],
        "recommendation": pred["recommendation"],
        "structured_recommendation": pred.get("structured_recommendation")
    }
