from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone, timedelta
import random

from app.database import get_db
from app.models import SystemSetting, DnsAnalysis
from app.config import settings
from app.services.analyzer import analyze_and_record

router = APIRouter(prefix="/settings", tags=["Settings"])

class SettingsUpdateRequest(BaseModel):
    alert_threshold: Optional[float] = Field(None, ge=10.0, le=99.0)
    monitoring_interval_ms: Optional[int] = Field(None, ge=200, le=10000)
    dns_enrichment_enabled: Optional[bool] = None
    deduplication_window_mins: Optional[int] = Field(None, ge=1, le=1440)
    demo_speed_ms: Optional[int] = Field(None, ge=200, le=10000)

@router.get("")
def get_system_settings(db: Session = Depends(get_db)):
    # Helper to get from DB with fallback
    def _get(key: str, default: str) -> str:
        row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
        return row.value if row else default

    alert_thresh = float(_get("alert_threshold", str(settings.DEFAULT_ALERT_THRESHOLD)))
    enrichment_en = _get("dns_enrichment_enabled", "false").lower() in ("true", "1")
    dedup_win = int(_get("deduplication_window_mins", "15"))
    demo_speed = int(_get("demo_speed_ms", "1500"))

    # Mask API key
    key = settings.DEFAULT_API_KEY
    masked_key = f"{key[:7]}...{key[-4:]}" if len(key) >= 12 else "shield-***"

    return {
        "alert_threshold": alert_thresh,
        "dns_enrichment_enabled": enrichment_en,
        "deduplication_window_mins": dedup_win,
        "demo_speed_ms": demo_speed,
        "ingestion_api_key_masked": masked_key,
        "ingestion_api_key_full": key,
        "database_url": settings.DATABASE_URL,
        "resolver_timeout_sec": settings.DNS_ENRICHMENT_TIMEOUT_SEC,
        "model_version": "RF-v1.0-Lexical"
    }

@router.put("")
def update_system_settings(
    payload: SettingsUpdateRequest,
    db: Session = Depends(get_db)
):
    def _set(key: str, val: str, desc: str):
        row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
        if not row:
            row = SystemSetting(key=key, value=val, description=desc)
            db.add(row)
        else:
            row.value = val
            row.updated_at = datetime.now(timezone.utc)

    if payload.alert_threshold is not None:
        _set("alert_threshold", str(payload.alert_threshold), "Threat alert score threshold (0-100)")
    if payload.dns_enrichment_enabled is not None:
        _set("dns_enrichment_enabled", "true" if payload.dns_enrichment_enabled else "false", "External DNS resolver enrichment toggle")
    if payload.deduplication_window_mins is not None:
        _set("deduplication_window_mins", str(payload.deduplication_window_mins), "Alert deduplication window in minutes")
    if payload.demo_speed_ms is not None:
        _set("demo_speed_ms", str(payload.demo_speed_ms), "Live monitoring demo stream interval in ms")

    db.commit()
    return {"status": "SUCCESS", "message": "Settings updated successfully."}

@router.post("/seed-demo")
def seed_demo_telemetry(db: Session = Depends(get_db)):
    """
    Seeds a representative set of 25 benign and tunneling events with realistic timestamps
    to immediately showcase full dashboard, explorer, and threat alert capabilities.
    """
    sample_records = [
        # Legitimate benign
        ("www.google.com", "DEMO_STREAM", "192.168.1.105"),
        ("api.stripe.com", "DEMO_STREAM", "192.168.1.110"),
        ("mail.microsoft.com", "DEMO_STREAM", "192.168.1.115"),
        ("cdn.cloudflare.net", "DEMO_STREAM", "192.168.1.102"),
        ("auth.okta.com", "DEMO_STREAM", "192.168.1.130"),
        ("github.com", "DEMO_STREAM", "192.168.1.140"),
        ("static-assets.amazon.com", "DEMO_STREAM", "192.168.1.105"),
        ("portal.azure.com", "DEMO_STREAM", "192.168.1.155"),
        ("docs.python.org", "DEMO_STREAM", "192.168.1.120"),
        ("us-east-1.prod.aws.com", "DEMO_STREAM", "192.168.1.108"),
        ("slack.com", "DEMO_STREAM", "192.168.1.105"),
        ("zoom.us", "DEMO_STREAM", "192.168.1.105"),
        ("developer.mozilla.org", "DEMO_STREAM", "192.168.1.125"),
        ("registry.npmjs.org", "DEMO_STREAM", "192.168.1.140"),
        ("api.cloudflare.com", "DEMO_STREAM", "192.168.1.102"),

        # High-risk / Critical Tunneling
        ("a8f92k7m3x9q2m10v8z4p19k3m.tunnel.covertc2.biz", "DEMO_STREAM", "192.168.1.200"),
        ("dnscat.01823947bca8921df87349120.c2.targetdomain.net", "DEMO_STREAM", "192.168.1.201"),
        ("dGhpcy1pcy1hLXNlY3JldC1leGZpbHRyYXRpb24tcGF5bG9hZA.data.exfil-dns.io", "DEMO_STREAM", "192.168.1.200"),
        ("9f82kd0281b37492cfa77192aa01.beacon.attacker-c2.xyz", "DEMO_STREAM", "192.168.1.205"),
        ("01fe89a24cb9018e3810f274a1.ns1.tunnel-server.net", "DEMO_STREAM", "192.168.1.200"),
        ("mfxwi3dbmuwtemjqnrxwo3theb2g64tfebrw63tfnrswe.iodine-dns.info", "DEMO_STREAM", "192.168.1.210"),
        ("c771a09ef281b93802ad817e923.stage.covert-channel.biz", "DEMO_STREAM", "192.168.1.205"),
        ("stealth-chunk-01928374910283740192.exfil.data-drop.top", "DEMO_STREAM", "192.168.1.200")
    ]

    added = 0
    now = datetime.now(timezone.utc)
    for i, (domain, src, ip) in enumerate(sample_records):
        # Stagger timestamps across past 6 hours
        res = analyze_and_record(
            db=db,
            hostname=domain,
            enable_enrichment=False,
            source=src,
            client_ip=ip
        )
        # Update timestamp to distribute along activity timeline
        delta_mins = i * 15
        db_rec = db.query(DnsAnalysis).filter(DnsAnalysis.id == res["id"]).first()
        if db_rec:
            db_rec.timestamp = now - timedelta(minutes=delta_mins)
            if db_rec.alerts:
                for alt in db_rec.alerts:
                    alt.timestamp = db_rec.timestamp
            added += 1

    db.commit()
    return {"status": "SUCCESS", "message": f"Successfully seeded {added} realistic demonstration records."}
