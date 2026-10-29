import re
import idna
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator

class DnsRecordEntry(BaseModel):
    value: str
    ttl: Optional[int] = None

class DnsEnrichmentResult(BaseModel):
    enabled: bool
    performed: bool
    query_time_ms: Optional[float] = None
    resolver_status: str = "UNKNOWN" # NOERROR, NXDOMAIN, TIMEOUT, SERVFAIL, RESOLVER_ERROR
    nameservers: List[str] = Field(default_factory=list)
    records: Dict[str, List[DnsRecordEntry]] = Field(default_factory=dict)
    error: Optional[str] = None
    disclaimer: str = (
        "Live DNS lookups were executed using the system resolver. "
        "Syntactically valid hostnames may not exist in public DNS. "
        "Resolution failure does not imply malicious intent."
    )

class DnsAnalysisRequest(BaseModel):
    hostname: str = Field(..., description="Target hostname or FQDN submitted by user", min_length=1, max_length=253)
    enable_enrichment: bool = Field(default=False, description="Whether to perform live DNS record resolution")
    query_type: Optional[str] = Field(default="A", description="DNS record type to query")
    source: Optional[str] = Field(default="MANUAL", description="Event source origin")
    client_ip: Optional[str] = Field(default="127.0.0.1", description="Client IP making the query")

    @field_validator("hostname")
    @classmethod
    def validate_and_normalize_hostname(cls, v: str) -> str:
        raw = v.strip()
        if not raw:
            raise ValueError("Hostname cannot be empty.")
        if len(raw) > 253:
            raise ValueError("Hostname exceeds maximum RFC length of 253 characters.")

        # Clean trailing dot for FQDN
        candidate = raw.rstrip(".")

        # Handle IDN / Punycode conversion safely
        try:
            ascii_domain = idna.encode(candidate.lower()).decode("ascii")
        except Exception:
            ascii_domain = candidate.lower()

        labels = ascii_domain.split(".")
        if len(labels) == 1 and not labels[0]:
            raise ValueError("Hostname contains no valid labels.")

        for label in labels:
            if not label:
                raise ValueError("Hostname contains empty label between dots (e.g. 'example..com').")
            if len(label) > 63:
                raise ValueError(f"Label '{label[:20]}...' exceeds maximum RFC label length of 63 characters.")
            if not re.match(r"^[a-z0-9_\-]+$", label):
                raise ValueError(f"Label '{label}' contains illegal characters. Only alphanumeric, hyphen, and underscore are valid.")

        return raw  # Preserve raw submitted string; normalization will be computed separately


class DnsFeatureSet(BaseModel):
    hostname_length: int
    num_labels: int
    subdomain_depth: int
    label_lengths: List[int] = Field(default_factory=list)
    max_label_length: int
    avg_label_length: float
    shannon_entropy: float
    digit_ratio: float
    hex_ratio: float
    vowel_ratio: float
    consonant_ratio: float
    consecutive_consonant_max: int
    hyphen_count: int
    underscore_count: int
    repeated_char_ratio: float
    has_known_tld: bool


class ReasonFactor(BaseModel):
    factor: str
    description: str
    weight: str # "HIGH", "MEDIUM", "LOW"


class StructuredRecommendation(BaseModel):
    summary: str
    detected: str
    significance: str
    next_steps: str
    supporting_evidence: str
    missing_information: str


class DnsAnalysisResponse(BaseModel):
    model_config = {"protected_namespaces": ()}

    id: Optional[int] = None
    submitted_hostname: str
    normalized_hostname: str
    is_suspicious: bool
    risk_score: float # 0.0 to 100.0
    severity: str # LOW (0-24), MODERATE (25-49), HIGH (50-74), CRITICAL (75-100)
    classification: str # "No strong suspicious indicators detected", "Moderate risk", "Suspicious / High-risk", "Critical risk", or "Insufficient evidence"
    
    confidence: float # Calibrated probability of prediction (0.50 to 1.00)
    confidence_display: str # e.g. "98.5% (High Certainty)" or "Confidence unavailable"
    uncertainty_status: str # "CALIBRATED_CONFIDENT", "MODERATE_UNCERTAINTY", "OUT_OF_DISTRIBUTION", "INSUFFICIENT_EVIDENCE"
    
    features: DnsFeatureSet
    reasons: List[ReasonFactor]
    enrichment: Optional[DnsEnrichmentResult] = None
    
    flow_features_available: bool = False
    flow_features_notice: str = (
        "Flow-based features (e.g. query frequency, byte variance, burstiness) are unavailable in static hostname analysis. "
        "Log ingestion mode or Zeek packet logs are required to evaluate temporal flow behavior."
    )
    
    limitations: str = (
        "Lexical feature analysis alone cannot conclusively establish malicious intent. "
        "Adversaries can use low-entropy dictionary subdomains, and legitimate cloud services can encode tracking tokens. "
        "Attribution requires correlation with traffic volume and authoritative responses."
    )
    
    timestamp: datetime
    source: str
    query_type: str
    client_ip: Optional[str] = None
    model_version: str = "GradientBoosting-v2.0-FlowLexical"
    recommendation: str
    structured_recommendation: Optional[StructuredRecommendation] = None


class ThreatAlertSchema(BaseModel):
    id: int
    alert_uid: str
    analysis_id: Optional[int]
    hostname: str
    risk_score: float
    severity: str
    status: str
    source: str
    reasons: List[ReasonFactor]
    notes: Optional[str]
    timestamp: datetime
    acknowledged_at: Optional[datetime]
    resolved_at: Optional[datetime]

    class Config:
        from_attributes = True


class AlertStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(OPEN|ACKNOWLEDGED|RESOLVED)$")
    notes: Optional[str] = None


class AlertNotesUpdate(BaseModel):
    notes: str = Field(..., max_length=2000)


class BatchAnalysisItemResult(BaseModel):
    row_number: int
    submitted_hostname: str
    normalized_hostname: str
    is_suspicious: bool
    risk_score: float
    severity: str
    classification: str
    confidence_display: str
    status: str = "SUCCESS"
    error: Optional[str] = None


class BatchAnalysisResponse(BaseModel):
    total_processed: int
    valid_count: int
    invalid_count: int
    suspicious_count: int
    high_risk_count: int
    detected_column: str
    results: List[BatchAnalysisItemResult]


class DashboardStats(BaseModel):
    model_config = {"protected_namespaces": ()}
    total_queries: int
    suspicious_queries: int
    high_risk_queries: int
    critical_queries: int
    detection_rate_pct: float
    open_alerts_count: int
    monitoring_status: str
    model_status: str
    database_status: str


class ActivityPoint(BaseModel):
    time_label: str
    total: int
    suspicious: int


class RiskDistribution(BaseModel):
    low: int
    medium: int # maps to moderate
    high: int
    critical: int


class TopSuspiciousDomain(BaseModel):
    hostname: str
    count: int
    max_risk_score: float
    severity: str
    last_detected: datetime


class ExternalEventPayload(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=253)
    query_type: Optional[str] = Field(default="A")
    client_ip: Optional[str] = Field(default="10.0.0.1")
    timestamp: Optional[datetime] = None
    log_source_id: Optional[str] = Field(default="default-collector")


class ExternalBatchEventPayload(BaseModel):
    events: List[ExternalEventPayload]


class ModelEvaluationMetrics(BaseModel):
    model_config = {"protected_namespaces": ()}
    model_type: str
    model_version: str
    trained_at: str
    dataset_source: str
    total_samples: int
    train_samples: int
    val_samples: int
    test_samples: int
    legitimate_samples: int
    tunneling_samples: int
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    roc_auc: float
    confusion_matrix: Dict[str, int] # tn, fp, fn, tp
    feature_importance: Dict[str, float]
    disclaimer: str


class SystemSettingsSchema(BaseModel):
    alert_threshold: float = 50.0 # High risk threshold
    monitoring_interval_ms: int = 1500
    dns_enrichment_enabled: bool = False
    deduplication_window_mins: int = 15
    demo_speed_ms: int = 2000
    ingestion_api_key_masked: str = "shield-***"
