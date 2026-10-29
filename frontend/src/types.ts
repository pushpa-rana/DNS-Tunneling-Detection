export type SeverityLevel = 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
export type AlertStatus = 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED';
export type EventSource = 'MANUAL' | 'BATCH' | 'DEMO_STREAM' | 'CSV_REPLAY' | 'API_INGESTION';

export interface DnsFeatureSet {
  hostname_length: number;
  num_labels: number;
  subdomain_depth: number;
  label_lengths?: number[];
  max_label_length: number;
  avg_label_length: number;
  shannon_entropy: number;
  digit_ratio: number;
  hex_ratio: number;
  vowel_ratio: number;
  consonant_ratio: number;
  consecutive_consonant_max: number;
  hyphen_count: number;
  underscore_count: number;
  repeated_char_ratio: number;
  has_known_tld: boolean;
}

export interface ReasonFactor {
  factor: string;
  description: string;
  weight: 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface StructuredRecommendation {
  summary: string;
  detected: string;
  significance: string;
  next_steps: string;
  supporting_evidence: string;
  missing_information: string;
}

export interface DnsRecordEntry {
  value: string;
  ttl?: number | null;
}

export interface DnsEnrichmentResult {
  enabled: boolean;
  performed: boolean;
  query_time_ms?: number;
  resolver_status: string;
  nameservers: string[];
  records: Record<string, DnsRecordEntry[]>;
  error?: string | null;
  disclaimer: string;
}

export interface DnsAnalysisResult {
  id?: number;
  submitted_hostname: string;
  normalized_hostname: string;
  is_suspicious: boolean;
  risk_score: number;
  severity: SeverityLevel;
  classification: string;
  confidence: number;
  confidence_display: string;
  uncertainty_status: string;
  features: DnsFeatureSet;
  reasons: ReasonFactor[];
  enrichment?: DnsEnrichmentResult | null;
  flow_features_available: boolean;
  flow_features_notice: string;
  limitations: string;
  timestamp: string;
  source: string;
  query_type: string;
  client_ip?: string;
  model_version: string;
  recommendation: string;
  structured_recommendation?: StructuredRecommendation;
}

export interface ThreatAlert {
  id: number;
  alert_uid: string;
  analysis_id?: number | null;
  hostname: string;
  risk_score: number;
  severity: SeverityLevel;
  status: AlertStatus;
  source: string;
  reasons: ReasonFactor[];
  notes?: string | null;
  timestamp: string;
  acknowledged_at?: string | null;
  resolved_at?: string | null;
}

export interface DashboardStats {
  total_queries: number;
  suspicious_queries: number;
  high_risk_queries: number;
  critical_queries: number;
  detection_rate_pct: number;
  open_alerts_count: number;
  monitoring_status: string;
  model_status: string;
  database_status: string;
}

export interface ActivityPoint {
  time_label: string;
  total: number;
  suspicious: number;
}

export interface RiskDistribution {
  low: number;
  medium: number; // maps to moderate
  high: number;
  critical: number;
}

export interface TopSuspiciousDomain {
  hostname: string;
  count: number;
  max_risk_score: number;
  severity: SeverityLevel;
  last_detected: string;
}

export interface DashboardData {
  stats: DashboardStats;
  risk_distribution: RiskDistribution;
  activity_timeline: ActivityPoint[];
  top_suspicious_domains: TopSuspiciousDomain[];
  recent_alerts: ThreatAlert[];
}

export interface ModelMetrics {
  model_type: string;
  model_version: string;
  trained_at: string;
  dataset_source: string;
  total_samples: number;
  train_samples: number;
  val_samples: number;
  test_samples: number;
  legitimate_samples: number;
  tunneling_samples: number;
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  roc_auc: number;
  confusion_matrix: {
    tn: number;
    fp: number;
    fn: number;
    tp: number;
  };
  feature_importance: Record<string, number>;
  disclaimer: string;
}

export interface SystemSettings {
  alert_threshold: number;
  dns_enrichment_enabled: boolean;
  deduplication_window_mins: number;
  demo_speed_ms: number;
  ingestion_api_key_masked: string;
  ingestion_api_key_full: string;
  database_url: string;
  resolver_timeout_sec: number;
  model_version: string;
}

export interface BatchAnalysisItem {
  row_number: number;
  submitted_hostname: string;
  normalized_hostname: string;
  is_suspicious: boolean;
  risk_score: number;
  severity: SeverityLevel;
  classification: string;
  confidence_display: string;
  status: string;
  error?: string | null;
}

export interface BatchAnalysisResponse {
  total_processed: number;
  valid_count: number;
  invalid_count: number;
  suspicious_count: number;
  high_risk_count: number;
  detected_column: string;
  results: BatchAnalysisItem[];
}

export interface LiveEventItem {
  id?: number;
  hostname: string;
  is_suspicious: boolean;
  risk_score: number;
  severity: SeverityLevel;
  source: string;
  client_ip?: string;
  timestamp: string;
}
