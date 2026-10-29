import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DATA_DIR = os.path.join(BASE_DIR, "data")
DEFAULT_DB_PATH = os.path.join(DEFAULT_DATA_DIR, "dns_shield.db").replace("\\", "/")

def parse_cors_origins() -> list[str]:
    raw = os.getenv("CORS_ORIGINS")
    if raw:
        return [o.strip() for o in raw.split(",") if o.strip()]
    return [
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "http://127.0.0.1:3000"
    ]

class Settings:
    PROJECT_NAME: str = "DNS Shield AI"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development") # development / production
    
    DATA_DIR: str = os.getenv("DATA_DIR", DEFAULT_DATA_DIR)
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH}")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dns-shield-insecure-dev-key-change-in-production")
    DEFAULT_API_KEY: str = os.getenv("INGESTION_API_KEY", "shield-sec-dev-api-key-2026")
    
    CORS_ORIGINS: list[str] = parse_cors_origins()
    
    MODEL_PATH: str = os.getenv("MODEL_PATH", os.path.join(DATA_DIR, "models", "dns_tunnel_rf_model.joblib"))
    METRICS_PATH: str = os.getenv("METRICS_PATH", os.path.join(DATA_DIR, "models", "model_metrics.json"))
    
    DEFAULT_ALERT_THRESHOLD: float = float(os.getenv("DEFAULT_ALERT_THRESHOLD", "65.0"))
    DNS_ENRICHMENT_TIMEOUT_SEC: float = float(os.getenv("DNS_ENRICHMENT_TIMEOUT_SEC", "2.0"))
    MAX_UPLOAD_SIZE_BYTES: int = int(os.getenv("MAX_UPLOAD_SIZE_BYTES", str(15 * 1024 * 1024))) # 15MB

settings = Settings()
