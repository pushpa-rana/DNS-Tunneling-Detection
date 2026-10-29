# DNS Shield AI — AI-Powered DNS Tunneling Detection & Threat Monitoring System

Final-year academic cybersecurity project implementing a complete full-stack detection and incident response system for DNS data exfiltration, covert channel tunneling, and C2 beaconing.

---

## 1. System Architecture

- **Frontend**: React 19 + TypeScript + Vite + Tailwind CSS + Recharts + Lucide Icons
- **Backend**: Python 3.12 + FastAPI + Pydantic v2 + SQLAlchemy ORM
- **Machine Learning**: scikit-learn Random Forest (15-dimensional lexical feature extraction, Shannon entropy, RFC conformity)
- **Database**: SQLite default (with configurable `DATABASE_URL` for PostgreSQL in production)
- **Networking & DNS Enrichment**: `dnspython` live resolver with strict timeouts

---

## 2. Quick Run Instructions

### Step 1: Start the Backend (Port 8001)
```powershell
cd c:\cybersheild\backend
python run_backend.py
```
- API Base URL: `http://127.0.0.1:8001`
- Swagger Interactive Docs: `http://127.0.0.1:8001/docs`
- Health Endpoint: `http://127.0.0.1:8001/api/health`

### Step 2: Start the Frontend (Vite)
```powershell
cd c:\cybersheild\frontend
npm run dev
```
- Web Application URL: `http://localhost:5174/` (or `http://localhost:5173/` if port is open)

---

## 3. Automated Test Suite

To run all automated unit and integration tests:
```powershell
cd c:\cybersheild
python -m pytest backend/app/tests -v
```

All 14 tests cover:
- Lexical feature extraction & Shannon entropy calculation
- RFC compliance & domain validation
- Model training, saving, loading & evaluation metrics
- Single domain analysis & batch CSV analysis
- Threat alert lifecycle (Creation, Acknowledge, Resolve, Notes)
- Mode C external ingestion API authentication (`X-API-Key`)

---

## 4. Key Functional Modules

1. **SOC Dashboard**: Real-time KPI summary cards, interactive activity timeline chart, severity distribution donut, top suspicious domains, and live incident feed.
2. **DNS Analysis**:
   - Single hostname inspection with 15 calculated features.
   - Transparent risk scoring (0-100) and weighted explainability reasons.
   - Optional live DNS record enrichment (A, TXT, MX, CNAME, etc.).
   - Batch CSV file upload and processing with results export.
3. **Live Monitoring**:
   - **Mode A (Demo Stream)**: Synthetic telemetry generation with configurable speed intervals.
   - **Mode B (CSV Replay)**: Replay historical network capture logs through the ML pipeline.
   - **Mode C (External Event Ingestion)**: Authenticated REST endpoint (`POST /api/monitoring/ingest` with `X-API-Key`).
4. **Threat Alerts**: Configurable score thresholds, 15-minute deduplication window, investigation notes, and status transition workflows (Open, Acknowledged, Resolved).
5. **DNS Query Explorer**: Searchable, server-paginated forensic table with CSV export.
6. **Model Insights**: Genuine test-set evaluation metrics, confusion matrix, and feature importances.
7. **Settings & System**: Interactive controls for alert threshold, demo speed, deduplication window, and external DNS lookup toggles.
