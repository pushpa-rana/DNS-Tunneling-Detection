import {
  DnsAnalysisResult,
  DashboardData,
  ThreatAlert,
  ModelMetrics,
  SystemSettings,
  BatchAnalysisResponse,
  LiveEventItem
} from './types';

const API_BASE = (import.meta.env.VITE_API_URL ? String(import.meta.env.VITE_API_URL).replace(/\/$/, '') : '') + '/api';

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let errorMsg = `HTTP Error ${res.status}: ${res.statusText}`;
    try {
      const errJson = await res.json();
      if (errJson.detail) {
        errorMsg = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail);
      }
    } catch {
      // ignore json parse error
    }
    throw new Error(errorMsg);
  }
  return res.json();
}

export const api = {
  // Health
  getHealth: () => fetch(`${API_BASE}/health`).then(r => handleResponse<{ status: string; database: string; model: string; model_version: string }>(r)),

  // Dashboard
  getDashboard: () => fetch(`${API_BASE}/dashboard/summary`).then(r => handleResponse<DashboardData>(r)),

  // DNS Analysis
  analyzeSingle: (hostname: string, enableEnrichment: boolean = false, queryType: string = 'A') =>
    fetch(`${API_BASE}/analysis/single`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hostname, enable_enrichment: enableEnrichment, query_type: queryType })
    }).then(r => handleResponse<DnsAnalysisResult>(r)),

  analyzeBatch: (file: File, hostnameColumn?: string) => {
    const formData = new FormData();
    formData.append('file', file);
    if (hostnameColumn) {
      formData.append('hostname_column', hostnameColumn);
    }
    return fetch(`${API_BASE}/analysis/batch`, {
      method: 'POST',
      body: formData
    }).then(r => handleResponse<BatchAnalysisResponse>(r));
  },

  getHistory: (params: Record<string, any>) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') {
        qs.append(k, String(v));
      }
    });
    return fetch(`${API_BASE}/analysis/history?${qs.toString()}`).then(r => handleResponse<{
      page: number;
      page_size: number;
      total: number;
      total_pages: number;
      items: DnsAnalysisResult[];
    }>(r));
  },

  getAnalysisDetail: (id: number) =>
    fetch(`${API_BASE}/analysis/${id}`).then(r => handleResponse<DnsAnalysisResult>(r)),

  // Threat Alerts
  getAlerts: (params: Record<string, any>) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') {
        qs.append(k, String(v));
      }
    });
    return fetch(`${API_BASE}/alerts?${qs.toString()}`).then(r => handleResponse<{
      page: number;
      page_size: number;
      total: number;
      total_pages: number;
      items: ThreatAlert[];
    }>(r));
  },

  getAlertDetail: (id: number) =>
    fetch(`${API_BASE}/alerts/${id}`).then(r => handleResponse<ThreatAlert>(r)),

  updateAlertStatus: (id: number, status: string, notes?: string) =>
    fetch(`${API_BASE}/alerts/${id}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, notes })
    }).then(r => handleResponse<ThreatAlert>(r)),

  updateAlertNotes: (id: number, notes: string) =>
    fetch(`${API_BASE}/alerts/${id}/notes`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ notes })
    }).then(r => handleResponse<ThreatAlert>(r)),

  // Monitoring
  getMonitoringStatus: () =>
    fetch(`${API_BASE}/monitoring/status`).then(r => handleResponse<{
      mode: string;
      status: string;
      speed_ms: number;
      total_streamed: number;
      suspicious_streamed: number;
      replay_progress?: { current: number; total: number } | null;
    }>(r)),

  startDemoStream: (speedMs: number = 1500) =>
    fetch(`${API_BASE}/monitoring/demo/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ speed_ms: speedMs })
    }).then(r => handleResponse<any>(r)),

  controlMonitoring: (action: 'pause' | 'resume' | 'stop') =>
    fetch(`${API_BASE}/monitoring/control`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action })
    }).then(r => handleResponse<any>(r)),

  resetDemoData: () =>
    fetch(`${API_BASE}/monitoring/demo/reset`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ confirm: true })
    }).then(r => handleResponse<any>(r)),

  uploadReplayCsv: (file: File, speedMs: number = 1500) => {
    const formData = new FormData();
    formData.append('file', file);
    return fetch(`${API_BASE}/monitoring/replay/upload?speed_ms=${speedMs}`, {
      method: 'POST',
      body: formData
    }).then(r => handleResponse<any>(r));
  },

  uploadZeekLog: (file: File, storeRecords: boolean = true) => {
    const formData = new FormData();
    formData.append('file', file);
    return fetch(`${API_BASE}/monitoring/zeek/upload?store_records=${storeRecords}`, {
      method: 'POST',
      body: formData
    }).then(r => handleResponse<any>(r));
  },

  getLiveEvents: (limit: number = 25) =>
    fetch(`${API_BASE}/monitoring/events?limit=${limit}`).then(r => handleResponse<{
      status: string;
      mode: string;
      events: LiveEventItem[];
    }>(r)),

  ingestExternalEvents: (events: Array<{ hostname: string; query_type?: string; client_ip?: string }>, apiKey: string) =>
    fetch(`${API_BASE}/monitoring/ingest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': apiKey
      },
      body: JSON.stringify({ events })
    }).then(r => handleResponse<any>(r)),

  // Model Info & Retrain
  getModelInfo: () =>
    fetch(`${API_BASE}/model/info`).then(r => handleResponse<ModelMetrics>(r)),

  retrainModel: () =>
    fetch(`${API_BASE}/model/retrain`, { method: 'POST' }).then(r => handleResponse<any>(r)),

  // Settings & Demo Seed
  getSettings: () =>
    fetch(`${API_BASE}/settings`).then(r => handleResponse<SystemSettings>(r)),

  updateSettings: (settingsPayload: Partial<SystemSettings>) =>
    fetch(`${API_BASE}/settings`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settingsPayload)
    }).then(r => handleResponse<any>(r)),

  seedDemo: () =>
    fetch(`${API_BASE}/settings/seed-demo`, { method: 'POST' }).then(r => handleResponse<{ status: string; message: string }>(r)),
};
