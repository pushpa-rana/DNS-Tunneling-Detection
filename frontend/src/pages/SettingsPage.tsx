import React, { useState, useEffect } from 'react';
import {
  Settings,
  Shield,
  Key,
  Database,
  Save,
  CheckCircle2,
  AlertTriangle,
  Copy,
  Info,
  Server,
  Terminal,
  Cpu
} from 'lucide-react';
import { SystemSettings } from '../types';
import { api } from '../api';

export const SettingsPage: React.FC = () => {
  const [settings, setSettings] = useState<SystemSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saveNotice, setSaveNotice] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);

  // Form states
  const [threshold, setThreshold] = useState<number>(65);
  const [enrichmentEnabled, setEnrichmentEnabled] = useState<boolean>(false);
  const [dedupWindow, setDedupWindow] = useState<number>(15);
  const [demoSpeed, setDemoSpeed] = useState<number>(1500);

  const loadSettings = async () => {
    try {
      setLoading(true);
      const res = await api.getSettings();
      setSettings(res);
      setThreshold(res.alert_threshold);
      setEnrichmentEnabled(res.dns_enrichment_enabled);
      setDedupWindow(res.deduplication_window_mins);
      setDemoSpeed(res.demo_speed_ms);
    } catch (err: any) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSettings();
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setSaving(true);
      setSaveNotice(null);
      await api.updateSettings({
        alert_threshold: threshold,
        dns_enrichment_enabled: enrichmentEnabled,
        deduplication_window_mins: dedupWindow,
        demo_speed_ms: demoSpeed
      });
      setSaveNotice('Settings updated successfully in persistent database.');
      setTimeout(() => setSaveNotice(null), 4000);
    } catch (err: any) {
      alert(`Save failed: ${err.message}`);
    } finally {
      setSaving(false);
    }
  };

  const copyApiKey = () => {
    if (settings?.ingestion_api_key_full) {
      navigator.clipboard.writeText(settings.ingestion_api_key_full);
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 2000);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="pb-2 border-b border-slate-800">
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <span>System Settings & Academic Project Architecture</span>
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Configure detection parameters, alert thresholds, API tokens, and inspect academic architectural components.
        </p>
      </div>

      {saveNotice && (
        <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span>{saveNotice}</span>
        </div>
      )}

      {/* Main Settings Form */}
      <form onSubmit={handleSave} className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Card 1: Alert Thresholds */}
          <div className="p-5 rounded-xl bg-[#0d1628] border border-slate-800 space-y-4">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              <span>Threat Alert Qualification Threshold</span>
            </h3>
            <p className="text-xs text-slate-400">
              Queries with calculated risk scores equal to or exceeding this value will automatically trigger a new security incident alert.
            </p>

            <div className="space-y-2 pt-2">
              <div className="flex justify-between text-xs font-mono">
                <span className="text-slate-400">Alert Trigger Score:</span>
                <span className="text-cyan-400 font-bold">{threshold} / 100</span>
              </div>
              <input
                type="range"
                min={20}
                max={95}
                step={1}
                value={threshold}
                onChange={(e) => setThreshold(Number(e.target.value))}
                className="w-full accent-cyan-500 cursor-pointer"
              />
              <div className="flex justify-between text-[10px] text-slate-500 font-mono">
                <span>20 (Very Sensitive)</span>
                <span>65 (Recommended)</span>
                <span>95 (Critical Only)</span>
              </div>
            </div>

            <div className="pt-2 border-t border-slate-800/80 space-y-2">
              <label className="text-xs text-slate-300 block font-medium">Alert Deduplication Window (Minutes)</label>
              <input
                type="number"
                min={1}
                max={1440}
                value={dedupWindow}
                onChange={(e) => setDedupWindow(Number(e.target.value))}
                className="w-full px-3 py-2 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
              />
              <span className="text-[10px] text-slate-500 block">
                Repeated queries for the same hostname within this window update the existing open alert rather than generating duplicates.
              </span>
            </div>
          </div>

          {/* Card 2: Live Monitoring & DNS Enrichment */}
          <div className="p-5 rounded-xl bg-[#0d1628] border border-slate-800 space-y-4">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              <span>Monitoring & Live DNS Resolution</span>
            </h3>

            <div className="space-y-2">
              <label className="text-xs text-slate-300 block font-medium">Demo Stream Speed (Milliseconds)</label>
              <select
                value={demoSpeed}
                onChange={(e) => setDemoSpeed(Number(e.target.value))}
                className="w-full px-3 py-2 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value={500}>500ms (High frequency)</option>
                <option value={1000}>1000ms (1 second)</option>
                <option value={1500}>1500ms (1.5 seconds - Standard)</option>
                <option value={3000}>3000ms (3.0 seconds)</option>
              </select>
            </div>

            <div className="pt-2 border-t border-slate-800/80 space-y-3">
              <label className="flex items-start gap-2.5 cursor-pointer text-xs text-slate-300">
                <input
                  type="checkbox"
                  checked={enrichmentEnabled}
                  onChange={(e) => setEnrichmentEnabled(e.target.checked)}
                  className="rounded bg-slate-900 border-slate-700 text-cyan-500 mt-0.5"
                />
                <div>
                  <span className="font-medium text-slate-200 block">Enable Global External DNS Resolution</span>
                  <span className="text-[11px] text-slate-400 block mt-0.5">
                    Query configured public resolver for A, AAAA, MX, NS, TXT, and CNAME records with 2.0s timeout.
                  </span>
                </div>
              </label>
            </div>
          </div>
        </div>

        <div className="flex justify-end">
          <button
            type="submit"
            disabled={saving}
            className="px-5 py-2.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition flex items-center gap-2 cursor-pointer shadow-md disabled:opacity-50"
          >
            <Save className="w-4 h-4" />
            <span>{saving ? 'Saving Changes...' : 'Save Configuration'}</span>
          </button>
        </div>
      </form>

      {/* API Key Management */}
      <div className="p-5 rounded-xl bg-[#0d1628] border border-slate-800 space-y-3">
        <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
          <Key className="w-4 h-4 text-cyan-400" />
          <span>Mode C: External Log Ingestion API Authentication</span>
        </h3>
        <p className="text-xs text-slate-400">
          External DNS log collectors (Zeek, CoreDNS, Bind9, or Windows Event Forwarder) must include this API key in the <code className="text-cyan-400">X-API-Key</code> HTTP header.
        </p>

        <div className="flex items-center gap-3 max-w-md pt-1">
          <input
            type="text"
            readOnly
            value={settings?.ingestion_api_key_full || 'shield-sec-dev-api-key-2026'}
            className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-700 text-xs font-mono text-cyan-300 select-all"
          />
          <button
            type="button"
            onClick={copyApiKey}
            className="px-3 py-2 rounded bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 border border-slate-700 flex items-center gap-1.5 cursor-pointer shrink-0"
          >
            <Copy className="w-3.5 h-3.5 text-cyan-400" />
            <span>{copiedKey ? 'Copied!' : 'Copy Key'}</span>
          </button>
        </div>
      </div>

      {/* Academic Project Specifications */}
      <div className="p-5 rounded-xl bg-[#0d1628] border border-slate-800 space-y-4">
        <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
          <Cpu className="w-4 h-4 text-cyan-400" />
          <span>Academic Project Overview — Final Year Defense</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
            <span className="font-semibold text-cyan-300 block">System Components</span>
            <ul className="list-disc pl-4 space-y-1 text-slate-400">
              <li><strong>Frontend:</strong> React 19 + TypeScript + Vite + Tailwind CSS + Recharts + Lucide.</li>
              <li><strong>Backend:</strong> Python 3.12 + FastAPI + Pydantic v2 + SQLAlchemy ORM.</li>
              <li><strong>ML Pipeline:</strong> scikit-learn Random Forest (15 Lexical Features, Shannon Entropy, Label Lengths).</li>
              <li><strong>Database:</strong> SQLite with configurable <code className="text-cyan-400">DATABASE_URL</code> for PostgreSQL compatibility.</li>
            </ul>
          </div>

          <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
            <span className="font-semibold text-cyan-300 block">Threat Vectors Addressed</span>
            <ul className="list-disc pl-4 space-y-1 text-slate-400">
              <li><strong>Iodine Tunneling:</strong> Base32 chunks encoded across long subdomains.</li>
              <li><strong>DNScat2 C2 Beaconing:</strong> Hexadecimal packet sequences and session tokens.</li>
              <li><strong>Base64 Data Exfiltration:</strong> File payloads fragmented across hierarchical labels.</li>
              <li><strong>Benign CDN Disambiguation:</strong> Multi-tenant cloud prefixes vs malicious exfiltration.</li>
            </ul>
          </div>
        </div>

        <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-[11px] text-slate-400">
          <strong>Database Persistence Note:</strong> Local SQLite is stored at <code className="text-cyan-400 font-mono">{settings?.database_url}</code>. When deploying to containerized or serverless cloud environments (AWS/GCP/Render), configure an external PostgreSQL URI via the <code className="text-cyan-400 font-mono">DATABASE_URL</code> environment variable.
        </div>
      </div>
    </div>
  );
};
