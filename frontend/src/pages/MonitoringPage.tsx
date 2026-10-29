import React, { useState, useEffect } from 'react';
import {
  Radio,
  Play,
  Pause,
  Square,
  RefreshCw,
  Trash2,
  Upload,
  Key,
  Code,
  CheckCircle2,
  AlertTriangle,
  Terminal,
  Activity,
  Send,
  Info
} from 'lucide-react';
import { LiveEventItem } from '../types';
import { api } from '../api';

interface MonitoringPageProps {
  onInspectHostname?: (hostname: string) => void;
}

export const MonitoringPage: React.FC<MonitoringPageProps> = ({ onInspectHostname }) => {
  const [activeMode, setActiveMode] = useState<'zeek' | 'ingest' | 'demo'>('zeek');
  const [status, setStatus] = useState<any>({
    mode: 'IDLE',
    status: 'STOPPED',
    speed_ms: 1500,
    total_streamed: 0,
    suspicious_streamed: 0
  });

  const [events, setEvents] = useState<LiveEventItem[]>([]);
  const [speedMs, setSpeedMs] = useState(1500);

  // Ingestion tester state
  const [ingestApiKey, setIngestApiKey] = useState('shield-sec-dev-api-key-2026');
  const [ingestDomain, setIngestDomain] = useState('01823947bca8921df87.c2.targetdomain.net');
  const [ingestClientIp, setIngestClientIp] = useState('10.200.4.15');
  const [ingestLoading, setIngestLoading] = useState(false);
  const [ingestResponse, setIngestResponse] = useState<any>(null);

  // Zeek Ingestion state
  const [zeekFile, setZeekFile] = useState<File | null>(null);
  const [zeekUploading, setZeekUploading] = useState(false);
  const [zeekResult, setZeekResult] = useState<any>(null);
  const [zeekError, setZeekError] = useState<string | null>(null);

  const handleUploadZeek = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!zeekFile) {
      alert('Please select a Zeek DNS log file (.log, .json, .jsonl, .txt).');
      return;
    }
    setZeekUploading(true);
    setZeekError(null);
    try {
      const res = await api.uploadZeekLog(zeekFile, true);
      setZeekResult(res);
      await pollTelemetry();
    } catch (err: any) {
      setZeekError(err.message || 'Failed to process Zeek log.');
    } finally {
      setZeekUploading(false);
    }
  };

  const handleTestIngest = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setIngestLoading(true);
      setIngestResponse(null);
      const res = await api.ingestExternalEvents(
        [{ hostname: ingestDomain, client_ip: ingestClientIp }],
        ingestApiKey
      );
      setIngestResponse(res);
      await pollTelemetry();
    } catch (err: any) {
      setIngestResponse({ error: err.message });
    } finally {
      setIngestLoading(false);
    }
  };

  // Poll status & events
  const pollTelemetry = async () => {
    try {
      const [statusRes, eventsRes] = await Promise.all([
        api.getMonitoringStatus(),
        api.getLiveEvents(30)
      ]);
      setStatus(statusRes);
      if (eventsRes.events) {
        setEvents(eventsRes.events);
      }
    } catch {
      // ignore transient poll error
    }
  };

  useEffect(() => {
    pollTelemetry();
    const interval = setInterval(pollTelemetry, 1500);
    return () => clearInterval(interval);
  }, []);

  const handleStartDemo = async () => {
    try {
      const res = await api.startDemoStream(speedMs);
      setStatus(res);
      await pollTelemetry();
    } catch (err: any) {
      alert(err.message);
    }
  };

  const handleControl = async (action: 'pause' | 'resume' | 'stop') => {
    try {
      const res = await api.controlMonitoring(action);
      setStatus(res);
      await pollTelemetry();
    } catch (err: any) {
      alert(err.message);
    }
  };

  const handleResetDemo = async () => {
    if (!window.confirm('Are you sure you want to purge all demo stream telemetry from the database?')) {
      return;
    }
    try {
      const res = await api.resetDemoData();
      alert(res.message);
      setEvents([]);
      await pollTelemetry();
    } catch (err: any) {
      alert(err.message);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Network Capture Architectural Notice */}
      <div className="p-4 rounded-xl bg-cyan-950/30 border border-cyan-500/30 text-xs text-cyan-200/90 flex items-start gap-3">
        <Info className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <span className="font-semibold text-cyan-300">Enterprise Network Architecture Transparency Notice:</span>
          <p className="text-slate-300">
            Web browsers run in a secure sandbox and cannot capture raw promiscuous network packets directly. DNS Shield AI ingests authorized DNS telemetry through three documented pathways: (A) Zeek JSON/TSV Sensor Log Import, (B) Live Sensor Forwarding via Python Tailer Adapter, or (C) Explicitly Labeled Demo Simulation.
          </p>
        </div>
      </div>

      {/* Mode Switcher Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Mode A Button: Zeek Import */}
        <button
          onClick={() => setActiveMode('zeek')}
          className={`p-4 rounded-xl text-left border transition-all cursor-pointer ${
            activeMode === 'zeek'
              ? 'bg-cyan-950/60 border-cyan-500/50 shadow-[0_0_15px_rgba(6,182,212,0.15)]'
              : 'bg-[#0d1628] border-slate-800 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider">Mode A (Real Telemetry)</span>
            <Upload className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-sm font-semibold text-slate-100 mt-2">Zeek DNS Log Import</div>
          <p className="text-[11px] text-slate-400 mt-1">
            Ingest authorized Zeek dns.log files (JSONL or TSV) to calculate flow features and hybrid detections.
          </p>
        </button>

        {/* Mode B Button: Live Sensor Stream Adapter */}
        <button
          onClick={() => setActiveMode('ingest')}
          className={`p-4 rounded-xl text-left border transition-all cursor-pointer ${
            activeMode === 'ingest'
              ? 'bg-cyan-950/60 border-cyan-500/50 shadow-[0_0_15px_rgba(6,182,212,0.15)]'
              : 'bg-[#0d1628] border-slate-800 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider">Mode B (Live Sensor)</span>
            <Key className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-sm font-semibold text-slate-100 mt-2">Live Stream Adapter API</div>
          <p className="text-[11px] text-slate-400 mt-1">
            Connect live sensor agents, SIEM log shippers, or the Zeek tailer adapter via authenticated REST API.
          </p>
        </button>

        {/* Mode C Button: Simulation Demo */}
        <button
          onClick={() => setActiveMode('demo')}
          className={`p-4 rounded-xl text-left border transition-all cursor-pointer ${
            activeMode === 'demo'
              ? 'bg-cyan-950/60 border-cyan-500/50 shadow-[0_0_15px_rgba(6,182,212,0.15)]'
              : 'bg-[#0d1628] border-slate-800 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-amber-400 uppercase tracking-wider">Mode C (Simulation)</span>
            <Radio className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-sm font-semibold text-slate-100 mt-2">Synthetic Demo Stream</div>
          <p className="text-[11px] text-slate-400 mt-1">
            Explicitly simulated demonstration stream to evaluate dashboard reactivity without a live sensor.
          </p>
        </button>
      </div>

      {/* Mode Controls Panel */}
      <div className="p-6 rounded-xl bg-[#0d1628] border border-slate-800 shadow-sm space-y-4">
        {/* Mode A: Zeek / JSONL / TSV DNS Log Telemetry Ingestion */}
        {activeMode === 'zeek' && (
          <div className="space-y-4">
            <div>
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                  <Upload className="w-4 h-4 text-cyan-400" />
                  <span>Mode A: Authorized Zeek DNS Log Telemetry Ingestion</span>
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-500/30">
                  HISTORICAL DATA IMPORT
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Upload authentic Zeek <code className="text-cyan-400">dns.log</code> files (JSON Lines or TSV format). The engine parses timestamps, client IPs, queries, response codes, and computes real-time traffic flow features (subdomain velocity, NXDOMAIN ratios, and TXT frequencies).
              </p>
            </div>

            <form onSubmit={handleUploadZeek} className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-3">
              <div className="flex flex-wrap items-center gap-4">
                <input
                  type="file"
                  accept=".log,.json,.jsonl,.txt,.tsv"
                  onChange={(e) => setZeekFile(e.target.files ? e.target.files[0] : null)}
                  className="text-xs text-slate-300 file:mr-3 file:py-2 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-slate-800 file:text-cyan-400 hover:file:bg-slate-700 cursor-pointer"
                />

                <button
                  type="submit"
                  disabled={!zeekFile || zeekUploading}
                  className="px-5 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition flex items-center gap-1.5 disabled:opacity-50 cursor-pointer shadow-md"
                >
                  <Activity className="w-3.5 h-3.5" />
                  <span>{zeekUploading ? 'Parsing & Correlating Flow...' : 'Ingest & Analyze Zeek Log'}</span>
                </button>
              </div>

              {zeekError && (
                <div className="p-3 rounded bg-rose-950/40 border border-rose-500/40 text-rose-300 text-xs flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>{zeekError}</span>
                </div>
              )}
            </form>

            {/* Zeek Processing Results Card */}
            {zeekResult && (
              <div className="p-5 rounded-xl bg-[#091122] border border-cyan-500/30 space-y-4 animate-fade-in">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
                  <div>
                    <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500">Telemetry Ingestion Report</span>
                    <h4 className="text-base font-bold text-slate-100 flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      <span>{zeekResult.filename || 'Zeek DNS Log'} Successfully Analyzed</span>
                    </h4>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950/60 text-amber-300 border border-amber-500/30">
                    HISTORICAL TELEMETRY (NOT LIVE INTERCEPTION)
                  </span>
                </div>

                {/* Key Metrics Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 font-mono text-xs">
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase">Records Processed</div>
                    <div className="text-base font-bold text-slate-100 mt-1">{zeekResult.total_records_processed}</div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase">Client IPs</div>
                    <div className="text-base font-bold text-cyan-400 mt-1">{zeekResult.unique_client_ips_count}</div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase">Unique Hostnames</div>
                    <div className="text-base font-bold text-slate-200 mt-1">{zeekResult.unique_hostnames_count}</div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase">Traffic Clusters</div>
                    <div className="text-base font-bold text-slate-200 mt-1">{zeekResult.clusters_analyzed}</div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase">Flagged Threats</div>
                    <div className={`text-base font-bold mt-1 ${zeekResult.suspicious_detections_count > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
                      {zeekResult.suspicious_detections_count}
                    </div>
                  </div>
                </div>

                {/* Missing Fields & Known Limitations Box */}
                {zeekResult.missing_fields && zeekResult.missing_fields.length > 0 && (
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-[11px] text-slate-400 flex items-start gap-2">
                    <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-semibold text-slate-300">Missing Sensor Fields in Upload: </span>
                      <span>{zeekResult.missing_fields.join('; ')}. Feature extraction gracefully adjusted to available fields.</span>
                    </div>
                  </div>
                )}

                {/* Flagged Threat Detections (Distinguishing ML vs Flow Rules) */}
                {zeekResult.flagged_detections && zeekResult.flagged_detections.length > 0 && (
                  <div className="space-y-2">
                    <span className="text-xs font-bold uppercase tracking-wider text-slate-300 block">
                      Detected Anomalies ({zeekResult.flagged_detections.length})
                    </span>
                    <div className="overflow-x-auto border border-slate-800 rounded-lg">
                      <table className="w-full text-left text-xs font-mono">
                        <thead className="bg-slate-900 text-slate-400 border-b border-slate-800">
                          <tr>
                            <th className="py-2 px-3">Hostname</th>
                            <th className="py-2 px-3">Client IP</th>
                            <th className="py-2 px-3">Apex Domain</th>
                            <th className="py-2 px-3 text-center">Risk Score</th>
                            <th className="py-2 px-3 text-center">Severity</th>
                            <th className="py-2 px-3">Detection Origins</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60">
                          {zeekResult.flagged_detections.map((f: any, idx: number) => (
                            <tr key={idx} className="hover:bg-slate-800/40">
                              <td className="py-2 px-3 text-cyan-300 max-w-[200px] truncate" title={f.hostname}>
                                {f.hostname}
                              </td>
                              <td className="py-2 px-3 text-slate-400">{f.client_ip}</td>
                              <td className="py-2 px-3 text-slate-400">{f.apex_domain}</td>
                              <td className="py-2 px-3 text-center font-bold text-slate-100">{f.risk_score}</td>
                              <td className="py-2 px-3 text-center">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                  f.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-500/40' :
                                  'bg-orange-950 text-orange-300 border border-orange-500/40'
                                }`}>
                                  {f.severity}
                                </span>
                              </td>
                              <td className="py-2 px-3 font-sans space-x-1">
                                {f.detection_types && f.detection_types.includes('ML_INFERENCE') && (
                                  <span className="px-1.5 py-0.5 rounded text-[9px] bg-cyan-950 text-cyan-300 border border-cyan-500/30">
                                    [ML MODEL]
                                  </span>
                                )}
                                {f.detection_types && f.detection_types.includes('RULE_DETECTION') && (
                                  <span className="px-1.5 py-0.5 rounded text-[9px] bg-amber-950 text-amber-300 border border-amber-500/30">
                                    [FLOW RULE]
                                  </span>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Mode B: Live Sensor Stream Ingestion & Adapter API */}
        {activeMode === 'ingest' && (
          <div className="space-y-4">
            <div>
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Key className="w-4 h-4 text-cyan-400" />
                <span>Mode B: Live Stream Ingestion & Sensor Adapter</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Target endpoint: <code className="text-cyan-400">POST /api/monitoring/ingest</code> with header <code className="text-cyan-400">X-API-Key</code>.
              </p>
            </div>

            {/* Zeek Stream Adapter CLI Guide */}
            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
              <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider block">
                Live Zeek Sensor Adapter Command
              </span>
              <p className="text-xs text-slate-300">
                To forward live telemetry from an authorized network monitoring sensor running Zeek, execute the included lightweight adapter script:
              </p>
              <pre className="p-3 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono text-cyan-300 overflow-x-auto">
{`python backend/scripts/zeek_stream_adapter.py \\
  --api-url http://localhost:8001 \\
  --api-key shield-sec-dev-api-key-2026 \\
  --log-file /opt/zeek/logs/current/dns.log`}
              </pre>
            </div>

            {/* Interactive Ingest Tester */}
            <form onSubmit={handleTestIngest} className="p-4 rounded-lg bg-slate-900/80 border border-slate-800 space-y-3">
              <span className="text-xs font-bold text-slate-300 uppercase tracking-wider block">
                Interactive Sensor Event Tester
              </span>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="text-[11px] text-slate-400 block mb-1">X-API-Key</label>
                  <input
                    type="text"
                    value={ingestApiKey}
                    onChange={(e) => setIngestApiKey(e.target.value)}
                    className="w-full px-3 py-1.5 rounded bg-slate-950 border border-slate-700 text-xs font-mono text-slate-200"
                  />
                </div>
                <div>
                  <label className="text-[11px] text-slate-400 block mb-1">Queried Hostname</label>
                  <input
                    type="text"
                    value={ingestDomain}
                    onChange={(e) => setIngestDomain(e.target.value)}
                    className="w-full px-3 py-1.5 rounded bg-slate-950 border border-slate-700 text-xs font-mono text-slate-200"
                  />
                </div>
                <div>
                  <label className="text-[11px] text-slate-400 block mb-1">Client Source IP</label>
                  <input
                    type="text"
                    value={ingestClientIp}
                    onChange={(e) => setIngestClientIp(e.target.value)}
                    className="w-full px-3 py-1.5 rounded bg-slate-950 border border-slate-700 text-xs font-mono text-slate-200"
                  />
                </div>
              </div>

              <div className="flex justify-end pt-1">
                <button
                  type="submit"
                  disabled={ingestLoading}
                  className="px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition flex items-center gap-1.5 cursor-pointer shadow-md disabled:opacity-50"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>{ingestLoading ? 'Forwarding Event...' : 'Send Live Telemetry Event'}</span>
                </button>
              </div>

              {ingestResponse && (
                <div className="mt-2 p-3 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono overflow-x-auto text-slate-300">
                  <pre>{JSON.stringify(ingestResponse, null, 2)}</pre>
                </div>
              )}
            </form>
          </div>
        )}

        {/* Mode C: Simulation Demo Generator */}
        {activeMode === 'demo' && (
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                    <Radio className="w-4 h-4 text-amber-400" />
                    <span>Mode C: Synthetic Demo Telemetry Stream</span>
                  </h3>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950/60 text-amber-300 border border-amber-500/30">
                    EXPLICIT SIMULATION
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  Generates synthetic DNS events to evaluate UI reactivity and dashboard charts without requiring an active enterprise network sensor.
                </p>
              </div>

              {/* Status Badge */}
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-400">Stream Status:</span>
                <span className={`px-2.5 py-1 rounded-full text-xs font-mono font-bold border ${
                  status.status === 'RUNNING' ? 'bg-cyan-950 text-cyan-300 border-cyan-500/40 animate-pulse' :
                  status.status === 'PAUSED' ? 'bg-amber-950 text-amber-300 border-amber-500/40' :
                  'bg-slate-900 text-slate-400 border-slate-800'
                }`}>
                  {status.status}
                </span>
              </div>
            </div>

            {/* Controls Bar */}
            <div className="flex flex-wrap items-center gap-3 pt-2">
              <label className="text-xs text-slate-400 flex items-center gap-2">
                <span>Speed Interval:</span>
                <select
                  value={speedMs}
                  onChange={(e) => setSpeedMs(Number(e.target.value))}
                  disabled={status.status === 'RUNNING'}
                  className="px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-slate-300 text-xs font-mono"
                >
                  <option value={500}>Fast (0.5s)</option>
                  <option value={1000}>Normal (1.0s)</option>
                  <option value={1500}>Moderate (1.5s)</option>
                  <option value={3000}>Relaxed (3.0s)</option>
                </select>
              </label>

              {status.status === 'STOPPED' ? (
                <button
                  onClick={handleStartDemo}
                  className="px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition flex items-center gap-1.5 cursor-pointer shadow-md"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>Start Simulated Stream</span>
                </button>
              ) : status.status === 'RUNNING' ? (
                <>
                  <button
                    onClick={() => handleControl('pause')}
                    className="px-4 py-2 rounded-lg text-xs font-semibold bg-amber-600 hover:bg-amber-500 text-white transition flex items-center gap-1.5 cursor-pointer"
                  >
                    <Pause className="w-3.5 h-3.5" />
                    <span>Pause</span>
                  </button>
                  <button
                    onClick={() => handleControl('stop')}
                    className="px-4 py-2 rounded-lg text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white transition flex items-center gap-1.5 cursor-pointer"
                  >
                    <Square className="w-3.5 h-3.5" />
                    <span>Stop</span>
                  </button>
                </>
              ) : (
                <>
                  <button
                    onClick={() => handleControl('resume')}
                    className="px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition flex items-center gap-1.5 cursor-pointer"
                  >
                    <Play className="w-3.5 h-3.5" />
                    <span>Resume</span>
                  </button>
                  <button
                    onClick={() => handleControl('stop')}
                    className="px-4 py-2 rounded-lg text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white transition flex items-center gap-1.5 cursor-pointer"
                  >
                    <Square className="w-3.5 h-3.5" />
                    <span>Stop</span>
                  </button>
                </>
              )}

              <div className="ml-auto">
                <button
                  onClick={handleResetDemo}
                  className="px-3 py-1.5 rounded-lg text-xs text-rose-400 hover:bg-rose-950/40 border border-rose-500/30 transition flex items-center gap-1.5 cursor-pointer"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>Purge Demo Telemetry</span>
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Real-time Telemetry Stream Feed */}
      <div className="p-6 rounded-xl bg-[#0d1628] border border-slate-800 shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-100">Live DNS Query Telemetry Stream</h3>
            <span className="text-[10px] text-slate-500 font-mono">({events.length} recent events)</span>
          </div>

          <span className="text-[11px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-500/30 px-2 py-0.5 rounded">
            RING BUFFER: 100
          </span>
        </div>

        <div className="overflow-x-auto border border-slate-800/80 rounded-lg">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3 font-medium">Timestamp</th>
                <th className="py-2.5 px-3 font-medium">Domain / Hostname</th>
                <th className="py-2.5 px-3 font-medium">Client IP</th>
                <th className="py-2.5 px-3 font-medium text-center">Risk Score</th>
                <th className="py-2.5 px-3 font-medium text-center">Severity</th>
                <th className="py-2.5 px-3 font-medium text-center">Source Mode</th>
                <th className="py-2.5 px-3 font-medium text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50 font-mono">
              {events.length > 0 ? (
                events.map((ev, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-2 px-3 text-slate-500 text-[11px]">
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2 px-3 text-slate-200 max-w-[240px] truncate" title={ev.hostname}>
                      {ev.hostname}
                    </td>
                    <td className="py-2 px-3 text-slate-400 text-[11px]">{ev.client_ip || '127.0.0.1'}</td>
                    <td className="py-2 px-3 text-center">
                      <span className="font-bold text-slate-200">{ev.risk_score}</span>
                    </td>
                    <td className="py-2 px-3 text-center">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        ev.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-500/40' :
                        ev.severity === 'HIGH' ? 'bg-orange-950 text-orange-300 border border-orange-500/40' :
                        ev.severity === 'MODERATE' ? 'bg-amber-950 text-amber-300 border border-amber-500/40' :
                        'bg-emerald-950 text-emerald-300 border border-emerald-500/40'
                      }`}>
                        {ev.severity}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-center font-sans">
                      <span className="text-[10px] px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-400">
                        {ev.source}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-right font-sans">
                      {onInspectHostname && (
                        <button
                          onClick={() => onInspectHostname(ev.hostname)}
                          className="text-[11px] text-cyan-400 hover:underline cursor-pointer"
                        >
                          Deep Scan
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 font-sans">
                    No live events streamed yet. Click "Start Live Stream" above or send an ingestion event.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
