import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  Download,
  Filter,
  Search,
  ChevronRight,
  ExternalLink,
  MessageSquare,
  ShieldCheck,
  RefreshCw,
  X
} from 'lucide-react';
import { ThreatAlert } from '../types';
import { api } from '../api';

interface AlertsPageProps {
  onInspectHostname?: (hostname: string) => void;
}

export const AlertsPage: React.FC<AlertsPageProps> = ({ onInspectHostname }) => {
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(12);
  const [totalPages, setTotalPages] = useState(1);
  const [loading, setLoading] = useState(true);

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [searchTerm, setSearchTerm] = useState<string>('');

  // Selected Alert for Detail Drawer
  const [selectedAlert, setSelectedAlert] = useState<ThreatAlert | null>(null);
  const [notesInput, setNotesInput] = useState<string>('');
  const [statusUpdating, setStatusUpdating] = useState(false);

  const loadAlerts = async () => {
    try {
      setLoading(true);
      const res = await api.getAlerts({
        page,
        page_size: pageSize,
        status: statusFilter || undefined,
        severity: severityFilter || undefined,
        search: searchTerm || undefined
      });
      setAlerts(res.items);
      setTotal(res.total);
      setTotalPages(res.total_pages);
    } catch (err: any) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, [page, statusFilter, severityFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    loadAlerts();
  };

  const handleOpenDetail = (alert: ThreatAlert) => {
    setSelectedAlert(alert);
    setNotesInput(alert.notes || '');
  };

  const handleUpdateStatus = async (newStatus: 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED') => {
    if (!selectedAlert) return;
    try {
      setStatusUpdating(true);
      const updated = await api.updateAlertStatus(selectedAlert.id, newStatus, notesInput);
      setSelectedAlert({
        ...selectedAlert,
        status: newStatus,
        notes: updated.notes,
        acknowledged_at: updated.acknowledged_at,
        resolved_at: updated.resolved_at
      });
      await loadAlerts();
    } catch (err: any) {
      alert(`Status update failed: ${err.message}`);
    } finally {
      setStatusUpdating(false);
    }
  };

  const handleSaveNotes = async () => {
    if (!selectedAlert) return;
    try {
      setStatusUpdating(true);
      const updated = await api.updateAlertNotes(selectedAlert.id, notesInput);
      setSelectedAlert({
        ...selectedAlert,
        notes: updated.notes
      });
      await loadAlerts();
      alert('Notes saved successfully.');
    } catch (err: any) {
      alert(`Failed to save notes: ${err.message}`);
    } finally {
      setStatusUpdating(false);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <span>Threat Alerts & Incident Response</span>
            <span className="text-xs px-2 py-0.5 rounded bg-rose-950 text-rose-400 border border-rose-500/30 font-mono">
              {total} TOTAL
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Automated alerts triggered by qualifying risk scores with configurable 15-minute time-window deduplication.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <a
            href={`/api/alerts/export/csv?status=${statusFilter}&severity=${severityFilter}`}
            download="dns_shield_alerts.csv"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Filtered Alerts</span>
          </a>
          <button
            onClick={loadAlerts}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition cursor-pointer"
            title="Refresh alerts"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="p-4 rounded-xl bg-[#0d1628] border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <form onSubmit={handleSearchSubmit} className="flex items-center gap-2 flex-1 max-w-md">
          <div className="relative w-full">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Filter by hostname..."
              className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <button
            type="submit"
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 cursor-pointer"
          >
            Filter
          </button>
        </form>

        <div className="flex flex-wrap items-center gap-3 text-xs">
          {/* Status Filter */}
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
              className="px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-slate-300 font-mono text-xs"
            >
              <option value="">All Statuses</option>
              <option value="OPEN">Open Only</option>
              <option value="ACKNOWLEDGED">Acknowledged</option>
              <option value="RESOLVED">Resolved</option>
            </select>
          </div>

          {/* Severity Filter */}
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => { setSeverityFilter(e.target.value); setPage(1); }}
              className="px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-slate-300 font-mono text-xs"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
            </select>
          </div>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="rounded-xl bg-[#0d1628] border border-slate-800 overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-3 px-4 font-medium">Alert UID</th>
                <th className="py-3 px-4 font-medium">Domain / Hostname</th>
                <th className="py-3 px-4 font-medium text-center">Risk Score</th>
                <th className="py-3 px-4 font-medium text-center">Severity</th>
                <th className="py-3 px-4 font-medium text-center">Status</th>
                <th className="py-3 px-4 font-medium">Detected At</th>
                <th className="py-3 px-4 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 font-mono">
              {alerts.length > 0 ? (
                alerts.map((alt) => (
                  <tr key={alt.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-4 text-cyan-400 font-bold">{alt.alert_uid}</td>
                    <td className="py-3 px-4 text-slate-200 max-w-[240px] truncate" title={alt.hostname}>
                      {alt.hostname}
                    </td>
                    <td className="py-3 px-4 text-center">
                      <span className="font-bold text-slate-100">{alt.risk_score}</span>
                    </td>
                    <td className="py-3 px-4 text-center">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        alt.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-500/40' :
                        alt.severity === 'HIGH' ? 'bg-orange-950 text-orange-300 border border-orange-500/40' :
                        'bg-amber-950 text-amber-300 border border-amber-500/40'
                      }`}>
                        {alt.severity}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-center font-sans">
                      <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-semibold ${
                        alt.status === 'OPEN' ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30' :
                        alt.status === 'ACKNOWLEDGED' ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30' :
                        'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                      }`}>
                        {alt.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {new Date(alt.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 text-right font-sans">
                      <button
                        onClick={() => handleOpenDetail(alt)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs font-medium border border-slate-700 transition cursor-pointer"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 font-sans">
                    {loading ? 'Loading threat alerts...' : 'No alerts match current criteria.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Controls */}
        <div className="p-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <span>Page {page} of {totalPages} ({total} alerts)</span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 cursor-pointer"
            >
              Previous
            </button>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 cursor-pointer"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* Alert Investigation Modal / Drawer */}
      {selectedAlert && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0d1628] border border-slate-800 rounded-xl max-w-2xl w-full p-6 space-y-5 shadow-2xl animate-fade-in max-h-[90vh] overflow-y-auto">
            {/* Modal Header */}
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <span className="text-[10px] font-mono text-cyan-400">{selectedAlert.alert_uid}</span>
                <h3 className="text-base font-bold text-slate-100 mt-0.5">Threat Alert Incident Review</h3>
              </div>
              <button
                onClick={() => setSelectedAlert(null)}
                className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-slate-200 cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Target & Risk Badges */}
            <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="space-y-1">
                <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Target Hostname</span>
                <span className="text-base font-mono font-bold text-cyan-300 break-all">{selectedAlert.hostname}</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="text-center px-3 py-1.5 rounded-lg bg-black/40 border border-slate-700">
                  <div className="text-[9px] text-slate-400">Score</div>
                  <div className="text-lg font-bold font-mono text-rose-400">{selectedAlert.risk_score}</div>
                </div>
                <div className="text-center px-3 py-1.5 rounded-lg bg-black/40 border border-slate-700">
                  <div className="text-[9px] text-slate-400">Severity</div>
                  <div className="text-xs font-bold text-rose-400 mt-1">{selectedAlert.severity}</div>
                </div>
              </div>
            </div>

            {/* Incident Status & Lifecycle Buttons */}
            <div className="space-y-2">
              <span className="text-xs font-semibold text-slate-300">Incident Lifecycle Status:</span>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => handleUpdateStatus('OPEN')}
                  disabled={statusUpdating || selectedAlert.status === 'OPEN'}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition cursor-pointer ${
                    selectedAlert.status === 'OPEN'
                      ? 'bg-rose-950 text-rose-300 border-rose-500/50'
                      : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200'
                  }`}
                >
                  Mark as OPEN
                </button>
                <button
                  type="button"
                  onClick={() => handleUpdateStatus('ACKNOWLEDGED')}
                  disabled={statusUpdating || selectedAlert.status === 'ACKNOWLEDGED'}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition cursor-pointer ${
                    selectedAlert.status === 'ACKNOWLEDGED'
                      ? 'bg-amber-950 text-amber-300 border-amber-500/50'
                      : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200'
                  }`}
                >
                  Acknowledge (Investigating)
                </button>
                <button
                  type="button"
                  onClick={() => handleUpdateStatus('RESOLVED')}
                  disabled={statusUpdating || selectedAlert.status === 'RESOLVED'}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition cursor-pointer ${
                    selectedAlert.status === 'RESOLVED'
                      ? 'bg-emerald-950 text-emerald-300 border-emerald-500/50'
                      : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200'
                  }`}
                >
                  Mark RESOLVED
                </button>
              </div>
            </div>

            {/* Detection Reasons */}
            {selectedAlert.reasons && selectedAlert.reasons.length > 0 && (
              <div className="space-y-2">
                <span className="text-xs font-semibold text-slate-300">Triggering Reasons:</span>
                <div className="space-y-1.5">
                  {selectedAlert.reasons.map((r, i) => (
                    <div key={i} className="p-2.5 rounded bg-slate-900 text-xs border border-slate-800 flex items-center justify-between">
                      <span className="text-slate-200">{r.factor}: {r.description}</span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-black/40 text-rose-400 font-bold">{r.weight}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Analyst Investigation Notes */}
            <div className="space-y-2">
              <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <MessageSquare className="w-3.5 h-3.5 text-cyan-400" />
                <span>Analyst Notes & Audit Trail:</span>
              </span>
              <textarea
                rows={3}
                value={notesInput}
                onChange={(e) => setNotesInput(e.target.value)}
                placeholder="Enter investigation observations, IP isolation details, or false-positive notes..."
                className="w-full p-3 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
              <div className="flex justify-between items-center">
                {onInspectHostname && (
                  <button
                    onClick={() => {
                      setSelectedAlert(null);
                      onInspectHostname(selectedAlert.hostname);
                    }}
                    className="text-xs text-cyan-400 hover:underline flex items-center gap-1 cursor-pointer"
                  >
                    <span>Launch Deep Feature Scan</span>
                    <ExternalLink className="w-3 h-3" />
                  </button>
                )}
                <button
                  type="button"
                  onClick={handleSaveNotes}
                  disabled={statusUpdating}
                  className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition cursor-pointer"
                >
                  Save Notes
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
