import React, { useState, useEffect } from 'react';
import {
  Database,
  Search,
  Filter,
  Download,
  RefreshCw,
  ChevronRight,
  ExternalLink,
  X,
  Cpu,
  Globe
} from 'lucide-react';
import { DnsAnalysisResult } from '../types';
import { api } from '../api';

interface ExplorerPageProps {
  onInspectHostname?: (hostname: string) => void;
}

export const ExplorerPage: React.FC<ExplorerPageProps> = ({ onInspectHostname }) => {
  const [items, setItems] = useState<DnsAnalysisResult[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(15);
  const [totalPages, setTotalPages] = useState(1);
  const [loading, setLoading] = useState(true);

  // Filters
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [suspiciousOnly, setSuspiciousOnly] = useState(false);
  const [sortBy, setSortBy] = useState('timestamp');
  const [sortOrder, setSortOrder] = useState('desc');

  // Detail Modal
  const [selectedRecord, setSelectedRecord] = useState<DnsAnalysisResult | null>(null);

  const loadRecords = async () => {
    try {
      setLoading(true);
      const res = await api.getHistory({
        page,
        page_size: pageSize,
        search: searchTerm || undefined,
        severity: severityFilter || undefined,
        source: sourceFilter || undefined,
        is_suspicious: suspiciousOnly ? true : undefined,
        sort_by: sortBy,
        sort_order: sortOrder
      });
      setItems(res.items);
      setTotal(res.total);
      setTotalPages(res.total_pages);
    } catch (err: any) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRecords();
  }, [page, pageSize, severityFilter, sourceFilter, suspiciousOnly, sortBy, sortOrder]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    loadRecords();
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <span>DNS Query Forensic Explorer</span>
            <span className="text-xs px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-500/30 font-mono">
              {total} RECORDS
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Searchable forensic database of all evaluated queries with deep feature inspection and CSV export.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <a
            href={`/api/analysis/export/csv?search=${searchTerm}&severity=${severityFilter}&source=${sourceFilter}`}
            download="dns_shield_queries.csv"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </a>
          <button
            onClick={loadRecords}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition cursor-pointer"
            title="Refresh records"
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
              placeholder="Search hostname or domain..."
              className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <button
            type="submit"
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 cursor-pointer"
          >
            Search
          </button>
        </form>

        <div className="flex flex-wrap items-center gap-3 text-xs">
          <label className="flex items-center gap-1.5 cursor-pointer text-slate-300">
            <input
              type="checkbox"
              checked={suspiciousOnly}
              onChange={(e) => { setSuspiciousOnly(e.target.checked); setPage(1); }}
              className="rounded bg-slate-900 border-slate-700 text-cyan-500"
            />
            <span>Suspicious Only</span>
          </label>

          <select
            value={severityFilter}
            onChange={(e) => { setSeverityFilter(e.target.value); setPage(1); }}
            className="px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-slate-300 font-mono text-xs"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <select
            value={sourceFilter}
            onChange={(e) => { setSourceFilter(e.target.value); setPage(1); }}
            className="px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-slate-300 font-mono text-xs"
          >
            <option value="">All Sources</option>
            <option value="MANUAL">Manual</option>
            <option value="BATCH">Batch CSV</option>
            <option value="DEMO_STREAM">Demo Stream</option>
            <option value="CSV_REPLAY">CSV Replay</option>
            <option value="API_INGESTION">API Ingest</option>
          </select>
        </div>
      </div>

      {/* Explorer Records Table */}
      <div className="rounded-xl bg-[#0d1628] border border-slate-800 overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-3 px-4 font-medium">Domain / Hostname</th>
                <th className="py-3 px-4 font-medium text-center">Score</th>
                <th className="py-3 px-4 font-medium text-center">Severity</th>
                <th className="py-3 px-4 font-medium text-center">Entropy</th>
                <th className="py-3 px-4 font-medium text-center">Length</th>
                <th className="py-3 px-4 font-medium">Source</th>
                <th className="py-3 px-4 font-medium">Logged Time</th>
                <th className="py-3 px-4 font-medium text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 font-mono">
              {items.length > 0 ? (
                items.map((row) => (
                  <tr key={row.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-4 text-slate-200 max-w-[260px] truncate" title={row.submitted_hostname || (row as any).hostname}>
                      {row.submitted_hostname || (row as any).hostname}
                    </td>
                    <td className="py-3 px-4 text-center font-bold text-slate-100">{row.risk_score}</td>
                    <td className="py-3 px-4 text-center">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        row.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-500/30' :
                        row.severity === 'HIGH' ? 'bg-orange-950 text-orange-300 border border-orange-500/30' :
                        row.severity === 'MODERATE' ? 'bg-amber-950 text-amber-300 border border-amber-500/30' :
                        'bg-emerald-950 text-emerald-300 border border-emerald-500/30'
                      }`}>
                        {row.severity}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-center text-cyan-400">
                      {row.features ? row.features.shannon_entropy : '-'}
                    </td>
                    <td className="py-3 px-4 text-center text-slate-300">
                      {row.features ? row.features.hostname_length : '-'}
                    </td>
                    <td className="py-3 px-4 font-sans text-slate-400 text-[11px]">{row.source}</td>
                    <td className="py-3 px-4 text-slate-500 text-[11px]">
                      {new Date(row.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 text-right font-sans">
                      <button
                        onClick={() => setSelectedRecord(row)}
                        className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs font-medium border border-slate-700 transition cursor-pointer"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 font-sans">
                    {loading ? 'Loading query records...' : 'No records match search parameters.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        <div className="p-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <span>Showing page {page} of {totalPages} ({total} total analyses)</span>
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

      {/* Record Inspection Modal */}
      {selectedRecord && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0d1628] border border-slate-800 rounded-xl max-w-2xl w-full p-6 space-y-5 shadow-2xl animate-fade-in max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <span className="text-[10px] font-mono text-cyan-400">ANALYSIS ID #{selectedRecord.id}</span>
                <h3 className="text-base font-bold text-slate-100 mt-0.5">Forensic Record Inspection</h3>
              </div>
              <button
                onClick={() => setSelectedRecord(null)}
                className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-slate-200 cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
              <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Target Hostname</span>
              <div className="text-base font-mono font-bold text-cyan-300 break-all">{selectedRecord.submitted_hostname || (selectedRecord as any).hostname}</div>
              {selectedRecord.normalized_hostname && selectedRecord.normalized_hostname !== selectedRecord.submitted_hostname && (
                <div className="text-xs font-mono text-slate-400">
                  Normalized: <span className="text-slate-200">{selectedRecord.normalized_hostname}</span>
                </div>
              )}
              <div className="flex items-center gap-4 text-xs text-slate-400 pt-1">
                <span>Score: <strong className="text-slate-200">{selectedRecord.risk_score}</strong></span>
                <span>Severity: <strong className="text-slate-200">{selectedRecord.severity}</strong></span>
                <span>Source: <strong className="text-slate-200">{selectedRecord.source}</strong></span>
              </div>
            </div>

            {/* Features Breakdown */}
            {selectedRecord.features && (
              <div className="space-y-2">
                <span className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-cyan-400" />
                  <span>Extracted Lexical Features</span>
                </span>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 font-mono text-xs">
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                    <span className="text-[10px] text-slate-500 block">Shannon Entropy</span>
                    <span className="text-cyan-400 font-bold">{selectedRecord.features.shannon_entropy}</span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                    <span className="text-[10px] text-slate-500 block">Hostname Length</span>
                    <span className="text-slate-200 font-bold">{selectedRecord.features.hostname_length}</span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                    <span className="text-[10px] text-slate-500 block">Subdomain Depth</span>
                    <span className="text-slate-200 font-bold">{selectedRecord.features.subdomain_depth}</span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                    <span className="text-[10px] text-slate-500 block">Max Label Length</span>
                    <span className="text-slate-200 font-bold">{selectedRecord.features.max_label_length}</span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                    <span className="text-[10px] text-slate-500 block">Digit Ratio</span>
                    <span className="text-slate-200 font-bold">{(selectedRecord.features.digit_ratio * 100).toFixed(1)}%</span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                    <span className="text-[10px] text-slate-500 block">Hex Ratio</span>
                    <span className="text-slate-200 font-bold">{(selectedRecord.features.hex_ratio * 100).toFixed(1)}%</span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                    <span className="text-[10px] text-slate-500 block">Consonant Streak</span>
                    <span className="text-slate-200 font-bold">{selectedRecord.features.consecutive_consonant_max}</span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                    <span className="text-[10px] text-slate-500 block">Known TLD</span>
                    <span className="text-slate-200 font-bold">{selectedRecord.features.has_known_tld ? 'Yes' : 'No'}</span>
                  </div>
                </div>
              </div>
            )}

            {/* Reasons */}
            {selectedRecord.reasons && selectedRecord.reasons.length > 0 && (
              <div className="space-y-2">
                <span className="text-xs font-semibold text-slate-300">Classification Factors:</span>
                <div className="space-y-1">
                  {selectedRecord.reasons.map((r, i) => (
                    <div key={i} className="p-2 rounded bg-slate-900 border border-slate-800 text-xs text-slate-300">
                      <strong>{r.factor}:</strong> {r.description}
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="pt-2 flex justify-between items-center border-t border-slate-800">
              {onInspectHostname && (
                <button
                  onClick={() => {
                    setSelectedRecord(null);
                    onInspectHostname(selectedRecord.submitted_hostname || (selectedRecord as any).hostname);
                  }}
                  className="text-xs text-cyan-400 hover:underline flex items-center gap-1 cursor-pointer"
                >
                  <span>Open in Full Analysis Page</span>
                  <ExternalLink className="w-3 h-3" />
                </button>
              )}
              <button
                onClick={() => setSelectedRecord(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
