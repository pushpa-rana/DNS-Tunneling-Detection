import React, { useState } from 'react';
import {
  Search,
  Upload,
  AlertTriangle,
  CheckCircle2,
  FileText,
  Download,
  Info,
  Shield,
  ArrowRight,
  Globe,
  RefreshCw,
  Cpu,
  Clock,
  Layers,
  HelpCircle,
  ShieldAlert
} from 'lucide-react';
import { DnsAnalysisResult, BatchAnalysisResponse } from '../types';
import { api } from '../api';

interface AnalysisPageProps {
  initialHostname?: string;
  onNavigateAlerts?: () => void;
}

export const AnalysisPage: React.FC<AnalysisPageProps> = ({ initialHostname, onNavigateAlerts }) => {
  const [activeTab, setActiveTab] = useState<'single' | 'batch'>('single');

  // Single analysis state
  const [hostname, setHostname] = useState(initialHostname || '');
  const [enableEnrichment, setEnableEnrichment] = useState(false);
  const [queryType, setQueryType] = useState('A');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<DnsAnalysisResult | null>(null);

  // Batch analysis state
  const [batchFile, setBatchFile] = useState<File | null>(null);
  const [customColumn, setCustomColumn] = useState('');
  const [batchLoading, setBatchLoading] = useState(false);
  const [batchError, setBatchError] = useState<string | null>(null);
  const [batchResult, setBatchResult] = useState<BatchAnalysisResponse | null>(null);

  const sampleDomains = [
    { label: 'Benign (Web)', value: 'www.example.com' },
    { label: 'Benign (API)', value: 'api.company.com' },
    { label: 'Iodine Tunneling', value: 'a8f92k7m3x9q2m10v8z.tunnel.evilcorp.org' },
    { label: 'DNScat2 Tunneling', value: 'dnscat.01823947bca8921df87.c2.targetdomain.net' },
    { label: 'Base64 Exfil', value: 'dGhpcy1pcy1hLXNlY3JldC1leGZpbA.data.exfil-dns.io' }
  ];

  const handleSingleAnalyze = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!hostname.trim()) {
      setError('Please enter a valid domain or hostname to analyze.');
      return;
    }

    try {
      setLoading(true);
      setError(null);
      const res = await api.analyzeSingle(hostname.trim(), enableEnrichment, queryType);
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'Analysis failed. Check backend connection.');
    } finally {
      setLoading(false);
    }
  };

  const handleBatchUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!batchFile) {
      setBatchError('Please select a .csv file to upload.');
      return;
    }

    try {
      setBatchLoading(true);
      setBatchError(null);
      const res = await api.analyzeBatch(batchFile, customColumn.trim() || undefined);
      setBatchResult(res);
    } catch (err: any) {
      setBatchError(err.message || 'Batch analysis failed.');
    } finally {
      setBatchLoading(false);
    }
  };

  const getRiskScoreColor = (score: number) => {
    if (score >= 75) return 'text-rose-400 border-rose-500/50 bg-rose-950/40';
    if (score >= 50) return 'text-orange-400 border-orange-500/50 bg-orange-950/40';
    if (score >= 25) return 'text-amber-400 border-amber-500/50 bg-amber-950/40';
    return 'text-emerald-400 border-emerald-500/50 bg-emerald-950/40';
  };

  const downloadBatchResultsCsv = () => {
    if (!batchResult) return;
    const header = "Row,Submitted Hostname,Normalized Hostname,Is Suspicious,Risk Score,Severity,Classification,Confidence,Status,Error\n";
    const rows = batchResult.results.map(r =>
      `"${r.row_number}","${r.submitted_hostname}","${r.normalized_hostname}","${r.is_suspicious}","${r.risk_score}","${r.severity}","${r.classification}","${r.confidence_display}","${r.status}","${(r.error || '').replace(/"/g, '""')}"`
    ).join("\n");
    const blob = new Blob([header + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dns_shield_batch_results_${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Tab Switcher */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveTab('single')}
            className={`px-4 py-2 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
              activeTab === 'single'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            Dynamic Hostname Deep Scan
          </button>
          <button
            onClick={() => setActiveTab('batch')}
            className={`px-4 py-2 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
              activeTab === 'batch'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            Batch CSV Dataset Ingestion
          </button>
        </div>
      </div>

      {activeTab === 'single' ? (
        <div className="space-y-6">
          {/* Analysis Form Card */}
          <div className="p-6 rounded-xl bg-[#0d1628] border border-slate-800 shadow-sm space-y-4">
            <div>
              <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <Search className="w-4 h-4 text-cyan-400" />
                <span>DNS Tunneling & Covert Channel Detection Engine</span>
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                Enter any valid public domain, FQDN, or internationalized domain name (IDN/Punycode). The Gradient-Boosted classifier calculates 15 deterministic lexical features.
              </p>
            </div>

            <form onSubmit={handleSingleAnalyze} className="space-y-4">
              <div className="flex flex-col sm:flex-row gap-3">
                <div className="flex-1 relative">
                  <input
                    type="text"
                    value={hostname}
                    onChange={(e) => setHostname(e.target.value)}
                    placeholder="Enter any domain, e.g. api.yourcompany.com, c2.attacker.xyz, or xn--80akhbyknj4f.com"
                    className="w-full px-4 py-2.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 placeholder-slate-500 font-mono text-xs focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/50"
                  />
                </div>
                <div className="flex items-center gap-2">
                  <select
                    value={queryType}
                    onChange={(e) => setQueryType(e.target.value)}
                    className="px-3 py-2.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-300 text-xs font-mono focus:outline-none focus:border-cyan-500"
                  >
                    <option value="A">Record A</option>
                    <option value="AAAA">Record AAAA</option>
                    <option value="TXT">Record TXT</option>
                    <option value="CNAME">Record CNAME</option>
                    <option value="MX">Record MX</option>
                    <option value="NS">Record NS</option>
                  </select>
                  <button
                    type="submit"
                    disabled={loading}
                    className="px-5 py-2.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition shadow-[0_0_15px_rgba(6,182,212,0.3)] disabled:opacity-50 cursor-pointer flex items-center gap-2"
                  >
                    {loading ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        <span>Running Model...</span>
                      </>
                    ) : (
                      <>
                        <Shield className="w-3.5 h-3.5" />
                        <span>Inspect Domain</span>
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Enrichment Toggle & Sample Buttons */}
              <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="text-[11px] text-slate-500 mr-1">Predefined Test Samples:</span>
                  {sampleDomains.map((sample, idx) => (
                    <button
                      key={idx}
                      type="button"
                      onClick={() => setHostname(sample.value)}
                      className="px-2 py-1 rounded bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-[10px] font-mono border border-slate-700 transition cursor-pointer"
                    >
                      {sample.label}
                    </button>
                  ))}
                </div>

                <label className="flex items-center gap-2 cursor-pointer text-xs text-slate-400 select-none">
                  <input
                    type="checkbox"
                    checked={enableEnrichment}
                    onChange={(e) => setEnableEnrichment(e.target.checked)}
                    className="rounded bg-slate-900 border-slate-700 text-cyan-500 focus:ring-0"
                  />
                  <span>Perform Live DNS Resolution with TTLs</span>
                </label>
              </div>
            </form>

            {error && (
              <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}
          </div>

          {/* Analysis Result Card */}
          {result && (
            <div className="p-6 rounded-xl bg-[#0d1628] border border-slate-800 shadow-sm space-y-6 animate-fade-in">
              {/* Verdict Header */}
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-[#091122] border border-slate-800/80">
                <div className="space-y-1">
                  <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">Submitted Hostname Target</div>
                  <div className="text-lg font-bold font-mono text-cyan-300 break-all">{result.submitted_hostname}</div>
                  {result.submitted_hostname !== result.normalized_hostname && (
                    <div className="text-xs font-mono text-slate-400">
                      Normalized / Punycode: <span className="text-slate-300">{result.normalized_hostname}</span>
                    </div>
                  )}
                  <div className="text-xs text-slate-400 flex flex-wrap items-center gap-3 pt-1">
                    <span>Source: <strong className="text-slate-300">{result.source}</strong></span>
                    <span>Model: <strong className="text-slate-300">{result.model_version}</strong></span>
                    <span>Confidence: <strong className="text-cyan-400">{result.confidence_display}</strong></span>
                  </div>
                </div>

                <div className="flex items-center gap-4">
                  {/* Calibrated Risk Score Badge */}
                  <div className={`p-4 rounded-xl border text-center min-w-[130px] ${getRiskScoreColor(result.risk_score)}`}>
                    <div className="text-[10px] font-bold tracking-wider uppercase">Risk Score</div>
                    <div className="text-3xl font-extrabold font-mono mt-0.5">{result.risk_score} <span className="text-xs font-normal">/100</span></div>
                    <div className="text-[10px] font-bold mt-1 px-1.5 py-0.5 rounded bg-black/40 inline-block">
                      {result.severity} BAND
                    </div>
                  </div>

                  {/* Classification Verdict Pill */}
                  <div className="space-y-2">
                    {result.is_suspicious ? (
                      <div className="px-3.5 py-2 rounded-lg bg-rose-950 text-rose-300 border border-rose-500/40 text-xs font-bold flex items-center gap-2 shadow-sm">
                        <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                        <span>{result.classification.toUpperCase()}</span>
                      </div>
                    ) : (
                      <div className="px-3.5 py-2 rounded-lg bg-emerald-950 text-emerald-300 border border-emerald-500/40 text-xs font-bold flex items-center gap-2 shadow-sm">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                        <span>{result.classification.toUpperCase()}</span>
                      </div>
                    )}
                    {result.is_suspicious && onNavigateAlerts && (
                      <button
                        onClick={onNavigateAlerts}
                        className="text-[11px] text-cyan-400 hover:underline flex items-center gap-1 cursor-pointer"
                      >
                        <span>Inspect in Threat Alerts</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                </div>
              </div>

              {/* Actionable Advisory Security Recommendation */}
              <div className="p-5 rounded-xl bg-[#091122] border border-cyan-500/30 text-xs space-y-3.5">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <span className="font-bold text-cyan-300 flex items-center gap-2 text-sm">
                    <Info className="w-4 h-4 text-cyan-400" />
                    <span>Actionable Advisory Security Recommendation</span>
                  </span>
                  <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-500/30 self-start sm:self-auto">
                    Strictly Advisory — Authorization Required
                  </span>
                </div>

                <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 leading-relaxed font-medium">
                  {result.structured_recommendation?.summary || result.recommendation}
                </div>

                {result.structured_recommendation && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                    <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
                      <div className="text-[10px] font-bold uppercase text-cyan-400">1. What Was Detected</div>
                      <p className="text-slate-300 text-[11px] leading-relaxed">{result.structured_recommendation.detected}</p>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
                      <div className="text-[10px] font-bold uppercase text-amber-400">2. Why It Matters</div>
                      <p className="text-slate-300 text-[11px] leading-relaxed">{result.structured_recommendation.significance}</p>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1 md:col-span-2">
                      <div className="text-[10px] font-bold uppercase text-emerald-400">3. Recommended Next Steps (Advisory Investigation)</div>
                      <p className="text-slate-300 text-[11px] leading-relaxed">{result.structured_recommendation.next_steps}</p>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
                      <div className="text-[10px] font-bold uppercase text-purple-400">4. Supporting Evidence</div>
                      <p className="text-slate-300 text-[11px] leading-relaxed">{result.structured_recommendation.supporting_evidence}</p>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
                      <div className="text-[10px] font-bold uppercase text-slate-400">5. Missing Information & Limitations</div>
                      <p className="text-slate-300 text-[11px] leading-relaxed">{result.structured_recommendation.missing_information}</p>
                    </div>
                  </div>
                )}

                <div className="text-[11px] text-amber-400/90 bg-amber-950/20 border border-amber-500/20 p-2.5 rounded-lg flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 shrink-0 text-amber-400" />
                  <span>Important: Recommendations are strictly advisory. Never automatically block a domain or alter firewall/DNS infrastructure without explicit human security authorization.</span>
                </div>
              </div>

              {/* Explainable Detection Factors List */}
              <div className="space-y-3">
                <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                  Explainable Evidence & Detection Factors ({result.reasons.length})
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {result.reasons.map((r, i) => (
                    <div key={i} className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold text-slate-200">{r.factor}</span>
                        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                          r.weight === 'HIGH' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                          r.weight === 'MEDIUM' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                          'bg-slate-800 text-slate-400'
                        }`}>
                          {r.weight}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400">{r.description}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Dynamic Feature Extraction Grid */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                    <Cpu className="w-4 h-4 text-cyan-400" />
                    <span>Extracted Hostname Lexical Features</span>
                  </h3>
                  <span className="text-[10px] text-slate-500 font-mono">16 DETERMINISTIC FEATURES</span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 font-mono text-xs">
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase">Total Length</div>
                    <div className="text-sm font-bold text-slate-200 mt-1">{result.features.hostname_length} chars</div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase">Shannon Entropy</div>
                    <div className="text-sm font-bold text-cyan-400 mt-1">{result.features.shannon_entropy} bits</div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase">Max Label Length</div>
                    <div className="text-sm font-bold text-slate-200 mt-1">{result.features.max_label_length} chars</div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase">Subdomain Depth</div>
                    <div className="text-sm font-bold text-slate-200 mt-1">{result.features.subdomain_depth} levels</div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase">Label Lengths</div>
                    <div className="text-xs font-bold text-cyan-300 mt-1 break-all">
                      {result.features.label_lengths ? `[${result.features.label_lengths.join(', ')}]` : `${result.features.max_label_length}`}
                    </div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase">Digit Ratio</div>
                    <div className="text-sm font-bold text-slate-200 mt-1">{(result.features.digit_ratio * 100).toFixed(1)}%</div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase">Hex Ratio</div>
                    <div className="text-sm font-bold text-slate-200 mt-1">{(result.features.hex_ratio * 100).toFixed(1)}%</div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase">Vowel Ratio</div>
                    <div className="text-sm font-bold text-slate-200 mt-1">{(result.features.vowel_ratio * 100).toFixed(1)}%</div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase">Consonant Streak</div>
                    <div className="text-sm font-bold text-slate-200 mt-1">{result.features.consecutive_consonant_max}</div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase">Num Labels</div>
                    <div className="text-sm font-bold text-slate-200 mt-1">{result.features.num_labels}</div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase">Known TLD</div>
                    <div className="text-sm font-bold text-slate-200 mt-1">{result.features.has_known_tld ? 'Yes' : 'No'}</div>
                  </div>
                </div>

                {/* Flow-based feature status notice */}
                <div className="p-3 rounded-lg bg-slate-900/40 border border-slate-800 text-[11px] text-slate-400 flex items-start gap-2">
                  <Layers className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-semibold text-slate-300">Flow-Level Features Status: </span>
                    <span>{result.flow_features_notice}</span>
                  </div>
                </div>
              </div>

              {/* Real DNS Resolution Records Box with TTLs */}
              {result.enrichment && result.enrichment.performed && (
                <div className="p-5 rounded-lg bg-[#091122] border border-cyan-500/30 space-y-3">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <h3 className="text-xs font-bold text-cyan-300 flex items-center gap-2">
                      <Globe className="w-4 h-4 text-cyan-400" />
                      <span>Live Public DNS Resolution Observations</span>
                    </h3>
                    <div className="flex items-center gap-2 font-mono text-[11px]">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        result.enrichment.resolver_status === 'NOERROR' ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/40' :
                        result.enrichment.resolver_status === 'NXDOMAIN' ? 'bg-amber-950 text-amber-300 border border-amber-500/40' :
                        'bg-rose-950 text-rose-300 border border-rose-500/40'
                      }`}>
                        RCODE: {result.enrichment.resolver_status}
                      </span>
                      <span className="text-slate-400">{result.enrichment.query_time_ms}ms</span>
                    </div>
                  </div>

                  {result.enrichment.error ? (
                    <div className="p-3 rounded bg-slate-900 border border-amber-500/30 text-amber-300 text-xs">
                      {result.enrichment.error}
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {Object.keys(result.enrichment.records).length > 0 ? (
                        Object.entries(result.enrichment.records).map(([rtype, recs]) => (
                          <div key={rtype} className="p-2.5 rounded bg-slate-900/80 border border-slate-800 text-xs font-mono">
                            <span className="font-bold text-cyan-400 mr-2">[{rtype}]</span>
                            <span className="text-slate-200">
                              {recs.map((r, idx) => (
                                <span key={idx} className="mr-3 inline-block">
                                  {r.value} {r.ttl !== null && <span className="text-slate-500 text-[10px]">(TTL: {r.ttl}s)</span>}
                                </span>
                              ))}
                            </span>
                          </div>
                        ))
                      ) : (
                        <div className="text-xs text-slate-400">No active authoritative records returned for this query type.</div>
                      )}
                    </div>
                  )}
                  <p className="text-[10px] text-slate-500 italic">{result.enrichment.disclaimer}</p>
                </div>
              )}

              {/* Limitations Notice */}
              <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-800 text-[11px] text-slate-400">
                <strong>Forensic Limitations:</strong> {result.limitations}
              </div>
            </div>
          )}
        </div>
      ) : (
        /* Batch CSV Upload Tab */
        <div className="p-6 rounded-xl bg-[#0d1628] border border-slate-800 shadow-sm space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <Upload className="w-4 h-4 text-cyan-400" />
                <span>Batch CSV Dataset Ingestion & Analysis</span>
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                Upload custom domain datasets. The backend detects the hostname column, runs lexical classification row-by-row, persists records, and flags skipped rows transparently.
              </p>
            </div>
            <a
              href="/api/analysis/sample-csv"
              download="dns_shield_sample.csv"
              className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-500/30 transition flex items-center gap-1.5 w-fit"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download Sample CSV Template</span>
            </a>
          </div>

          <form onSubmit={handleBatchUpload} className="space-y-4">
            <div className="border-2 border-dashed border-slate-700 hover:border-cyan-500/50 rounded-xl p-8 text-center transition bg-slate-900/40">
              <input
                type="file"
                accept=".csv"
                onChange={(e) => setBatchFile(e.target.files ? e.target.files[0] : null)}
                className="hidden"
                id="csv-file-input"
              />
              <label htmlFor="csv-file-input" className="cursor-pointer space-y-2 block">
                <FileText className="w-8 h-8 text-cyan-400 mx-auto" />
                <div className="text-xs font-semibold text-slate-200">
                  {batchFile ? batchFile.name : 'Click to select CSV file from your computer'}
                </div>
                <div className="text-[11px] text-slate-500">
                  Max file size: 10MB. Supports arbitrary column names and large test datasets.
                </div>
              </label>
            </div>

            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2">
              <div className="flex items-center gap-2">
                <label className="text-xs text-slate-400 whitespace-nowrap">Hostname Column Override (Optional):</label>
                <input
                  type="text"
                  value={customColumn}
                  onChange={(e) => setCustomColumn(e.target.value)}
                  placeholder="e.g. domain_name, query, or fqdn"
                  className="px-3 py-1.5 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <button
                type="submit"
                disabled={!batchFile || batchLoading}
                className="px-5 py-2.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition shadow-[0_0_15px_rgba(6,182,212,0.3)] disabled:opacity-50 cursor-pointer flex items-center gap-2"
              >
                {batchLoading ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Analyzing Dataset Rows...</span>
                  </>
                ) : (
                  <>
                    <Upload className="w-3.5 h-3.5" />
                    <span>Process Batch CSV Dataset</span>
                  </>
                )}
              </button>
            </div>
          </form>

          {batchError && (
            <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{batchError}</span>
            </div>
          )}

          {/* Batch Results Overview */}
          {batchResult && (
            <div className="space-y-4 pt-4 border-t border-slate-800">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="text-xs text-slate-300">
                  Target Column Detected: <strong className="text-cyan-400 font-mono">{batchResult.detected_column}</strong>
                </div>
                <button
                  onClick={downloadBatchResultsCsv}
                  className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-500/30 transition flex items-center gap-1.5 cursor-pointer w-fit"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download Analysis Results CSV</span>
                </button>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center font-mono">
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                  <div className="text-[10px] text-slate-500 font-sans">Total Processed</div>
                  <div className="text-lg font-bold text-slate-100">{batchResult.total_processed}</div>
                </div>
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                  <div className="text-[10px] text-slate-500 font-sans">Valid Evaluated</div>
                  <div className="text-lg font-bold text-emerald-400">{batchResult.valid_count}</div>
                </div>
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                  <div className="text-[10px] text-slate-500 font-sans">Suspicious Detected</div>
                  <div className="text-lg font-bold text-amber-400">{batchResult.suspicious_count}</div>
                </div>
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                  <div className="text-[10px] text-slate-500 font-sans">Skipped / Corrupt Rows</div>
                  <div className="text-lg font-bold text-rose-400">{batchResult.invalid_count}</div>
                </div>
              </div>

              <div className="overflow-x-auto border border-slate-800 rounded-lg max-h-96">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-900 text-slate-400 border-b border-slate-800 sticky top-0">
                    <tr>
                      <th className="py-2.5 px-3 font-medium">#</th>
                      <th className="py-2.5 px-3 font-medium">Domain / Hostname</th>
                      <th className="py-2.5 px-3 font-medium text-center">Score</th>
                      <th className="py-2.5 px-3 font-medium text-center">Severity</th>
                      <th className="py-2.5 px-3 font-medium">Classification</th>
                      <th className="py-2.5 px-3 font-medium text-right">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 font-mono">
                    {batchResult.results.map((row) => (
                      <tr key={row.row_number} className="hover:bg-slate-800/30">
                        <td className="py-2 px-3 text-slate-500">{row.row_number}</td>
                        <td className="py-2 px-3 text-slate-200 max-w-[220px] truncate" title={row.submitted_hostname}>
                          {row.submitted_hostname}
                        </td>
                        <td className="py-2 px-3 text-center">{row.risk_score}</td>
                        <td className="py-2 px-3 text-center">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                            row.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300' :
                            row.severity === 'HIGH' ? 'bg-orange-950 text-orange-300' :
                            row.severity === 'MODERATE' ? 'bg-amber-950 text-amber-300' :
                            'bg-emerald-950 text-emerald-300'
                          }`}>
                            {row.severity}
                          </span>
                        </td>
                        <td className="py-2 px-3 text-slate-300 font-sans text-[11px]">{row.classification}</td>
                        <td className="py-2 px-3 text-right font-sans">
                          {row.status === 'SUCCESS' ? (
                            <span className="text-emerald-400 text-[11px]">Recorded</span>
                          ) : (
                            <span className="text-rose-400 text-[11px]" title={row.error || 'Skipped row'}>
                              Skipped ({row.error ? row.error.slice(0, 20) : 'Error'}...)
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
  );
};
