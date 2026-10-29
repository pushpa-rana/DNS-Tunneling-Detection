import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Activity,
  Layers,
  RefreshCw,
  ExternalLink,
  ChevronRight,
  TrendingUp,
  Cpu,
  Server,
  Sparkles
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  Legend
} from 'recharts';
import { DashboardData } from '../types';
import { api } from '../api';

interface DashboardPageProps {
  onNavigate: (page: string, params?: any) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({ onNavigate }) => {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.getDashboard();
      setData(res);
    } catch (err: any) {
      setError(err.message || 'Failed to load dashboard metrics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 8000); // Polling every 8s
    return () => clearInterval(interval);
  }, []);

  const stats = data?.stats;
  const riskDist = data?.risk_distribution;

  const pieData = riskDist ? [
    { name: 'Low Risk', value: riskDist.low, color: '#10b981' },
    { name: 'Medium Risk', value: riskDist.medium, color: '#f59e0b' },
    { name: 'High Risk', value: riskDist.high, color: '#f97316' },
    { name: 'Critical Risk', value: riskDist.critical, color: '#ef4444' }
  ].filter(d => d.value > 0) : [];

  const handleSeedFromEmpty = async () => {
    try {
      setLoading(true);
      await api.seedDemo();
      await loadData();
    } catch (err: any) {
      alert(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Top Banner & Refresh */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <span>Threat Intelligence & Security Dashboard</span>
            <span className="text-xs px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-500/30 font-mono">
              REAL-TIME
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Real-time DNS exfiltration and tunneling heuristics powered by Random Forest lexical analysis.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-rose-950/40 border border-rose-500/30 text-rose-300 text-xs flex items-center justify-between">
          <span>Failed to retrieve dashboard telemetry: {error}</span>
          <button onClick={loadData} className="underline hover:text-white cursor-pointer">Retry</button>
        </div>
      )}

      {/* KPI Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Total Queries */}
        <div className="p-4 rounded-xl bg-[#0d1628] border border-slate-800/90 shadow-sm relative overflow-hidden group hover:border-cyan-500/30 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Total Analyzed</span>
            <div className="p-2 rounded-lg bg-cyan-950/60 border border-cyan-500/20 text-cyan-400">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-slate-100">{stats?.total_queries ?? 0}</span>
            <span className="text-[11px] text-slate-500 font-mono">queries</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-400 flex items-center gap-1">
            <Server className="w-3 h-3 text-cyan-400" />
            <span>All monitored vectors</span>
          </div>
          <div className="absolute -right-4 -bottom-4 w-16 h-16 bg-cyan-500/5 rounded-full pointer-events-none group-hover:scale-125 transition-transform"></div>
        </div>

        {/* Card 2: Suspicious Queries */}
        <div className="p-4 rounded-xl bg-[#0d1628] border border-slate-800/90 shadow-sm relative overflow-hidden group hover:border-amber-500/30 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Suspicious Tunneling</span>
            <div className="p-2 rounded-lg bg-amber-950/60 border border-amber-500/20 text-amber-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-amber-300">{stats?.suspicious_queries ?? 0}</span>
            <span className="text-[11px] text-amber-400/80 font-mono">detected</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-400 flex items-center gap-1">
            <TrendingUp className="w-3 h-3 text-amber-400" />
            <span>Tunneling signatures flagged</span>
          </div>
          <div className="absolute -right-4 -bottom-4 w-16 h-16 bg-amber-500/5 rounded-full pointer-events-none group-hover:scale-125 transition-transform"></div>
        </div>

        {/* Card 3: High Risk & Critical */}
        <div className="p-4 rounded-xl bg-[#0d1628] border border-slate-800/90 shadow-sm relative overflow-hidden group hover:border-rose-500/30 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">High / Critical Risk</span>
            <div className="p-2 rounded-lg bg-rose-950/60 border border-rose-500/20 text-rose-400">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-rose-400">
              {(stats?.high_risk_queries ?? 0) + (stats?.critical_queries ?? 0)}
            </span>
            <span className="text-[11px] text-rose-400/70 font-mono">
              ({stats?.critical_queries ?? 0} critical)
            </span>
          </div>
          <div className="mt-2 text-[11px] text-slate-400 flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse"></span>
            <span>Immediate review required</span>
          </div>
          <div className="absolute -right-4 -bottom-4 w-16 h-16 bg-rose-500/5 rounded-full pointer-events-none group-hover:scale-125 transition-transform"></div>
        </div>

        {/* Card 4: Detection Rate & Open Alerts */}
        <div className="p-4 rounded-xl bg-[#0d1628] border border-slate-800/90 shadow-sm relative overflow-hidden group hover:border-teal-500/30 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Detection Rate</span>
            <div className="p-2 rounded-lg bg-teal-950/60 border border-teal-500/20 text-teal-400">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-teal-300">
              {stats?.detection_rate_pct ?? 0}%
            </span>
            <span className="text-[11px] text-slate-400 font-mono">
              ({stats?.open_alerts_count ?? 0} open alerts)
            </span>
          </div>
          <div className="mt-2 text-[11px] text-slate-400 flex items-center gap-1">
            <Cpu className="w-3 h-3 text-teal-400" />
            <span>Score formula: (Suspicious / Total)</span>
          </div>
          <div className="absolute -right-4 -bottom-4 w-16 h-16 bg-teal-500/5 rounded-full pointer-events-none group-hover:scale-125 transition-transform"></div>
        </div>
      </div>

      {/* Empty State Banner if 0 queries */}
      {stats && stats.total_queries === 0 && (
        <div className="p-8 rounded-xl bg-[#0b1325] border border-cyan-500/30 text-center space-y-4">
          <div className="w-12 h-12 rounded-full bg-cyan-950 border border-cyan-500/40 text-cyan-400 flex items-center justify-center mx-auto shadow-md">
            <Sparkles className="w-6 h-6 text-cyan-400" />
          </div>
          <h3 className="text-base font-semibold text-slate-100">Welcome to DNS Shield AI</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            The database is currently initialized and clean. You can immediately seed realistic demonstration network queries (both benign and tunneling attacks) or run a manual hostname analysis.
          </p>
          <div className="flex items-center justify-center gap-3">
            <button
              onClick={handleSeedFromEmpty}
              className="px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition shadow-[0_0_15px_rgba(6,182,212,0.3)] cursor-pointer flex items-center gap-1.5"
            >
              <Sparkles className="w-4 h-4" />
              <span>Load Realistic Demonstration Telemetry</span>
            </button>
            <button
              onClick={() => onNavigate('analysis')}
              className="px-4 py-2 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition cursor-pointer"
            >
              Analyze Custom Domain
            </button>
          </div>
        </div>
      )}

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Activity Timeline Chart (2 cols) */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-[#0d1628] border border-slate-800 shadow-sm space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">DNS Query Activity Timeline</h3>
              <p className="text-[11px] text-slate-400">Total traffic vs suspicious queries detected over recent time intervals</p>
            </div>
            <span className="text-[10px] text-slate-400 font-mono bg-slate-900 px-2 py-1 rounded border border-slate-800">
              UTC HOURLY
            </span>
          </div>

          <div className="h-64 w-full">
            {data?.activity_timeline && data.activity_timeline.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data.activity_timeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="totalGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0}/>
                    </linearGradient>
                    <linearGradient id="suspGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.6}/>
                      <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="time_label" stroke="#64748b" fontSize={11} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={11} tickLine={false} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#091122', borderColor: '#1e293b', borderRadius: '8px', fontSize: '11px', color: '#f1f5f9' }}
                  />
                  <Area type="monotone" dataKey="total" name="Total Queries" stroke="#06b6d4" strokeWidth={2} fillOpacity={1} fill="url(#totalGrad)" />
                  <Area type="monotone" dataKey="suspicious" name="Suspicious" stroke="#f43f5e" strokeWidth={2} fillOpacity={1} fill="url(#suspGrad)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-slate-500 text-xs">No activity records available</div>
            )}
          </div>
        </div>

        {/* Risk Distribution Donut (1 col) */}
        <div className="p-5 rounded-xl bg-[#0d1628] border border-slate-800 shadow-sm space-y-3 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-200">Severity Distribution</h3>
            <p className="text-[11px] text-slate-400">Classified risk breakdown</p>
          </div>

          <div className="h-52 w-full flex items-center justify-center">
            {pieData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={75}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#091122', borderColor: '#1e293b', borderRadius: '8px', fontSize: '11px' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-slate-500 text-xs">No classified data yet</div>
            )}
          </div>

          <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-800 text-[11px]">
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
              <span className="text-slate-400">Low: {riskDist?.low ?? 0}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span>
              <span className="text-slate-400">Med: {riskDist?.medium ?? 0}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-orange-500"></span>
              <span className="text-slate-400">High: {riskDist?.high ?? 0}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500"></span>
              <span className="text-slate-400">Crit: {riskDist?.critical ?? 0}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Tables Section: Top Suspicious Domains & Recent Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Suspicious Domains */}
        <div className="p-5 rounded-xl bg-[#0d1628] border border-slate-800 shadow-sm space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-200">Top Suspicious Hostnames</h3>
            <button
              onClick={() => onNavigate('explorer')}
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer"
            >
              <span>View All</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="pb-2 font-medium">Domain / Hostname</th>
                  <th className="pb-2 font-medium text-center">Hits</th>
                  <th className="pb-2 font-medium text-center">Max Risk</th>
                  <th className="pb-2 font-medium text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {data?.top_suspicious_domains && data.top_suspicious_domains.length > 0 ? (
                  data.top_suspicious_domains.map((dom, idx) => (
                    <tr key={idx} className="hover:bg-slate-800/30">
                      <td className="py-2.5 text-slate-200 max-w-[200px] truncate" title={dom.hostname}>
                        {dom.hostname}
                      </td>
                      <td className="py-2.5 text-center text-slate-400">{dom.count}</td>
                      <td className="py-2.5 text-center">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          dom.max_risk_score >= 85 ? 'bg-rose-950 text-rose-300 border border-rose-500/30' :
                          dom.max_risk_score >= 65 ? 'bg-orange-950 text-orange-300 border border-orange-500/30' :
                          'bg-amber-950 text-amber-300 border border-amber-500/30'
                        }`}>
                          {dom.max_risk_score}
                        </span>
                      </td>
                      <td className="py-2.5 text-right font-sans">
                        <button
                          onClick={() => onNavigate('analysis', { hostname: dom.hostname })}
                          className="text-[11px] text-cyan-400 hover:underline cursor-pointer"
                        >
                          Deep Scan
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={4} className="py-6 text-center text-slate-500 font-sans">
                      No suspicious domains logged yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Recent Threat Alerts */}
        <div className="p-5 rounded-xl bg-[#0d1628] border border-slate-800 shadow-sm space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-200">Recent Incident Alerts</h3>
            <button
              onClick={() => onNavigate('alerts')}
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer"
            >
              <span>Manage Alerts</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="pb-2 font-medium">Alert UID</th>
                  <th className="pb-2 font-medium">Hostname</th>
                  <th className="pb-2 font-medium text-center">Severity</th>
                  <th className="pb-2 font-medium text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {data?.recent_alerts && data.recent_alerts.length > 0 ? (
                  data.recent_alerts.map((alt) => (
                    <tr key={alt.id} className="hover:bg-slate-800/30">
                      <td className="py-2.5 text-cyan-400 text-[11px]">{alt.alert_uid}</td>
                      <td className="py-2.5 text-slate-200 max-w-[180px] truncate" title={alt.hostname}>
                        {alt.hostname}
                      </td>
                      <td className="py-2.5 text-center">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          alt.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-500/30' :
                          alt.severity === 'HIGH' ? 'bg-orange-950 text-orange-300 border border-orange-500/30' :
                          'bg-amber-950 text-amber-300 border border-amber-500/30'
                        }`}>
                          {alt.severity}
                        </span>
                      </td>
                      <td className="py-2.5 text-right font-sans">
                        <span className={`text-[11px] px-2 py-0.5 rounded-full ${
                          alt.status === 'OPEN' ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20' :
                          alt.status === 'ACKNOWLEDGED' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                          'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                        }`}>
                          {alt.status}
                        </span>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={4} className="py-6 text-center text-slate-500 font-sans">
                      No alerts triggered yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
