import React, { useState } from 'react';
import {
  Activity,
  CheckCircle2,
  AlertCircle,
  Database,
  Sparkles,
  RefreshCw,
  Search,
  Settings
} from 'lucide-react';
import { api } from '../api';

interface NavbarProps {
  currentPage: string;
  backendHealthy: boolean;
  monitoringStatus: string;
  onRefreshDashboard?: () => void;
  onNavigate: (page: string) => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentPage,
  backendHealthy,
  monitoringStatus,
  onRefreshDashboard,
  onNavigate
}) => {
  const [seeding, setSeeding] = useState(false);
  const [seedNotice, setSeedNotice] = useState<string | null>(null);

  const pageTitles: Record<string, string> = {
    dashboard: 'SOC Security Operations Dashboard',
    analysis: 'DNS Lexical & ML Analysis Engine',
    monitoring: 'Live DNS Telemetry & Threat Ingestion',
    alerts: 'Threat Alerts & Security Incident Response',
    explorer: 'DNS Query Log Explorer & Forensic History',
    model: 'Machine Learning Model Architecture & Performance',
    settings: 'System Configuration & Project Details'
  };

  const handleSeedDemo = async () => {
    try {
      setSeeding(true);
      const res = await api.seedDemo();
      setSeedNotice(res.message);
      if (onRefreshDashboard) onRefreshDashboard();
      setTimeout(() => setSeedNotice(null), 4000);
    } catch (err: any) {
      alert(`Error seeding demo data: ${err.message}`);
    } finally {
      setSeeding(false);
    }
  };

  return (
    <header className="h-16 bg-[#091122]/90 backdrop-blur-md border-b border-slate-800 px-6 flex items-center justify-between sticky top-0 z-30">
      {/* Title & Section Breadcrumb */}
      <div className="flex items-center gap-3">
        <h1 className="text-sm font-semibold text-slate-100 flex items-center gap-2 m-0 p-0">
          <span>{pageTitles[currentPage] || 'DNS Shield AI'}</span>
        </h1>
        {seedNotice && (
          <span className="text-[11px] bg-cyan-950 text-cyan-300 border border-cyan-500/40 px-2 py-0.5 rounded-full flex items-center gap-1 animate-fade-in">
            <CheckCircle2 className="w-3 h-3 text-cyan-400" />
            {seedNotice}
          </span>
        )}
      </div>

      {/* Right Action & Status Items */}
      <div className="flex items-center gap-3">
        {/* Backend Connectivity Status */}
        <div className={`px-2.5 py-1 rounded-full text-[11px] font-mono flex items-center gap-1.5 border ${
          backendHealthy
            ? 'bg-emerald-950/40 text-emerald-300 border-emerald-500/30'
            : 'bg-rose-950/40 text-rose-300 border-rose-500/30'
        }`}>
          <span className={`w-1.5 h-1.5 rounded-full ${backendHealthy ? 'bg-emerald-400' : 'bg-rose-500'} animate-pulse`}></span>
          <span>{backendHealthy ? 'API ONLINE' : 'API OFFLINE'}</span>
        </div>

        {/* Monitoring State */}
        <div className="px-2.5 py-1 rounded-full text-[11px] font-mono flex items-center gap-1.5 border bg-slate-900 border-slate-700 text-slate-300">
          <Activity className={`w-3.5 h-3.5 ${monitoringStatus === 'RUNNING' ? 'text-cyan-400 animate-spin' : 'text-slate-500'}`} />
          <span>STREAM: {monitoringStatus}</span>
        </div>

        {/* Quick Seed Demo Telemetry Button */}
        <button
          onClick={handleSeedDemo}
          disabled={seeding}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-500/30 transition-colors shadow-sm disabled:opacity-50 cursor-pointer"
          title="Seed realistic benign and tunneling traffic into database"
        >
          <Sparkles className={`w-3.5 h-3.5 text-cyan-400 ${seeding ? 'animate-spin' : ''}`} />
          <span>{seeding ? 'Seeding...' : 'Load Demo Data'}</span>
        </button>

        {/* New DNS Analysis Shortcut */}
        <button
          onClick={() => onNavigate('analysis')}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition-all shadow-[0_0_12px_rgba(6,182,212,0.3)] cursor-pointer"
        >
          <Search className="w-3.5 h-3.5" />
          <span>Analyze Domain</span>
        </button>
      </div>
    </header>
  );
};
