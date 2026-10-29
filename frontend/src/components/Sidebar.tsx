import React from 'react';
import {
  LayoutDashboard,
  Search,
  Radio,
  AlertTriangle,
  Database,
  Cpu,
  Settings,
  Shield,
  ExternalLink,
  ChevronRight
} from 'lucide-react';

interface SidebarProps {
  currentPage: string;
  onSelectPage: (page: string) => void;
  openAlertsCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentPage,
  onSelectPage,
  openAlertsCount,
}) => {
  const navItems = [
    { id: 'dashboard', label: 'SOC Dashboard', icon: LayoutDashboard },
    { id: 'analysis', label: 'DNS Analysis', icon: Search },
    { id: 'monitoring', label: 'Live Monitoring', icon: Radio },
    {
      id: 'alerts',
      label: 'Threat Alerts',
      icon: AlertTriangle,
      badge: openAlertsCount > 0 ? openAlertsCount : undefined
    },
    { id: 'explorer', label: 'Query Explorer', icon: Database },
    { id: 'model', label: 'Model Insights', icon: Cpu },
    { id: 'settings', label: 'Settings & System', icon: Settings },
  ];

  return (
    <aside className="w-64 bg-[#091122] border-r border-slate-800 flex flex-col justify-between shrink-0 select-none">
      <div>
        {/* Brand Header */}
        <div className="h-16 flex items-center px-6 border-b border-slate-800 gap-3">
          <div className="w-9 h-9 rounded-lg bg-cyan-950 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-[0_0_12px_rgba(6,182,212,0.25)]">
            <Shield className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <div className="font-bold text-slate-100 tracking-wide flex items-center gap-1.5 text-sm">
              <span>DNS SHIELD</span>
              <span className="text-[10px] font-semibold bg-cyan-500/20 text-cyan-400 px-1.5 py-0.5 rounded border border-cyan-500/30">AI</span>
            </div>
            <div className="text-[11px] text-slate-400 font-mono">SOC Detection v1.0</div>
          </div>
        </div>

        {/* Navigation list */}
        <div className="p-3 space-y-1">
          <div className="px-3 py-2 text-[10px] font-semibold tracking-wider text-slate-500 uppercase">
            Operations & Detection
          </div>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentPage === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectPage(item.id)}
                className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-xs font-medium transition-all duration-150 ${
                  isActive
                    ? 'bg-cyan-950/70 text-cyan-300 border border-cyan-500/30 shadow-[0_0_15px_rgba(6,182,212,0.15)] font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                </div>
                {item.badge !== undefined && (
                  <span className="px-1.5 py-0.5 text-[10px] font-bold rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/30 animate-pulse">
                    {item.badge}
                  </span>
                )}
                {isActive && item.badge === undefined && (
                  <ChevronRight className="w-3.5 h-3.5 text-cyan-400/70" />
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* System Status Footer */}
      <div className="p-4 border-t border-slate-800/80 bg-[#070d1a]">
        <div className="rounded-lg bg-slate-900/80 border border-slate-800 p-3 text-xs">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-slate-400 text-[11px]">Detection Engine</span>
            <span className="inline-flex items-center gap-1 text-[11px] font-mono text-emerald-400 font-medium">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
              ACTIVE
            </span>
          </div>
          <div className="text-[11px] text-slate-500 truncate font-mono">RF Lexical Classifier</div>
          <div className="mt-2 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[10px] text-slate-400">
            <span>Tunneling Filter</span>
            <span className="text-cyan-400 font-mono">15 Features</span>
          </div>
        </div>
      </div>
    </aside>
  );
};
