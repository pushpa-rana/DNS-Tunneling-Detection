import React, { useState, useEffect } from 'react';
import { Sidebar } from './components/Sidebar';
import { Navbar } from './components/Navbar';
import { DashboardPage } from './pages/DashboardPage';
import { AnalysisPage } from './pages/AnalysisPage';
import { MonitoringPage } from './pages/MonitoringPage';
import { AlertsPage } from './pages/AlertsPage';
import { ExplorerPage } from './pages/ExplorerPage';
import { ModelInsightsPage } from './pages/ModelInsightsPage';
import { SettingsPage } from './pages/SettingsPage';
import { api } from './api';

export function App() {
  const [currentPage, setCurrentPage] = useState<string>('dashboard');
  const [backendHealthy, setBackendHealthy] = useState<boolean>(true);
  const [monitoringStatus, setMonitoringStatus] = useState<string>('STOPPED');
  const [openAlertsCount, setOpenAlertsCount] = useState<number>(0);
  const [targetHostname, setTargetHostname] = useState<string>('');

  // Check backend health and alerts
  const checkStatus = async () => {
    try {
      const health = await api.getHealth();
      setBackendHealthy(health.status === 'healthy');

      const mon = await api.getMonitoringStatus();
      setMonitoringStatus(mon.status);

      const alerts = await api.getAlerts({ status: 'OPEN', page_size: 1 });
      setOpenAlertsCount(alerts.total);
    } catch {
      setBackendHealthy(false);
    }
  };

  useEffect(() => {
    checkStatus();
    const interval = setInterval(checkStatus, 7000);
    return () => clearInterval(interval);
  }, []);

  const handleNavigate = (page: string, params?: { hostname?: string }) => {
    if (params?.hostname) {
      setTargetHostname(params.hostname);
    }
    setCurrentPage(page);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const renderCurrentPage = () => {
    switch (currentPage) {
      case 'dashboard':
        return <DashboardPage onNavigate={handleNavigate} />;
      case 'analysis':
        return (
          <AnalysisPage
            initialHostname={targetHostname}
            onNavigateAlerts={() => handleNavigate('alerts')}
          />
        );
      case 'monitoring':
        return (
          <MonitoringPage
            onInspectHostname={(h) => handleNavigate('analysis', { hostname: h })}
          />
        );
      case 'alerts':
        return (
          <AlertsPage
            onInspectHostname={(h) => handleNavigate('analysis', { hostname: h })}
          />
        );
      case 'explorer':
        return (
          <ExplorerPage
            onInspectHostname={(h) => handleNavigate('analysis', { hostname: h })}
          />
        );
      case 'model':
        return <ModelInsightsPage />;
      case 'settings':
        return <SettingsPage />;
      default:
        return <DashboardPage onNavigate={handleNavigate} />;
    }
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#070d19] text-slate-100 cyber-grid">
      {/* Sidebar Navigation */}
      <Sidebar
        currentPage={currentPage}
        onSelectPage={(page) => handleNavigate(page)}
        openAlertsCount={openAlertsCount}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col h-full overflow-hidden">
        {/* Top Navbar */}
        <Navbar
          currentPage={currentPage}
          backendHealthy={backendHealthy}
          monitoringStatus={monitoringStatus}
          onRefreshDashboard={checkStatus}
          onNavigate={(page) => handleNavigate(page)}
        />

        {/* Dynamic Page Container */}
        <main className="flex-1 overflow-y-auto">
          {renderCurrentPage()}
        </main>
      </div>
    </div>
  );
}

export default App;
