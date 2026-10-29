import React, { useState, useEffect } from 'react';
import {
  Cpu,
  RefreshCw,
  Layers,
  Award,
  CheckCircle2,
  AlertTriangle,
  Info,
  BarChart3,
  Sparkles,
  GitCommit
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell
} from 'recharts';
import { ModelMetrics } from '../types';
import { api } from '../api';

export const ModelInsightsPage: React.FC = () => {
  const [metrics, setMetrics] = useState<ModelMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [retraining, setRetraining] = useState(false);
  const [retrainNotice, setRetrainNotice] = useState<string | null>(null);

  const loadModelInfo = async () => {
    try {
      setLoading(true);
      const res = await api.getModelInfo();
      setMetrics(res);
    } catch (err: any) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadModelInfo();
  }, []);

  const handleRetrain = async () => {
    if (!window.confirm('Retrain the Random Forest classifier now? This runs cross-validation and updates saved metrics.')) {
      return;
    }
    try {
      setRetraining(true);
      setRetrainNotice(null);
      const res = await api.retrainModel();
      setRetrainNotice(res.message);
      await loadModelInfo();
    } catch (err: any) {
      alert(`Retraining failed: ${err.message}`);
    } finally {
      setRetraining(false);
    }
  };

  // Prepare feature importance data for chart
  const featureData = metrics?.feature_importance
    ? Object.entries(metrics.feature_importance)
        .map(([feature, importance]) => ({
          name: feature.replace(/_/g, ' '),
          importance: Math.round(importance * 1000) / 10
        }))
        .slice(0, 10)
    : [];

  const cm = metrics?.confusion_matrix;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <span>Machine Learning Architecture & Model Insights</span>
            <span className="text-xs px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-500/30 font-mono">
              GRADIENT BOOSTING
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Genuine model evaluation metrics, feature weights, and confusion matrix measured on held-out test subsets.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleRetrain}
            disabled={retraining}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition disabled:opacity-50 cursor-pointer shadow-md"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${retraining ? 'animate-spin' : ''}`} />
            <span>{retraining ? 'Retraining Classifier...' : 'Retrain Classifier'}</span>
          </button>
        </div>
      </div>

      {retrainNotice && (
        <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span>{retrainNotice}</span>
        </div>
      )}

      {/* Model Spec & Training Metadata Card */}
      <div className="p-5 rounded-xl bg-[#0d1628] border border-slate-800 shadow-sm space-y-3">
        <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
          <Cpu className="w-4 h-4 text-cyan-400" />
          <span>Model Metadata & Stratified Dataset Architecture</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
          <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
            <span className="text-[10px] text-slate-500 block uppercase">Algorithm Architecture</span>
            <span className="text-slate-100 font-bold">{metrics?.model_type || 'Gradient-Boosted Classifier'}</span>
            <span className="text-[11px] text-cyan-400 block font-normal">Version: {metrics?.model_version}</span>
          </div>

          <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
            <span className="text-[10px] text-slate-500 block uppercase">Stratified 3-Way Partitioning</span>
            <span className="text-slate-100 font-bold">{metrics?.total_samples ?? 0} Samples Total</span>
            <span className="text-[11px] text-slate-400 block font-normal">
              Train: {metrics?.train_samples ?? 0} (70%) | Val: {metrics?.val_samples ?? 0} (15%) | Test: {metrics?.test_samples ?? 0} (15%)
            </span>
          </div>

          <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
            <span className="text-[10px] text-slate-500 block uppercase">Class Distribution</span>
            <span className="text-emerald-400 font-bold">{metrics?.legitimate_samples ?? 0} Benign</span>
            <span className="text-rose-400 font-bold ml-2">/ {metrics?.tunneling_samples ?? 0} Tunneling</span>
            <span className="text-[10px] text-slate-500 block pt-0.5">Balanced (50% / 50%)</span>
          </div>
        </div>

        <div className="text-[11px] text-slate-400 p-2.5 rounded bg-slate-900/60 border border-slate-800/80">
          <strong>Dataset Source:</strong> {metrics?.dataset_source}
        </div>
      </div>

      {/* KPI Performance Cards (Evaluated on Test Split) */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <div className="p-4 rounded-xl bg-[#0d1628] border border-slate-800 text-center">
          <span className="text-[10px] font-medium text-slate-400 uppercase tracking-wider block">Accuracy</span>
          <span className="text-2xl font-bold font-mono text-cyan-400 mt-1 block">
            {metrics ? (metrics.accuracy * 100).toFixed(1) : '-'}%
          </span>
          <span className="text-[10px] text-slate-500 mt-1 block">Test Partition</span>
        </div>

        <div className="p-4 rounded-xl bg-[#0d1628] border border-slate-800 text-center">
          <span className="text-[10px] font-medium text-slate-400 uppercase tracking-wider block">Precision</span>
          <span className="text-2xl font-bold font-mono text-teal-400 mt-1 block">
            {metrics ? (metrics.precision * 100).toFixed(1) : '-'}%
          </span>
          <span className="text-[10px] text-slate-500 mt-1 block">TP / (TP + FP)</span>
        </div>

        <div className="p-4 rounded-xl bg-[#0d1628] border border-slate-800 text-center">
          <span className="text-[10px] font-medium text-slate-400 uppercase tracking-wider block">Recall</span>
          <span className="text-2xl font-bold font-mono text-emerald-400 mt-1 block">
            {metrics ? (metrics.recall * 100).toFixed(1) : '-'}%
          </span>
          <span className="text-[10px] text-slate-500 mt-1 block">TP / (TP + FN)</span>
        </div>

        <div className="p-4 rounded-xl bg-[#0d1628] border border-slate-800 text-center">
          <span className="text-[10px] font-medium text-slate-400 uppercase tracking-wider block">F1-Score</span>
          <span className="text-2xl font-bold font-mono text-cyan-300 mt-1 block">
            {metrics ? (metrics.f1_score * 100).toFixed(1) : '-'}%
          </span>
          <span className="text-[10px] text-slate-500 mt-1 block">Harmonic Mean</span>
        </div>

        <div className="p-4 rounded-xl bg-[#0d1628] border border-slate-800 text-center col-span-2 sm:col-span-1">
          <span className="text-[10px] font-medium text-slate-400 uppercase tracking-wider block">ROC-AUC</span>
          <span className="text-2xl font-bold font-mono text-purple-400 mt-1 block">
            {metrics ? metrics.roc_auc.toFixed(3) : '-'}
          </span>
          <span className="text-[10px] text-slate-500 mt-1 block">Area Under Curve</span>
        </div>
      </div>

      {/* Confusion Matrix and Feature Importances */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Confusion Matrix Card */}
        <div className="p-5 rounded-xl bg-[#0d1628] border border-slate-800 shadow-sm space-y-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-200">Confusion Matrix (Held-out Test Split)</h3>
            <p className="text-[11px] text-slate-400">Calculated on test evaluation split ({metrics?.test_samples ?? 0} samples)</p>
          </div>

          {cm ? (
            <div className="space-y-3 font-mono text-xs">
              <div className="grid grid-cols-2 gap-3">
                {/* True Negative */}
                <div className="p-4 rounded-xl bg-emerald-950/30 border border-emerald-500/30 text-center">
                  <div className="text-[10px] text-emerald-400 uppercase font-semibold">True Negatives (TN)</div>
                  <div className="text-3xl font-bold text-emerald-300 my-1">{cm.tn}</div>
                  <div className="text-[10px] text-slate-400 font-sans">Legitimate correctly identified</div>
                </div>

                {/* False Positive */}
                <div className="p-4 rounded-xl bg-amber-950/30 border border-amber-500/30 text-center">
                  <div className="text-[10px] text-amber-400 uppercase font-semibold">False Positives (FP)</div>
                  <div className="text-3xl font-bold text-amber-300 my-1">{cm.fp}</div>
                  <div className="text-[10px] text-slate-400 font-sans">Benign misclassified as tunnel</div>
                </div>

                {/* False Negative */}
                <div className="p-4 rounded-xl bg-rose-950/30 border border-rose-500/30 text-center">
                  <div className="text-[10px] text-rose-400 uppercase font-semibold">False Negatives (FN)</div>
                  <div className="text-3xl font-bold text-rose-300 my-1">{cm.fn}</div>
                  <div className="text-[10px] text-slate-400 font-sans">Tunneling missed as benign</div>
                </div>

                {/* True Positive */}
                <div className="p-4 rounded-xl bg-cyan-950/30 border border-cyan-500/30 text-center">
                  <div className="text-[10px] text-cyan-400 uppercase font-semibold">True Positives (TP)</div>
                  <div className="text-3xl font-bold text-cyan-300 my-1">{cm.tp}</div>
                  <div className="text-[10px] text-slate-400 font-sans">Tunneling correctly detected</div>
                </div>
              </div>

              <div className="text-[10px] text-slate-500 text-center font-sans">
                True positive rate (Sensitivity): {metrics ? (metrics.recall * 100).toFixed(1) : 0}% | True negative rate (Specificity): {cm ? ((cm.tn / (cm.tn + cm.fp)) * 100).toFixed(1) : 0}%
              </div>
            </div>
          ) : (
            <div className="py-12 text-center text-slate-500 text-xs">No confusion matrix available</div>
          )}
        </div>

        {/* Feature Importance Bar Chart */}
        <div className="p-5 rounded-xl bg-[#0d1628] border border-slate-800 shadow-sm space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Gini Feature Importance (%)</h3>
              <p className="text-[11px] text-slate-400">Relative contribution of each lexical feature to classification trees</p>
            </div>
            <BarChart3 className="w-4 h-4 text-cyan-400" />
          </div>

          <div className="h-64 w-full">
            {featureData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={featureData} layout="vertical" margin={{ top: 5, right: 20, left: 70, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                  <XAxis type="number" stroke="#64748b" fontSize={10} unit="%" />
                  <YAxis type="category" dataKey="name" stroke="#94a3b8" fontSize={10} tickLine={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#091122', borderColor: '#1e293b', borderRadius: '8px', fontSize: '11px', color: '#f1f5f9' }}
                    formatter={(val: any) => [`${val}%`, 'Importance']}
                  />
                  <Bar dataKey="importance" fill="#06b6d4" radius={[0, 4, 4, 0]}>
                    {featureData.map((_, index) => (
                      <Cell key={`cell-${index}`} fill={index === 0 ? '#14b8a6' : '#06b6d4'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-slate-500 text-xs">No feature importances found</div>
            )}
          </div>
        </div>
      </div>

      {/* Model Limitations & Academic Defense Statement */}
      <div className="p-5 rounded-xl bg-[#0d1628] border border-slate-800 shadow-sm space-y-3">
        <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
          <Info className="w-4 h-4 text-cyan-400" />
          <span>Scientific Scope & Detection Limitations</span>
        </h3>
        <p className="text-xs text-slate-400 leading-relaxed">
          {metrics?.disclaimer}
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2 text-xs">
          <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
            <span className="font-semibold text-slate-200 block mb-1">Lexical Only Vector</span>
            <span className="text-slate-400">Classifies domains strictly from character distribution and entropy. Does not inspect payload body bytes.</span>
          </div>
          <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
            <span className="font-semibold text-slate-200 block mb-1">Encrypted Legit CDNs</span>
            <span className="text-slate-400">Certain cloud services encode tracking tokens in subdomains, which can exhibit high entropy (mitigated by known TLD heuristics).</span>
          </div>
          <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
            <span className="font-semibold text-slate-200 block mb-1">Low-and-Slow Exfil</span>
            <span className="text-slate-400">Adversaries transmitting 1 character per hour evade frequency filters. Correlating client IP history is essential.</span>
          </div>
        </div>
      </div>
    </div>
  );
};
