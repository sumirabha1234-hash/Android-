import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  DownloadCloud,
  Terminal,
  Activity,
  Smartphone,
  Wifi,
  FileCode,
  AlertTriangle,
  Play,
  RotateCw,
  Search,
  ExternalLink,
  Copy,
  Check,
  CheckCircle2,
  XCircle,
  FileText,
  Radio,
  Lock,
  Cpu,
  Layers,
  HardDrive,
  Download,
} from 'lucide-react';
import { ApkAnalysisResult, DynamicSandboxResult, InterceptedDownloadFile, SandboxLogEntry } from '../types';
import { runIsolatedAndroidSandbox } from '../lib/sandbox-emulator';

interface SandboxTabProps {
  analysis: ApkAnalysisResult;
  onUpdateAnalysis: (updated: ApkAnalysisResult) => void;
}

export const SandboxTab: React.FC<SandboxTabProps> = ({ analysis, onUpdateAnalysis }) => {
  const [activeSubTab, setActiveSubTab] = useState<'downloads' | 'network' | 'logcat' | 'device'>('downloads');
  const [isSimulating, setIsSimulating] = useState(false);
  const [logFilter, setLogFilter] = useState<'all' | 'error' | 'warn' | 'info'>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [selectedFile, setSelectedFile] = useState<InterceptedDownloadFile | null>(
    analysis.dynamicSandbox.downloadedFiles[0] || null
  );

  const sandbox = analysis.dynamicSandbox;
  const isDropper = sandbox.verdict === 'DROPPER_DETECTED';
  const isMalicious = sandbox.verdict === 'MALICIOUS_DOWNLOADER';
  const isSuspicious = sandbox.verdict === 'SUSPICIOUS_NETWORK';
  const isClean = sandbox.verdict === 'CLEAN';

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleRerunSimulation = async () => {
    setIsSimulating(true);
    try {
      const newSandbox = await runIsolatedAndroidSandbox({
        packageName: analysis.packageName,
        appName: analysis.appName,
        components: analysis.components,
        permissions: analysis.permissions,
        vulnerabilities: analysis.vulnerabilities,
        endpoints: analysis.endpoints,
        decompiledFiles: analysis.decompiledFiles,
        rawManifestXml: analysis.formattedManifestXml,
      });

      onUpdateAnalysis({
        ...analysis,
        dynamicSandbox: newSandbox,
        stats: {
          ...analysis.stats,
          downloadedFilesCount: newSandbox.downloadedFiles.length,
        },
      });

      if (newSandbox.downloadedFiles.length > 0) {
        setSelectedFile(newSandbox.downloadedFiles[0]);
      }
    } finally {
      setIsSimulating(false);
    }
  };

  const handleExportLogcat = () => {
    const content = sandbox.logs
      .map((l) => `[${l.timestamp}] [${l.level.padEnd(5)}] [${l.tag.padEnd(16)}] ${l.message}`)
      .join('\n');
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${analysis.packageName}-sandbox-logcat.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredLogs = sandbox.logs.filter((log) => {
    if (logFilter === 'error' && log.level !== 'ERROR') return false;
    if (logFilter === 'warn' && log.level !== 'WARN' && log.level !== 'ERROR') return false;
    if (logFilter === 'info' && log.level === 'DEBUG') return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      return (
        log.message.toLowerCase().includes(term) ||
        log.tag.toLowerCase().includes(term) ||
        log.timestamp.includes(term)
      );
    }
    return true;
  });

  const filteredNetwork = sandbox.networkTraces.filter((n) => {
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      return (
        n.url.toLowerCase().includes(term) ||
        n.host.toLowerCase().includes(term) ||
        n.method.toLowerCase().includes(term)
      );
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Top Banner: Virtual OS & Verdict */}
      <div
        className={`p-6 rounded-2xl border transition-all ${
          isDropper
            ? 'bg-gradient-to-r from-rose-950/40 via-slate-900 to-rose-950/20 border-rose-500/40 shadow-lg shadow-rose-950/30'
            : isMalicious
            ? 'bg-gradient-to-r from-orange-950/40 via-slate-900 to-orange-950/20 border-orange-500/40'
            : isSuspicious
            ? 'bg-gradient-to-r from-amber-950/40 via-slate-900 to-amber-950/20 border-amber-500/40'
            : 'bg-gradient-to-r from-emerald-950/30 via-slate-900 to-cyan-950/20 border-emerald-500/30'
        }`}
      >
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
          <div className="flex items-start gap-4">
            <div
              className={`p-3.5 rounded-xl border ${
                isDropper
                  ? 'bg-rose-500/20 border-rose-500/40 text-rose-400'
                  : isMalicious
                  ? 'bg-orange-500/20 border-orange-500/40 text-orange-400'
                  : isSuspicious
                  ? 'bg-amber-500/20 border-amber-500/40 text-amber-400'
                  : 'bg-emerald-500/20 border-emerald-500/40 text-emerald-400'
              }`}
            >
              {isDropper || isMalicious ? (
                <ShieldAlert className="w-8 h-8 animate-pulse" />
              ) : isSuspicious ? (
                <AlertTriangle className="w-8 h-8" />
              ) : (
                <ShieldCheck className="w-8 h-8" />
              )}
            </div>

            <div>
              <div className="flex flex-wrap items-center gap-2 mb-1">
                <span className="px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider bg-slate-800/80 border border-slate-700 text-slate-300 flex items-center gap-1.5">
                  <Smartphone className="w-3.5 h-3.5 text-cyan-400" />
                  {sandbox.environment.osVersion}
                </span>

                <span
                  className={`px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider border ${
                    isDropper
                      ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                      : isMalicious
                      ? 'bg-orange-500/20 text-orange-300 border-orange-500/30'
                      : isSuspicious
                      ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                      : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                  }`}
                >
                  {isDropper
                    ? 'CRITICAL: Secondary Dropper Trapped'
                    : isMalicious
                    ? 'HIGH: Remote Payload Download Trapped'
                    : isSuspicious
                    ? 'SUSPICIOUS: Remote Downloads Detected'
                    : 'VERIFIED SAFE: No Download Droppers'}
                </span>
              </div>

              <h2 className="text-xl font-bold text-slate-100">
                Isolated Android Sandbox &amp; Payload Intercept Engine
              </h2>
              <p className="text-sm text-slate-300 mt-1 max-w-3xl leading-relaxed">
                {sandbox.verdictSummary}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 w-full lg:w-auto justify-end">
            <button
              onClick={handleRerunSimulation}
              disabled={isSimulating}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs transition disabled:opacity-50 cursor-pointer shadow-lg shadow-cyan-500/20"
            >
              <RotateCw className={`w-4 h-4 ${isSimulating ? 'animate-spin' : ''}`} />
              <span>{isSimulating ? 'Executing in Sandbox...' : 'Re-Run Sandbox'}</span>
            </button>
          </div>
        </div>

        {/* Quick Sandbox Environment Stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-6 pt-5 border-t border-slate-800/80">
          <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800">
            <span className="text-[10px] text-slate-400 font-medium uppercase">Downloaded Files Trapped</span>
            <div className="text-lg font-bold font-mono text-slate-100 flex items-center gap-1.5 mt-0.5">
              <DownloadCloud className={`w-4 h-4 ${sandbox.downloadedFiles.length > 0 ? 'text-rose-400' : 'text-emerald-400'}`} />
              <span className={sandbox.downloadedFiles.length > 0 ? 'text-rose-400' : 'text-emerald-400'}>
                {sandbox.downloadedFiles.length}
              </span>
            </div>
          </div>

          <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800">
            <span className="text-[10px] text-slate-400 font-medium uppercase">Network Requests Trapped</span>
            <div className="text-lg font-bold font-mono text-slate-100 flex items-center gap-1.5 mt-0.5">
              <Activity className="w-4 h-4 text-cyan-400" />
              <span>{sandbox.totalNetworkRequests}</span>
            </div>
          </div>

          <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800">
            <span className="text-[10px] text-slate-400 font-medium uppercase">Dynamic Code Loading (DCL)</span>
            <div className="text-lg font-bold font-mono text-slate-100 flex items-center gap-1.5 mt-0.5">
              <Cpu className={`w-4 h-4 ${sandbox.dynamicCodeLoadingDetected ? 'text-rose-400' : 'text-slate-400'}`} />
              <span className={sandbox.dynamicCodeLoadingDetected ? 'text-rose-400' : 'text-slate-400'}>
                {sandbox.dynamicCodeLoadingDetected ? 'Detected (DEX Hook)' : 'None'}
              </span>
            </div>
          </div>

          <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800">
            <span className="text-[10px] text-slate-400 font-medium uppercase">Anti-Analysis Evasion Traps</span>
            <div className="text-lg font-bold font-mono text-slate-100 flex items-center gap-1.5 mt-0.5">
              <Lock className={`w-4 h-4 ${sandbox.evasionTechniquesDetected.length > 0 ? 'text-amber-400' : 'text-slate-400'}`} />
              <span className={sandbox.evasionTechniquesDetected.length > 0 ? 'text-amber-400' : 'text-slate-400'}>
                {sandbox.evasionTechniquesDetected.length > 0 ? `${sandbox.evasionTechniquesDetected.length} Evaded` : 'Passed'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex items-center justify-between gap-4 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2 overflow-x-auto">
          <button
            onClick={() => setActiveSubTab('downloads')}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold whitespace-nowrap transition cursor-pointer ${
              activeSubTab === 'downloads'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <DownloadCloud className="w-4 h-4" />
            <span>Intercepted File Downloads</span>
            {sandbox.downloadedFiles.length > 0 && (
              <span className="px-1.5 py-0.2 bg-rose-500/20 text-rose-300 text-[10px] rounded-full border border-rose-500/30">
                {sandbox.downloadedFiles.length}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveSubTab('network')}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold whitespace-nowrap transition cursor-pointer ${
              activeSubTab === 'network'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Wifi className="w-4 h-4" />
            <span>Network Traffic &amp; MitM Intercept</span>
            <span className="text-[10px] text-slate-500">({sandbox.networkTraces.length})</span>
          </button>

          <button
            onClick={() => setActiveSubTab('logcat')}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold whitespace-nowrap transition cursor-pointer ${
              activeSubTab === 'logcat'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Terminal className="w-4 h-4" />
            <span>Live Sandbox Logcat</span>
            <span className="text-[10px] text-slate-500">({sandbox.logs.length})</span>
          </button>

          <button
            onClick={() => setActiveSubTab('device')}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold whitespace-nowrap transition cursor-pointer ${
              activeSubTab === 'device'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Smartphone className="w-4 h-4" />
            <span>Virtual Android Runtime</span>
          </button>
        </div>

        {/* Global Search inside Tab */}
        <div className="relative w-64 hidden sm:block">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search sandbox traces..."
            className="w-full bg-slate-900/80 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* VIEW 1: INTERCEPTED FILE DOWNLOADS (The Main Request Feature) */}
      {activeSubTab === 'downloads' && (
        <div className="space-y-6">
          {sandbox.downloadedFiles.length === 0 ? (
            <div className="p-12 text-center rounded-2xl bg-slate-900/40 border border-slate-800/80">
              <div className="w-14 h-14 mx-auto mb-4 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
                <CheckCircle2 className="w-7 h-7" />
              </div>
              <h3 className="text-base font-semibold text-slate-200">No Secondary File Downloads Detected</h3>
              <p className="text-xs text-slate-400 max-w-lg mx-auto mt-1 leading-relaxed">
                The fake Android 14 runtime hooked <code className="text-cyan-400 font-mono">DownloadManager</code>,{' '}
                <code className="text-cyan-400 font-mono">HttpURLConnection</code>, and{' '}
                <code className="text-cyan-400 font-mono">DexClassLoader</code> during execution. No attempts were made
                to fetch executable binaries, APK updates, or dropped payloads from the internet.
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Left Column: List of Intercepted Downloads */}
              <div className="lg:col-span-5 space-y-3">
                <div className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center justify-between">
                  <span>Intercepted Payloads ({sandbox.downloadedFiles.length})</span>
                  <span className="text-[10px] text-rose-400 font-semibold">Trapped in Sandbox</span>
                </div>

                {sandbox.downloadedFiles.map((file) => {
                  const isSelected = selectedFile?.id === file.id;
                  return (
                    <div
                      key={file.id}
                      onClick={() => setSelectedFile(file)}
                      className={`p-4 rounded-xl border transition-all cursor-pointer ${
                        isSelected
                          ? 'bg-slate-800/90 border-cyan-500/60 shadow-md ring-1 ring-cyan-500/20'
                          : 'bg-slate-900/60 hover:bg-slate-800/60 border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2 mb-2">
                        <div className="flex items-center gap-2">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase ${
                              file.riskLevel === 'CRITICAL'
                                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                                : file.riskLevel === 'HIGH'
                                ? 'bg-orange-500/20 text-orange-300 border border-orange-500/30'
                                : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                            }`}
                          >
                            {file.extension}
                          </span>
                          <span className="font-semibold text-sm text-slate-200 truncate">{file.fileName}</span>
                        </div>

                        <span className="text-[11px] font-mono text-slate-400">{file.fileSizeEstimate}</span>
                      </div>

                      <div className="text-xs text-rose-300/90 font-medium mb-2">{file.riskLabel}</div>

                      <div className="flex items-center gap-2 text-[11px] text-slate-400 font-mono truncate">
                        <DownloadCloud className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                        <span className="truncate">{file.url}</span>
                      </div>

                      <div className="flex items-center justify-between mt-3 pt-2.5 border-t border-slate-800/60 text-[10px] text-slate-400">
                        <span>Via: <strong className="text-slate-300">{file.downloadMethod}</strong></span>
                        {file.isExecutedAfterDownload && (
                          <span className="text-rose-400 font-semibold flex items-center gap-1">
                            <AlertTriangle className="w-3 h-3" />
                            Attempted Execution
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Right Column: Detailed Intercept Breakdown */}
              {selectedFile && (
                <div className="lg:col-span-7 p-6 rounded-2xl bg-slate-900/70 border border-slate-800 space-y-6">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span
                          className={`px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider border ${
                            selectedFile.riskLevel === 'CRITICAL'
                              ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                              : 'bg-orange-500/20 text-orange-300 border-orange-500/30'
                          }`}
                        >
                          {selectedFile.riskLevel} SEVERITY
                        </span>
                        <span className="text-xs text-slate-400 font-mono">{selectedFile.mimeType}</span>
                      </div>
                      <h3 className="text-lg font-bold text-slate-100">{selectedFile.riskLabel}</h3>
                    </div>

                    <div className="text-right">
                      <span className="text-[10px] uppercase text-slate-400 font-medium">Estimated Payload Size</span>
                      <div className="text-base font-mono font-bold text-slate-200">{selectedFile.fileSizeEstimate}</div>
                    </div>
                  </div>

                  {/* Remote URL & Copy */}
                  <div className="space-y-1.5">
                    <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Remote Download URL</span>
                    <div className="flex items-center justify-between p-3 rounded-xl bg-slate-950/70 border border-slate-800 font-mono text-xs text-cyan-300 break-all">
                      <span className="truncate mr-2">{selectedFile.url}</span>
                      <button
                        onClick={() => handleCopy(selectedFile.url, selectedFile.id)}
                        className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition shrink-0 cursor-pointer"
                        title="Copy URL"
                      >
                        {copiedId === selectedFile.id ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>

                  {/* Target VFS Path */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div className="p-3.5 rounded-xl bg-slate-950/50 border border-slate-800">
                      <span className="text-[10px] uppercase text-slate-400 font-medium block mb-1">Target Virtual FS Path</span>
                      <div className="font-mono text-xs text-slate-200 truncate">{selectedFile.destinationPath}</div>
                    </div>

                    <div className="p-3.5 rounded-xl bg-slate-950/50 border border-slate-800">
                      <span className="text-[10px] uppercase text-slate-400 font-medium block mb-1">Triggering Component</span>
                      <div className="font-mono text-xs text-slate-200 truncate">{selectedFile.triggerComponent}</div>
                    </div>
                  </div>

                  {/* Dynamic Behavior Analysis */}
                  <div className="space-y-2">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
                      <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                      Dynamic Sandbox Interception Trace
                    </h4>
                    <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800/80 text-xs text-slate-300 leading-relaxed">
                      {selectedFile.behaviorAnalysis}
                    </div>
                  </div>

                  {/* Execution Vector Warning */}
                  {selectedFile.isExecutedAfterDownload && (
                    <div className="p-4 rounded-xl bg-rose-950/30 border border-rose-500/30 space-y-1.5">
                      <div className="flex items-center gap-2 text-rose-300 font-bold text-xs">
                        <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                        <span>Secondary Payload Execution Vector Detected</span>
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed">
                        The decompiled bytecode contains calls attempting to execute or mount this file after download
                        {selectedFile.isDynamicCodeLoading ? ' via Dalvik/ART DexClassLoader memory loading' : ' via system package installation intents'}.
                      </p>
                    </div>
                  )}

                  {/* Remediation */}
                  <div className="space-y-2">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
                      <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                      Security Mitigation Action
                    </h4>
                    <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-500/20 text-xs text-slate-300 leading-relaxed">
                      {selectedFile.mitigation}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* VIEW 2: NETWORK TRAFFIC & MITM INTERCEPT */}
      {activeSubTab === 'network' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-400">
              MitM Captured Network Packets ({filteredNetwork.length})
            </span>
            <span className="text-[10px] text-slate-500">Virtual eth0 interface (10.0.2.15)</span>
          </div>

          <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/60">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950 text-[10px] font-bold uppercase tracking-wider text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Offset</th>
                  <th className="py-3 px-4">Method</th>
                  <th className="py-3 px-4">Host / Destination URL</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Content-Type</th>
                  <th className="py-3 px-4 text-right">Bytes</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {filteredNetwork.map((trace) => (
                  <tr key={trace.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-4 text-slate-500">+{trace.timeOffsetMs}ms</td>
                    <td className="py-3 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          trace.method === 'GET'
                            ? 'bg-cyan-500/20 text-cyan-300'
                            : trace.method === 'POST'
                            ? 'bg-purple-500/20 text-purple-300'
                            : 'bg-slate-800 text-slate-300'
                        }`}
                      >
                        {trace.method}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-sans">
                      <div className="font-mono text-xs text-slate-200 truncate max-w-md">{trace.url}</div>
                      {trace.suspicionReasons.length > 0 && (
                        <div className="text-[10px] text-rose-400 font-semibold mt-0.5">
                          ⚠️ {trace.suspicionReasons[0]}
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        {trace.responseCode} {trace.responseStatus.split(' ')[1] || 'OK'}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-[11px] truncate max-w-xs">{trace.contentType}</td>
                    <td className="py-3 px-4 text-right text-slate-400">
                      {(trace.bytesReceived / 1024).toFixed(1)} KB
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* VIEW 3: LIVE SANDBOX LOGCAT */}
      {activeSubTab === 'logcat' && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-1.5">
              {(['all', 'error', 'warn', 'info'] as const).map((lvl) => (
                <button
                  key={lvl}
                  onClick={() => setLogFilter(lvl)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold uppercase tracking-wider transition cursor-pointer ${
                    logFilter === lvl
                      ? 'bg-cyan-500 text-slate-950'
                      : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {lvl}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={handleExportLogcat}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export Logcat</span>
              </button>
            </div>
          </div>

          <div className="p-4 rounded-2xl bg-slate-950 border border-slate-800 font-mono text-xs overflow-y-auto max-h-[500px] space-y-1.5 shadow-inner">
            {filteredLogs.map((log) => (
              <div key={log.id} className="flex items-start gap-2 leading-relaxed">
                <span className="text-slate-600 select-none shrink-0">{log.timestamp}</span>
                <span
                  className={`px-1.5 py-0.2 rounded text-[10px] font-bold shrink-0 ${
                    log.level === 'ERROR'
                      ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                      : log.level === 'WARN'
                      ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                      : log.level === 'DEBUG'
                      ? 'bg-purple-500/20 text-purple-400'
                      : 'bg-slate-800 text-cyan-400'
                  }`}
                >
                  {log.tag}
                </span>
                <span
                  className={
                    log.level === 'ERROR'
                      ? 'text-rose-300 font-semibold'
                      : log.level === 'WARN'
                      ? 'text-amber-200'
                      : log.level === 'DEBUG'
                      ? 'text-slate-400'
                      : 'text-slate-200'
                  }
                >
                  {log.message}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* VIEW 4: VIRTUAL RUNTIME SPECS */}
      {activeSubTab === 'device' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
              <Smartphone className="w-4 h-4 text-cyan-400" />
              Isolated Virtual Device Environment
            </h3>

            <div className="space-y-3 text-xs">
              <div className="flex justify-between py-2 border-b border-slate-800">
                <span className="text-slate-400">Emulated Device</span>
                <span className="font-semibold text-slate-200">{sandbox.environment.deviceModel}</span>
              </div>
              <div className="flex justify-between py-2 border-b border-slate-800">
                <span className="text-slate-400">Operating System</span>
                <span className="font-semibold text-slate-200">{sandbox.environment.osVersion}</span>
              </div>
              <div className="flex justify-between py-2 border-b border-slate-800">
                <span className="text-slate-400">Runtime Subsystem</span>
                <span className="font-semibold text-slate-200">{sandbox.environment.runtime}</span>
              </div>
              <div className="flex justify-between py-2 border-b border-slate-800">
                <span className="text-slate-400">Security Sandbox Isolation</span>
                <span className="font-semibold text-emerald-400">{sandbox.environment.securityLevel}</span>
              </div>
              <div className="flex justify-between py-2 border-b border-slate-800">
                <span className="text-slate-400">Virtual Interface MAC</span>
                <span className="font-mono text-slate-300">{sandbox.environment.macAddress}</span>
              </div>
              <div className="flex justify-between py-2">
                <span className="text-slate-400">Mock Telephony IMEI</span>
                <span className="font-mono text-slate-300">{sandbox.environment.mockImei}</span>
              </div>
            </div>
          </div>

          <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
              <Lock className="w-4 h-4 text-amber-400" />
              Anti-Analysis Evasion Traps ({sandbox.evasionTechniquesDetected.length})
            </h3>

            {sandbox.evasionTechniquesDetected.length === 0 ? (
              <div className="p-8 text-center rounded-xl bg-slate-950/50 border border-slate-800/80">
                <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
                <p className="text-xs text-slate-300 font-semibold">No Anti-Sandbox Evasion Code Found</p>
                <p className="text-[11px] text-slate-500 mt-1">The application does not attempt to detect virtual machines, root states, or debug hooks.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {sandbox.evasionTechniquesDetected.map((trick, idx) => (
                  <div key={idx} className="p-3.5 rounded-xl bg-amber-950/20 border border-amber-500/30 text-xs text-slate-300 space-y-1">
                    <div className="flex items-center gap-1.5 text-amber-300 font-semibold">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                      <span>Evasion Pattern #{idx + 1}</span>
                    </div>
                    <p className="text-slate-400 leading-relaxed">{trick}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
