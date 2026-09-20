import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  FileCode,
  Globe,
  Lock,
  Layers,
  Sparkles,
  Upload,
  Download,
  FileText,
  Terminal,
  Activity,
  Award,
  Smartphone,
  DownloadCloud,
  Cpu,
  Send
} from 'lucide-react';
import { Navbar } from './components/Navbar';
import { UploadZone } from './components/UploadZone';
import { OverviewTab } from './components/OverviewTab';
import { VulnerabilitiesTab } from './components/VulnerabilitiesTab';
import { PermissionsTab } from './components/PermissionsTab';
import { EndpointsTab } from './components/EndpointsTab';
import { SignatureTab } from './components/SignatureTab';
import { CodeExplorerTab } from './components/CodeExplorerTab';
import { SandboxTab } from './components/SandboxTab';
import { BinaryDecompilerTab } from './components/BinaryDecompilerTab';
import { ReportModal } from './components/ReportModal';
import { ApkAnalysisResult } from './types';
import { analyzeApkFile, analyzeBinaryStandalone, createDecompiledZip } from './lib/apk-analyzer';

export function App() {
  const [analysis, setAnalysis] = useState<ApkAnalysisResult | null>(null);
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [analyzingStep, setAnalyzingStep] = useState<string>('');
  const [isDownloadingZip, setIsDownloadingZip] = useState<boolean>(false);
  const [isReportModalOpen, setIsReportModalOpen] = useState<boolean>(false);
  const [selectedCodePath, setSelectedCodePath] = useState<string>('AndroidManifest.xml');
  const [realLatency, setRealLatency] = useState<number | null>(null);

  // Measure real network round-trip ping latency
  useEffect(() => {
    const measureLatency = async () => {
      const start = performance.now();
      try {
        await fetch('/api/health', { method: 'GET', cache: 'no-store' });
        const latency = Math.max(1, Math.round(performance.now() - start));
        setRealLatency(latency);
      } catch {
        // Fallback measure client execution frame time
        const frameTime = Math.max(1, Math.round(performance.now() - start));
        setRealLatency(frameTime);
      }
    };

    measureLatency();
    const interval = setInterval(measureLatency, 10000);
    return () => clearInterval(interval);
  }, []);

  // Handle uploaded APK or Standalone Binary file
  const handleFileSelected = async (file: File) => {
    setIsAnalyzing(true);
    const lower = file.name.toLowerCase();
    const isStandaloneBinary =
      lower.endsWith('.so') ||
      lower.endsWith('.elf') ||
      lower.endsWith('.bin') ||
      lower.endsWith('.dex') ||
      lower.endsWith('.o') ||
      lower.endsWith('.dll') ||
      lower.endsWith('.dylib');

    setAnalyzingStep(
      isStandaloneBinary
        ? 'Reading binary stream, extracting ELF headers & disassembling...'
        : 'Unpacking binary APK package & reading headers...'
    );

    try {
      const result = isStandaloneBinary
        ? await analyzeBinaryStandalone(file, file.name, (step) => setAnalyzingStep(step))
        : await analyzeApkFile(file, file.name, (step) => setAnalyzingStep(step));

      setAnalysis(result);
      setActiveTab(isStandaloneBinary ? 'binary' : 'overview');
    } catch (err: any) {
      console.error('Analysis error:', err);
      alert(`Failed to analyze file: ${err.message || 'Unknown error'}`);
    } finally {
      setIsAnalyzing(false);
      setAnalyzingStep('');
    }
  };

  // Download full decompiled ZIP
  const handleDownloadZip = async () => {
    if (!analysis) return;
    setIsDownloadingZip(true);
    try {
      const zipBlob = await createDecompiledZip(analysis);
      const url = URL.createObjectURL(zipBlob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${analysis.packageName || 'apk'}-decompiled-source.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      console.error('Error generating decompiled ZIP:', err);
      alert('Failed to generate ZIP archive: ' + err.message);
    } finally {
      setIsDownloadingZip(false);
    }
  };

  // Export JSON Report
  const handleExportJson = () => {
    if (!analysis) return;
    const jsonStr = JSON.stringify(analysis, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${analysis.packageName}-security-audit.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleNavigateToCode = (filePath: string) => {
    setSelectedCodePath(filePath);
    setActiveTab('code');
  };

  return (
    <div className="min-h-screen bg-[#0c0c0e] text-[#edeff2] flex flex-col font-sans selection:bg-[#00f2ff] selection:text-[#0c0c0e] relative">
      {/* Background Technical Grid Texture */}
      <div className="grid-bg" />

      {/* Top Navbar */}
      <Navbar
        analysis={analysis}
        onOpenUpload={() => setAnalysis(null)}
        onDownloadZip={handleDownloadZip}
        onExportJson={handleExportJson}
        isDownloadingZip={isDownloadingZip}
        activeTab={activeTab}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-[1400px] w-full mx-auto px-6 sm:px-10 py-6 sm:py-8 relative z-10">
        {!analysis ? (
          <UploadZone
            onFileSelected={handleFileSelected}
            isAnalyzing={isAnalyzing}
            analyzingStep={analyzingStep}
          />
        ) : (
          <div className="space-y-6">
            {/* Header / Active Binary Banner */}
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 border-2 border-[#edeff2] bg-[#141418]/80 backdrop-blur-sm shadow-xl">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 bg-[#edeff2] text-[#0c0c0e] flex items-center justify-center font-bold">
                  <Terminal className="w-6 h-6" />
                </div>
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <h1 className="font-syne text-xl font-extrabold uppercase tracking-tight text-[#edeff2]">
                      {analysis.appName}
                    </h1>
                    <span className="font-mono text-xs text-[#00f2ff] bg-[#00f2ff]/10 px-2 py-0.5 border border-[#00f2ff]/30">
                      {analysis.packageName}
                    </span>
                  </div>
                  <div className="flex items-center gap-3 text-xs text-[#edeff2]/60 mt-1 font-mono flex-wrap">
                    <span>v{analysis.versionName} (Build {analysis.versionCode})</span>
                    <span>&bull;</span>
                    <span>Target SDK {analysis.targetSdkVersion} (Min {analysis.minSdkVersion})</span>
                    <span>&bull;</span>
                    <span>{(analysis.fileSize / (1024 * 1024)).toFixed(2)} MB</span>
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center gap-2 flex-wrap">
                <button
                  onClick={() => setIsReportModalOpen(true)}
                  className="flex items-center gap-1.5 px-3.5 py-2 bg-transparent hover:bg-[#edeff2]/10 text-[#edeff2] text-xs font-mono uppercase tracking-wider border border-[#edeff2]/30 transition cursor-pointer"
                >
                  <FileText className="w-3.5 h-3.5 text-[#00f2ff]" />
                  <span>Audit Report</span>
                </button>

                <button
                  onClick={handleDownloadZip}
                  disabled={isDownloadingZip}
                  className="flex items-center gap-1.5 px-4 py-2 bg-[#00f2ff] hover:brightness-110 text-[#0c0c0e] text-xs font-syne font-extrabold uppercase tracking-wider transition cursor-pointer disabled:opacity-50"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>{isDownloadingZip ? 'Zipping...' : 'Download Decompiled ZIP'}</span>
                </button>

                <button
                  onClick={() => setAnalysis(null)}
                  className="p-2 border border-[#edeff2]/30 hover:bg-[#edeff2]/10 text-[#edeff2] text-xs transition cursor-pointer"
                  title="Upload Another APK"
                >
                  <Upload className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Navigation Tabs */}
            <div className="flex items-center gap-1 p-1 bg-[#0c0c0e] border border-[#edeff2]/20 overflow-x-auto">
              <button
                onClick={() => setActiveTab('overview')}
                className={`flex items-center gap-2 px-4 py-2.5 text-xs font-mono uppercase tracking-wider whitespace-nowrap transition cursor-pointer ${
                  activeTab === 'overview'
                    ? 'bg-[#edeff2] text-[#0c0c0e] font-bold'
                    : 'text-[#edeff2]/60 hover:text-[#edeff2] hover:bg-[#edeff2]/5'
                }`}
              >
                <Activity className="w-4 h-4" />
                <span>Overview &amp; Scores</span>
              </button>

              <button
                onClick={() => setActiveTab('vulnerabilities')}
                className={`flex items-center gap-2 px-4 py-2.5 text-xs font-mono uppercase tracking-wider whitespace-nowrap transition cursor-pointer ${
                  activeTab === 'vulnerabilities'
                    ? 'bg-[#edeff2] text-[#0c0c0e] font-bold'
                    : 'text-[#edeff2]/60 hover:text-[#edeff2] hover:bg-[#edeff2]/5'
                }`}
              >
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                <span>Vulnerabilities</span>
                <span className="px-1.5 py-0.2 text-[10px] font-mono bg-rose-500/20 text-rose-400 font-bold border border-rose-500/30">
                  {analysis.vulnerabilities.length}
                </span>
              </button>

              <button
                onClick={() => setActiveTab('endpoints')}
                className={`flex items-center gap-2 px-4 py-2.5 text-xs font-mono uppercase tracking-wider whitespace-nowrap transition cursor-pointer ${
                  activeTab === 'endpoints'
                    ? 'bg-[#edeff2] text-[#0c0c0e] font-bold'
                    : 'text-[#edeff2]/60 hover:text-[#edeff2] hover:bg-[#edeff2]/5'
                }`}
              >
                <Globe className="w-4 h-4 text-[#00f2ff]" />
                <span>Network &amp; URLs</span>
                <span className="px-1.5 py-0.2 text-[10px] font-mono bg-[#00f2ff]/20 text-[#00f2ff] font-bold border border-[#00f2ff]/30">
                  {analysis.endpoints.length}
                </span>
              </button>

              <button
                onClick={() => setActiveTab('permissions')}
                className={`flex items-center gap-2 px-4 py-2.5 text-xs font-mono uppercase tracking-wider whitespace-nowrap transition cursor-pointer ${
                  activeTab === 'permissions'
                    ? 'bg-[#edeff2] text-[#0c0c0e] font-bold'
                    : 'text-[#edeff2]/60 hover:text-[#edeff2] hover:bg-[#edeff2]/5'
                }`}
              >
                <Lock className="w-4 h-4 text-amber-400" />
                <span>Permissions</span>
                <span className="px-1.5 py-0.2 text-[10px] font-mono bg-amber-500/20 text-amber-400 font-bold border border-amber-500/30">
                  {analysis.permissions.length}
                </span>
              </button>

              <button
                onClick={() => setActiveTab('signature')}
                className={`flex items-center gap-2 px-4 py-2.5 text-xs font-mono uppercase tracking-wider whitespace-nowrap transition cursor-pointer ${
                  activeTab === 'signature'
                    ? 'bg-[#edeff2] text-[#0c0c0e] font-bold'
                    : 'text-[#edeff2]/60 hover:text-[#edeff2] hover:bg-[#edeff2]/5'
                }`}
              >
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span>Signature &amp; Certs</span>
              </button>

              <button
                onClick={() => setActiveTab('code')}
                className={`flex items-center gap-2 px-4 py-2.5 text-xs font-mono uppercase tracking-wider whitespace-nowrap transition cursor-pointer ${
                  activeTab === 'code'
                    ? 'bg-[#edeff2] text-[#0c0c0e] font-bold'
                    : 'text-[#edeff2]/60 hover:text-[#edeff2] hover:bg-[#edeff2]/5'
                }`}
              >
                <FileCode className="w-4 h-4 text-[#00f2ff]" />
                <span>Decompiled Source</span>
                <span className="px-1.5 py-0.2 text-[10px] font-mono bg-[#edeff2]/20 text-[#edeff2] font-bold">
                  {analysis.decompiledFiles.length}
                </span>
              </button>

              <button
                onClick={() => setActiveTab('binary')}
                className={`flex items-center gap-2 px-4 py-2.5 text-xs font-mono uppercase tracking-wider whitespace-nowrap transition cursor-pointer ${
                  activeTab === 'binary'
                    ? 'bg-[#edeff2] text-[#0c0c0e] font-bold'
                    : 'text-[#edeff2]/60 hover:text-[#edeff2] hover:bg-[#edeff2]/5'
                }`}
              >
                <Cpu className="w-4 h-4 text-[#00f2ff]" />
                <span>ARM64 Native ELF &bull; C/C++ AST</span>
                {analysis.nativeLibraries && analysis.nativeLibraries.length > 0 && (
                  <span className="px-1.5 py-0.2 text-[10px] font-mono bg-[#00f2ff]/20 text-[#00f2ff] font-bold">
                    {analysis.nativeLibraries.length}
                  </span>
                )}
              </button>

              <button
                onClick={() => setActiveTab('sandbox')}
                className={`flex items-center gap-2 px-4 py-2.5 text-xs font-mono uppercase tracking-wider whitespace-nowrap transition cursor-pointer ${
                  activeTab === 'sandbox'
                    ? 'bg-[#edeff2] text-[#0c0c0e] font-bold'
                    : 'text-[#edeff2]/60 hover:text-[#edeff2] hover:bg-[#edeff2]/5'
                }`}
              >
                <Smartphone className="w-4 h-4 text-[#00f2ff]" />
                <span>Isolated Android Sandbox</span>
                {analysis.dynamicSandbox.downloadedFiles.length > 0 ? (
                  <span className="ml-1 px-1.5 py-0.2 bg-rose-500/20 text-rose-300 text-[10px] font-mono border border-rose-500/30">
                    {analysis.dynamicSandbox.downloadedFiles.length} DL Trapped
                  </span>
                ) : (
                  <span className="ml-1 px-1.5 py-0.2 bg-emerald-500/20 text-emerald-300 text-[10px] font-mono border border-emerald-500/30">
                    Clean
                  </span>
                )}
              </button>
            </div>

            {/* Tab Views */}
            {activeTab === 'overview' && (
              <OverviewTab analysis={analysis} onNavigateTab={setActiveTab} />
            )}

            {activeTab === 'binary' && (
              <BinaryDecompilerTab
                analysis={analysis}
                onNavigateToCode={handleNavigateToCode}
              />
            )}

            {activeTab === 'sandbox' && (
              <SandboxTab
                analysis={analysis}
                onUpdateAnalysis={setAnalysis}
              />
            )}

            {activeTab === 'vulnerabilities' && (
              <VulnerabilitiesTab
                vulnerabilities={analysis.vulnerabilities}
                onViewInCode={handleNavigateToCode}
              />
            )}

            {activeTab === 'endpoints' && (
              <EndpointsTab endpoints={analysis.endpoints} />
            )}

            {activeTab === 'permissions' && (
              <PermissionsTab permissions={analysis.permissions} />
            )}

            {activeTab === 'signature' && (
              <SignatureTab signature={analysis.signature} />
            )}

            {activeTab === 'code' && (
              <CodeExplorerTab
                files={analysis.decompiledFiles}
                vulnerabilities={analysis.vulnerabilities}
                initialSelectedPath={selectedCodePath}
                analysisResult={analysis}
              />
            )}
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="px-6 sm:px-10 py-5 border-t border-[#edeff2]/10 flex flex-col sm:flex-row items-center justify-between gap-4 font-mono text-[0.65rem] text-[#edeff2]/50 uppercase tracking-wider relative z-10">
        <div className="flex items-center gap-3">
          <span>&copy; 2024 APK_GUARD_SYSTEM</span>
          <span className="text-[#edeff2]/20">&bull;</span>
          <a
            href="https://t.me/nayanmoni"
            target="_blank"
            rel="noopener noreferrer"
            className="text-[#00f2ff] hover:underline flex items-center gap-1 font-semibold"
          >
            <Send className="w-3 h-3" />
            <span>Contact: @nayanmoni</span>
          </a>
        </div>
        <div className="flex flex-wrap items-center gap-6 sm:gap-8">
          <div><strong className="text-[#edeff2] mr-1">SECURE_HASH:</strong> SHA-256</div>
          <div><strong className="text-[#edeff2] mr-1">CORE:</strong> V2.01.ALPHA</div>
          <div className="flex items-center gap-1.5">
            <span className="inline-block w-1.5 h-1.5 rounded-full bg-[#00f2ff] animate-pulse" />
            <strong className="text-[#edeff2]">LATENCY:</strong>
            <span className="text-[#00f2ff] font-bold">{realLatency !== null ? `${realLatency}ms` : 'Measuring...'}</span>
          </div>
        </div>
      </footer>

      {/* Report & Export Modal */}
      {analysis && (
        <ReportModal
          isOpen={isReportModalOpen}
          onClose={() => setIsReportModalOpen(false)}
          analysis={analysis}
          onDownloadZip={handleDownloadZip}
          onExportJson={handleExportJson}
          isDownloadingZip={isDownloadingZip}
        />
      )}
    </div>
  );
}

export default App;
