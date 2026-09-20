import React, { useState } from 'react';
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
  Cpu
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
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
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
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {!analysis ? (
          <UploadZone
            onFileSelected={handleFileSelected}
            isAnalyzing={isAnalyzing}
            analyzingStep={analyzingStep}
          />
        ) : (
          <div className="space-y-6">
            {/* Header / Active Binary Banner */}
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl">
              <div className="flex items-center gap-4">
                <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-inner">
                  <Terminal className="w-7 h-7" />
                </div>
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <h1 className="text-xl font-extrabold text-slate-100 tracking-tight">
                      {analysis.appName}
                    </h1>
                    <span className="text-xs font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/60">
                      {analysis.packageName}
                    </span>
                  </div>
                  <div className="flex items-center gap-3 text-xs text-slate-400 mt-1 font-mono flex-wrap">
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
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition cursor-pointer"
                >
                  <FileText className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Audit Report</span>
                </button>

                <button
                  onClick={handleDownloadZip}
                  disabled={isDownloadingZip}
                  className="flex items-center gap-1.5 px-4 py-1.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white text-xs font-bold shadow-lg shadow-cyan-500/20 transition cursor-pointer disabled:opacity-50"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>{isDownloadingZip ? 'Zipping...' : 'Download Decompiled ZIP'}</span>
                </button>

                <button
                  onClick={() => setAnalysis(null)}
                  className="p-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 text-xs border border-slate-700 transition cursor-pointer"
                  title="Upload Another APK"
                >
                  <Upload className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Navigation Tabs */}
            <div className="flex items-center gap-1.5 p-1.5 rounded-2xl bg-slate-900/90 border border-slate-800 overflow-x-auto">
              <button
                onClick={() => setActiveTab('overview')}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold whitespace-nowrap transition cursor-pointer ${
                  activeTab === 'overview'
                    ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <Activity className="w-4 h-4" />
                <span>Overview &amp; Scores</span>
              </button>

              <button
                onClick={() => setActiveTab('vulnerabilities')}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold whitespace-nowrap transition cursor-pointer ${
                  activeTab === 'vulnerabilities'
                    ? 'bg-gradient-to-r from-rose-500/20 to-amber-500/20 text-rose-300 border border-rose-500/40 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <ShieldAlert className="w-4 h-4" />
                <span>Vulnerabilities</span>
                <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-rose-500/20 text-rose-400 font-bold">
                  {analysis.vulnerabilities.length}
                </span>
              </button>

              <button
                onClick={() => setActiveTab('endpoints')}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold whitespace-nowrap transition cursor-pointer ${
                  activeTab === 'endpoints'
                    ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <Globe className="w-4 h-4" />
                <span>Network &amp; URLs</span>
                <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-cyan-500/20 text-cyan-400 font-bold">
                  {analysis.endpoints.length}
                </span>
              </button>

              <button
                onClick={() => setActiveTab('permissions')}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold whitespace-nowrap transition cursor-pointer ${
                  activeTab === 'permissions'
                    ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <Lock className="w-4 h-4" />
                <span>Permissions</span>
                <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-amber-500/20 text-amber-400 font-bold">
                  {analysis.permissions.length}
                </span>
              </button>

              <button
                onClick={() => setActiveTab('signature')}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold whitespace-nowrap transition cursor-pointer ${
                  activeTab === 'signature'
                    ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <Award className="w-4 h-4" />
                <span>Signatures &amp; Certs</span>
              </button>

              <button
                onClick={() => setActiveTab('code')}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold whitespace-nowrap transition cursor-pointer ${
                  activeTab === 'code'
                    ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <FileCode className="w-4 h-4" />
                <span>Decompiled Source</span>
              </button>

              <button
                onClick={() => setActiveTab('binary')}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold whitespace-nowrap transition cursor-pointer ${
                  activeTab === 'binary'
                    ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <Cpu className="w-4 h-4 text-cyan-400" />
                <span>Native Binary Decompiler</span>
                {analysis.binaryAnalysis && analysis.binaryAnalysis.length > 0 && (
                  <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/30">
                    {analysis.binaryAnalysis.length} ELF
                  </span>
                )}
              </button>

              <button
                onClick={() => setActiveTab('sandbox')}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold whitespace-nowrap transition cursor-pointer ${
                  activeTab === 'sandbox'
                    ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <Smartphone className="w-4 h-4 text-cyan-400" />
                <span>Isolated Android Sandbox</span>
                {analysis.dynamicSandbox.downloadedFiles.length > 0 ? (
                  <span className="ml-1 px-1.5 py-0.2 bg-rose-500/20 text-rose-300 text-[10px] rounded-full border border-rose-500/30">
                    {analysis.dynamicSandbox.downloadedFiles.length} DL Trapped
                  </span>
                ) : (
                  <span className="ml-1 px-1.5 py-0.2 bg-emerald-500/20 text-emerald-300 text-[10px] rounded-full border border-emerald-500/30">
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
