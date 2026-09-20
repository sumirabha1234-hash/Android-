import React from 'react';
import { Shield, ShieldAlert, ShieldCheck, Download, FileText, Upload, RefreshCw, Sparkles, Terminal } from 'lucide-react';
import { ApkAnalysisResult } from '../types';

interface NavbarProps {
  analysis: ApkAnalysisResult | null;
  onOpenUpload: () => void;
  onDownloadZip: () => void;
  onExportJson: () => void;
  isDownloadingZip: boolean;
  activeTab: string;
}

export const Navbar: React.FC<NavbarProps> = ({
  analysis,
  onOpenUpload,
  onDownloadZip,
  onExportJson,
  isDownloadingZip,
}) => {
  return (
    <header className="border-b border-slate-800 bg-slate-950/90 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 ring-1 ring-cyan-400/30">
            <Terminal className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-lg tracking-tight bg-gradient-to-r from-slate-100 via-slate-200 to-slate-400 bg-clip-text text-transparent">
                APK Guard <span className="text-cyan-400 text-sm font-mono">2.01</span>
              </span>
              <span className="text-[10px] uppercase font-mono font-bold tracking-wider px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                Security Audit
              </span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">
              Static Bytecode Decompiler &amp; Threat Intelligence
            </p>
          </div>
        </div>

        {/* Current Binary Status & Actions */}
        <div className="flex items-center gap-2 sm:gap-3">
          {analysis && (
            <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/80 border border-slate-800 text-xs font-mono">
              <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-slate-300 font-medium truncate max-w-[160px]">
                {analysis.packageName}
              </span>
              <span className="text-slate-500">v{analysis.versionName}</span>
              <div className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                analysis.securityRating === 'A+' || analysis.securityRating === 'A'
                  ? 'bg-emerald-500/20 text-emerald-400'
                  : analysis.securityRating === 'B' || analysis.securityRating === 'C'
                  ? 'bg-amber-500/20 text-amber-400'
                  : 'bg-rose-500/20 text-rose-400'
              }`}>
                Score: {analysis.securityScore}/100 ({analysis.securityRating})
              </div>
            </div>
          )}

          {/* Upload Button */}
          <button
            onClick={onOpenUpload}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 text-xs font-medium transition cursor-pointer"
          >
            <Upload className="w-3.5 h-3.5 text-cyan-400" />
            <span className="hidden sm:inline">Upload APK</span>
          </button>

          {/* Export Zip Button */}
          {analysis && (
            <button
              onClick={onDownloadZip}
              disabled={isDownloadingZip}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-md shadow-cyan-900/30 transition cursor-pointer disabled:opacity-50"
              title="Download full decompiled files as a ZIP archive"
            >
              {isDownloadingZip ? (
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Download className="w-3.5 h-3.5" />
              )}
              <span className="hidden sm:inline">Download Decompiled ZIP</span>
              <span className="sm:hidden">ZIP</span>
            </button>
          )}
        </div>
      </div>
    </header>
  );
};
