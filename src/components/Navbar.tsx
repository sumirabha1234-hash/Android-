import React from 'react';
import { Upload, Download, RefreshCw, Terminal, Shield } from 'lucide-react';
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
  isDownloadingZip,
}) => {
  return (
    <header className="px-6 sm:px-10 py-5 border-b-2 border-[#edeff2] bg-[#0c0c0e]/95 backdrop-blur-md sticky top-0 z-40 flex items-center justify-between gap-4">
      {/* Brand */}
      <div className="flex items-center gap-3 sm:gap-4">
        <div className="w-10 h-10 sm:w-11 sm:h-11 bg-[#edeff2] text-[#0c0c0e] flex items-center justify-center shrink-0">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
            <path d="M12 19h8" />
            <path d="m4 17 6-6-6-6" />
          </svg>
        </div>
        <div className="title-group">
          <div className="flex items-center">
            <h1 className="font-syne text-lg sm:text-xl font-extrabold uppercase tracking-tight text-[#edeff2]">
              APK Guard
            </h1>
            <span className="font-mono text-[0.65rem] px-1.5 py-0.5 border border-[#edeff2] ml-2 text-[#edeff2]">
              2.01
            </span>
          </div>
          <div className="font-mono text-[0.6rem] uppercase tracking-[0.15em] text-[#edeff2]/50 mt-0.5 hidden xs:block">
            Static Bytecode Decompiler &amp; Threat Intelligence
          </div>
        </div>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-2 sm:gap-3">
        {analysis && (
          <div className="hidden md:flex items-center gap-2 px-3 py-1.5 border border-[#edeff2]/20 font-mono text-[0.68rem] bg-[#141418]">
            <span className="inline-block w-2 h-2 rounded-full bg-[#00f2ff] animate-pulse" />
            <span className="text-[#edeff2] font-semibold truncate max-w-[150px]">
              {analysis.packageName}
            </span>
            <span className="text-[#edeff2]/50">v{analysis.versionName}</span>
            <span className="text-[#00f2ff] font-bold border-l border-[#edeff2]/20 pl-2">
              SCORE: {analysis.securityScore}/100 ({analysis.securityRating})
            </span>
          </div>
        )}

        {analysis ? (
          <>
            <button
              onClick={onOpenUpload}
              className="flex items-center gap-1.5 px-3 py-2 border border-[#edeff2] text-[#edeff2] hover:bg-[#edeff2] hover:text-[#0c0c0e] font-mono text-[0.68rem] uppercase tracking-wider transition cursor-pointer"
            >
              <Upload className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">New Audit</span>
            </button>

            <button
              onClick={onDownloadZip}
              disabled={isDownloadingZip}
              className="flex items-center gap-1.5 px-4 py-2 bg-[#00f2ff] text-[#0c0c0e] font-syne font-extrabold text-[0.72rem] uppercase tracking-wider hover:brightness-110 disabled:opacity-50 transition cursor-pointer"
            >
              {isDownloadingZip ? (
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Download className="w-3.5 h-3.5" />
              )}
              <span className="hidden sm:inline">Export Decompiled ZIP</span>
              <span className="sm:hidden">ZIP</span>
            </button>
          </>
        ) : (
          <div className="px-3 sm:px-5 py-2 bg-[#edeff2] text-[#0c0c0e] font-mono text-[0.68rem] font-bold uppercase tracking-wider border border-[#edeff2]">
            System Audit
          </div>
        )}
      </div>
    </header>
  );
};
