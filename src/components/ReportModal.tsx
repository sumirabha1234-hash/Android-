import React, { useState } from 'react';
import {
  Download,
  FileText,
  X,
  CheckCircle2,
  ShieldAlert,
  Sparkles,
  Printer,
  Lock,
  Sliders,
  FileSpreadsheet,
  Globe,
  Award,
  Key,
  Layers,
  Settings,
  Eye,
  Check,
  RefreshCw,
  Share2
} from 'lucide-react';
import { ApkAnalysisResult } from '../types';
import {
  ReportCustomizationOptions,
  DEFAULT_REPORT_OPTIONS,
  generatePdfReport,
  generateCsvReport,
  generateMarkdownReport,
  getFilteredVulnerabilities,
  getFilteredEndpoints,
  getFilteredPermissions,
} from '../lib/report-exporter';

interface ReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  analysis: ApkAnalysisResult;
  onDownloadZip: () => void;
  onExportJson: () => void;
  isDownloadingZip: boolean;
}

export const ReportModal: React.FC<ReportModalProps> = ({
  isOpen,
  onClose,
  analysis,
  onDownloadZip,
  isDownloadingZip,
}) => {
  const [options, setOptions] = useState<ReportCustomizationOptions>({
    ...DEFAULT_REPORT_OPTIONS,
    reportTitle: `Security Audit Report - ${analysis.appName || analysis.packageName}`,
  });

  const [activeTab, setActiveTab] = useState<'export' | 'customize' | 'preview'>('export');
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);
  const [copiedFormat, setCopiedFormat] = useState<string | null>(null);

  if (!isOpen) return null;

  // Handler for PDF Download
  const handleDownloadPdf = async () => {
    setIsGeneratingPdf(true);
    try {
      const pdfBlob = await generatePdfReport(analysis, options);
      const url = URL.createObjectURL(pdfBlob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${analysis.packageName}-security-audit-report.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      console.error('Error generating PDF:', err);
      alert('Failed to generate PDF: ' + err.message);
    } finally {
      setIsGeneratingPdf(false);
    }
  };

  // Handler for CSV Download
  const handleDownloadCsv = (dataset: 'all' | 'vulnerabilities' | 'endpoints' | 'permissions' | 'secrets') => {
    try {
      const csvContent = generateCsvReport(analysis, dataset, options);
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${analysis.packageName}-${dataset}-audit.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      console.error('Error generating CSV:', err);
      alert('Failed to export CSV: ' + err.message);
    }
  };

  // Handler for Custom JSON Download
  const handleDownloadCustomJson = () => {
    try {
      const filteredVulns = getFilteredVulnerabilities(analysis.vulnerabilities, options.severityFilter);
      const filteredEndpoints = getFilteredEndpoints(analysis.endpoints, options.endpointInsecureOnly);
      const filteredPermissions = getFilteredPermissions(analysis.permissions, options.permissionDangerousOnly);

      const customReportPayload = {
        metadata: {
          reportTitle: options.reportTitle,
          auditor: options.auditorName,
          organization: options.organization,
          generatedAt: new Date().toISOString(),
          apkFileName: analysis.fileName,
          packageName: analysis.packageName,
          versionName: analysis.versionName,
          versionCode: analysis.versionCode,
          sha256: analysis.sha256,
          securityScore: analysis.securityScore,
          securityRating: analysis.securityRating,
          threatLevel: analysis.threatLevel,
        },
        executiveStats: analysis.stats,
        ...(options.includeVulnerabilities ? { vulnerabilities: filteredVulns } : {}),
        ...(options.includeSecrets ? { hardcodedSecrets: analysis.secrets } : {}),
        ...(options.includeEndpoints ? { networkEndpoints: filteredEndpoints } : {}),
        ...(options.includePermissions ? { permissions: filteredPermissions } : {}),
        ...(options.includeSignatures ? { signatureDetails: analysis.signature } : {}),
        ...(options.includeSandbox ? { dynamicSandboxSimulation: analysis.dynamicSandbox } : {}),
      };

      const jsonStr = JSON.stringify(customReportPayload, null, 2);
      const blob = new Blob([jsonStr], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${analysis.packageName}-security-audit.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      console.error('Error generating JSON:', err);
      alert('Failed to export JSON: ' + err.message);
    }
  };

  // Handler for Markdown Download
  const handleDownloadMarkdown = () => {
    try {
      const mdContent = generateMarkdownReport(analysis, options);
      const blob = new Blob([mdContent], { type: 'text/markdown;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${analysis.packageName}-audit-report.md`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      console.error('Error generating Markdown:', err);
      alert('Failed to export Markdown: ' + err.message);
    }
  };

  const handleCopyMarkdown = () => {
    const md = generateMarkdownReport(analysis, options);
    navigator.clipboard.writeText(md);
    setCopiedFormat('md');
    setTimeout(() => setCopiedFormat(null), 2000);
  };

  const filteredVulns = getFilteredVulnerabilities(analysis.vulnerabilities, options.severityFilter);
  const filteredEndpoints = getFilteredEndpoints(analysis.endpoints, options.endpointInsecureOnly);
  const filteredPermissions = getFilteredPermissions(analysis.permissions, options.permissionDangerousOnly);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-slate-950/85 backdrop-blur-md overflow-y-auto">
      <div className="relative w-full max-w-4xl rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl text-slate-100 max-h-[92vh] flex flex-col overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/60">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 text-cyan-400 border border-cyan-500/30">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                Advanced Security Report &amp; Audit Exporter
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                {analysis.packageName} (v{analysis.versionName}) &bull; Score: {analysis.securityScore}/100 ({analysis.securityRating})
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <div className="flex items-center bg-slate-950 rounded-lg p-1 border border-slate-800 text-xs font-medium">
              <button
                onClick={() => setActiveTab('export')}
                className={`px-3 py-1 rounded-md transition cursor-pointer ${
                  activeTab === 'export' ? 'bg-cyan-500/20 text-cyan-300 font-bold' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Export Formats
              </button>
              <button
                onClick={() => setActiveTab('customize')}
                className={`px-3 py-1 rounded-md transition cursor-pointer flex items-center gap-1 ${
                  activeTab === 'customize' ? 'bg-cyan-500/20 text-cyan-300 font-bold' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Sliders className="w-3.5 h-3.5" />
                Customize Data
              </button>
              <button
                onClick={() => setActiveTab('preview')}
                className={`px-3 py-1 rounded-md transition cursor-pointer flex items-center gap-1 ${
                  activeTab === 'preview' ? 'bg-cyan-500/20 text-cyan-300 font-bold' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Eye className="w-3.5 h-3.5" />
                Live Preview
              </button>
            </div>

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Tab 1: Export Formats Hub */}
        {activeTab === 'export' && (
          <div className="flex-1 overflow-y-auto p-6 space-y-6 text-xs">
            {/* Summary Highlights */}
            <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 flex items-center justify-between flex-wrap gap-4">
              <div>
                <div className="font-bold text-slate-200 text-sm">{options.reportTitle}</div>
                <div className="text-slate-400 text-xs font-mono mt-0.5">
                  Auditor: <strong className="text-slate-300">{options.auditorName}</strong> ({options.organization})
                </div>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-[11px] font-mono px-2 py-1 rounded bg-slate-900 border border-slate-700 text-slate-300">
                  {filteredVulns.length} Findings Selected
                </span>
                <button
                  onClick={() => setActiveTab('customize')}
                  className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-400 font-medium text-xs border border-slate-700 transition cursor-pointer"
                >
                  Adjust Filters
                </button>
              </div>
            </div>

            {/* Main Export Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* PDF Document Export */}
              <div className="p-5 rounded-2xl bg-gradient-to-br from-slate-950 via-slate-900 to-cyan-950/20 border border-cyan-500/30 flex flex-col justify-between hover:border-cyan-500/50 transition shadow-lg">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="p-2.5 rounded-xl bg-rose-500/10 text-rose-400 border border-rose-500/20">
                      <FileText className="w-5 h-5" />
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                      Executive Ready
                    </span>
                  </div>
                  <h4 className="font-bold text-slate-100 text-sm mb-1">
                    Formal PDF Audit Report
                  </h4>
                  <p className="text-slate-400 text-xs leading-relaxed mb-4">
                    Generates a publication-grade vector PDF audit report complete with executive scorecard, OWASP MASVS risk matrix, full vulnerability impact details, and mitigation roadmap.
                  </p>
                </div>

                <button
                  onClick={handleDownloadPdf}
                  disabled={isGeneratingPdf}
                  className="w-full py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-bold text-xs shadow-lg shadow-cyan-500/25 transition cursor-pointer flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  {isGeneratingPdf ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
                  <span>{isGeneratingPdf ? 'Generating PDF...' : 'Download PDF Report'}</span>
                </button>
              </div>

              {/* CSV Spreadsheet Export */}
              <div className="p-5 rounded-2xl bg-slate-950/80 border border-slate-800 flex flex-col justify-between hover:border-slate-700 transition">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="p-2.5 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      <FileSpreadsheet className="w-5 h-5" />
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                      Spreadsheet (.CSV)
                    </span>
                  </div>
                  <h4 className="font-bold text-slate-100 text-sm mb-1">
                    CSV Data Export for Auditing &amp; SIEM
                  </h4>
                  <p className="text-slate-400 text-xs leading-relaxed mb-3">
                    Export structured tabular datasets for Excel, Google Sheets, Jira import, or enterprise security telemetry.
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-2 mt-2">
                  <button
                    onClick={() => handleDownloadCsv('all')}
                    className="py-2 px-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-xs border border-slate-700 transition cursor-pointer flex items-center justify-center gap-1.5"
                  >
                    <Download className="w-3.5 h-3.5 text-emerald-400" />
                    <span>All Datasets CSV</span>
                  </button>
                  <button
                    onClick={() => handleDownloadCsv('vulnerabilities')}
                    className="py-2 px-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-xs border border-slate-700 transition cursor-pointer flex items-center justify-center gap-1.5"
                  >
                    <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                    <span>Vulns CSV</span>
                  </button>
                  <button
                    onClick={() => handleDownloadCsv('endpoints')}
                    className="py-2 px-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-xs border border-slate-700 transition cursor-pointer flex items-center justify-center gap-1.5"
                  >
                    <Globe className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Endpoints CSV</span>
                  </button>
                  <button
                    onClick={() => handleDownloadCsv('secrets')}
                    className="py-2 px-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-xs border border-slate-700 transition cursor-pointer flex items-center justify-center gap-1.5"
                  >
                    <Key className="w-3.5 h-3.5 text-amber-400" />
                    <span>Secrets CSV</span>
                  </button>
                </div>
              </div>

              {/* JSON Machine-Readable Export */}
              <div className="p-5 rounded-2xl bg-slate-950/80 border border-slate-800 flex flex-col justify-between hover:border-slate-700 transition">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="p-2.5 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
                      <FileText className="w-5 h-5" />
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">
                      REST / JSON
                    </span>
                  </div>
                  <h4 className="font-bold text-slate-100 text-sm mb-1">
                    Custom JSON Security Payload
                  </h4>
                  <p className="text-slate-400 text-xs leading-relaxed mb-4">
                    Machine-readable JSON representation structured according to your custom section toggles and severity filters for automated CI/CD gating.
                  </p>
                </div>

                <button
                  onClick={handleDownloadCustomJson}
                  className="w-full py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-100 font-bold text-xs border border-slate-700 transition cursor-pointer flex items-center justify-center gap-2"
                >
                  <Download className="w-4 h-4 text-purple-400" />
                  <span>Download Custom JSON</span>
                </button>
              </div>

              {/* Markdown Export for GitHub / Jira */}
              <div className="p-5 rounded-2xl bg-slate-950/80 border border-slate-800 flex flex-col justify-between hover:border-slate-700 transition">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="p-2.5 rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/20">
                      <FileText className="w-5 h-5" />
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                      Markdown (.MD)
                    </span>
                  </div>
                  <h4 className="font-bold text-slate-100 text-sm mb-1">
                    Markdown Security Advisory
                  </h4>
                  <p className="text-slate-400 text-xs leading-relaxed mb-4">
                    Pre-formatted markdown tables and code blocks ready for instant posting into GitHub Security Advisories, GitLab Issues, or Confluence documentation.
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={handleDownloadMarkdown}
                    className="flex-1 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-100 font-bold text-xs border border-slate-700 transition cursor-pointer flex items-center justify-center gap-1.5"
                  >
                    <Download className="w-4 h-4 text-amber-400" />
                    <span>Download .MD</span>
                  </button>
                  <button
                    onClick={handleCopyMarkdown}
                    className="py-2.5 px-3 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold text-xs border border-slate-700 transition cursor-pointer flex items-center gap-1"
                    title="Copy Markdown to Clipboard"
                  >
                    {copiedFormat === 'md' ? <Check className="w-4 h-4 text-emerald-400" /> : <Share2 className="w-4 h-4" />}
                    <span>{copiedFormat === 'md' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
              </div>
            </div>

            {/* Decompiled ZIP Package Banner */}
            <div className="p-4 rounded-xl bg-gradient-to-r from-slate-950 to-blue-950/40 border border-blue-500/30 flex items-center justify-between flex-wrap gap-3">
              <div>
                <div className="font-bold text-slate-100 flex items-center gap-2">
                  <Download className="w-4 h-4 text-cyan-400" />
                  Full Decompiled Source &amp; Metadata ZIP Archive
                </div>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Includes formatted AndroidManifest.xml, disassembled Java sources, extracted endpoints, and full security finding bundle.
                </p>
              </div>

              <button
                onClick={onDownloadZip}
                disabled={isDownloadingZip}
                className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs shadow-md shadow-blue-500/20 transition cursor-pointer disabled:opacity-50"
              >
                {isDownloadingZip ? 'Archiving ZIP...' : 'Download Decompiled ZIP'}
              </button>
            </div>
          </div>
        )}

        {/* Tab 2: Customization Panel */}
        {activeTab === 'customize' && (
          <div className="flex-1 overflow-y-auto p-6 space-y-6 text-xs">
            {/* Metadata inputs */}
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
              <h4 className="font-bold text-slate-200 text-xs uppercase font-mono tracking-wider flex items-center gap-2">
                <Settings className="w-4 h-4 text-cyan-400" />
                Report Title &amp; Auditor Metadata
              </h4>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono">
                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">Report Heading Title</label>
                  <input
                    type="text"
                    value={options.reportTitle}
                    onChange={(e) => setOptions({ ...options, reportTitle: e.target.value })}
                    className="w-full px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 text-xs focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">Lead Auditor / Examiner</label>
                  <input
                    type="text"
                    value={options.auditorName}
                    onChange={(e) => setOptions({ ...options, auditorName: e.target.value })}
                    className="w-full px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 text-xs focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">Audit Organization / Firm</label>
                  <input
                    type="text"
                    value={options.organization}
                    onChange={(e) => setOptions({ ...options, organization: e.target.value })}
                    className="w-full px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 text-xs focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>
            </div>

            {/* Section Inclusion Toggles */}
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
              <h4 className="font-bold text-slate-200 text-xs uppercase font-mono tracking-wider flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                Report Modules &amp; Sections to Include
              </h4>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <label className="flex items-center gap-2.5 p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.includeExecutiveSummary}
                    onChange={(e) => setOptions({ ...options, includeExecutiveSummary: e.target.checked })}
                    className="w-4 h-4 rounded text-cyan-500 bg-slate-800 border-slate-700 focus:ring-0 cursor-pointer"
                  />
                  <div>
                    <div className="font-semibold text-slate-200">Executive Threat Scorecard</div>
                    <div className="text-[10px] text-slate-400">Security score (0-100), rating, and issue totals</div>
                  </div>
                </label>

                <label className="flex items-center gap-2.5 p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.includeVulnerabilities}
                    onChange={(e) => setOptions({ ...options, includeVulnerabilities: e.target.checked })}
                    className="w-4 h-4 rounded text-cyan-500 bg-slate-800 border-slate-700 focus:ring-0 cursor-pointer"
                  />
                  <div>
                    <div className="font-semibold text-slate-200">Vulnerability Findings &amp; OWASP Mapping</div>
                    <div className="text-[10px] text-slate-400">Detailed CWE breakdown, location, and remediation</div>
                  </div>
                </label>

                <label className="flex items-center gap-2.5 p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.includeSecrets}
                    onChange={(e) => setOptions({ ...options, includeSecrets: e.target.checked })}
                    className="w-4 h-4 rounded text-cyan-500 bg-slate-800 border-slate-700 focus:ring-0 cursor-pointer"
                  />
                  <div>
                    <div className="font-semibold text-slate-200">Hardcoded Secrets &amp; Keys</div>
                    <div className="text-[10px] text-slate-400">Stripe, AWS, Private API keys, and JWT tokens</div>
                  </div>
                </label>

                <label className="flex items-center gap-2.5 p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.includeEndpoints}
                    onChange={(e) => setOptions({ ...options, includeEndpoints: e.target.checked })}
                    className="w-4 h-4 rounded text-cyan-500 bg-slate-800 border-slate-700 focus:ring-0 cursor-pointer"
                  />
                  <div>
                    <div className="font-semibold text-slate-200">Network Endpoints &amp; Recon</div>
                    <div className="text-[10px] text-slate-400">Extracted URLs, APIs, IPs, and cloud storage</div>
                  </div>
                </label>

                <label className="flex items-center gap-2.5 p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.includePermissions}
                    onChange={(e) => setOptions({ ...options, includePermissions: e.target.checked })}
                    className="w-4 h-4 rounded text-cyan-500 bg-slate-800 border-slate-700 focus:ring-0 cursor-pointer"
                  />
                  <div>
                    <div className="font-semibold text-slate-200">Android Permissions Matrix</div>
                    <div className="text-[10px] text-slate-400">Protection levels and privacy threat assessment</div>
                  </div>
                </label>

                <label className="flex items-center gap-2.5 p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.includeSignatures}
                    onChange={(e) => setOptions({ ...options, includeSignatures: e.target.checked })}
                    className="w-4 h-4 rounded text-cyan-500 bg-slate-800 border-slate-700 focus:ring-0 cursor-pointer"
                  />
                  <div>
                    <div className="font-semibold text-slate-200">Cryptographic Signatures &amp; Certs</div>
                    <div className="text-[10px] text-slate-400">v1/v2/v3 schemes, RSA key sizes, fingerprints</div>
                  </div>
                </label>

                <label className="flex items-center gap-2.5 p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition cursor-pointer sm:col-span-2">
                  <input
                    type="checkbox"
                    checked={options.includeSandbox}
                    onChange={(e) => setOptions({ ...options, includeSandbox: e.target.checked })}
                    className="w-4 h-4 rounded text-cyan-500 bg-slate-800 border-slate-700 focus:ring-0 cursor-pointer"
                  />
                  <div>
                    <div className="font-semibold text-slate-200">Isolated Android Sandbox &amp; Intercepted Downloads</div>
                    <div className="text-[10px] text-slate-400">Dynamic file downloads trapped, background droppers, and MitM network logs</div>
                  </div>
                </label>
              </div>
            </div>

            {/* Severity & Data Filtering */}
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
              <h4 className="font-bold text-slate-200 text-xs uppercase font-mono tracking-wider flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                Vulnerability Severity Filters
              </h4>

              <div className="flex flex-wrap gap-3">
                {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => (
                  <label
                    key={sev}
                    className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 transition cursor-pointer"
                  >
                    <input
                      type="checkbox"
                      checked={options.severityFilter[sev]}
                      onChange={(e) =>
                        setOptions({
                          ...options,
                          severityFilter: {
                            ...options.severityFilter,
                            [sev]: e.target.checked,
                          },
                        })
                      }
                      className="w-3.5 h-3.5 text-cyan-500 rounded bg-slate-800 border-slate-700"
                    />
                    <span className="capitalize font-mono font-semibold text-slate-200 text-[11px]">{sev}</span>
                  </label>
                ))}
              </div>

              <div className="pt-2 border-t border-slate-800/80 flex flex-wrap gap-4">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.endpointInsecureOnly}
                    onChange={(e) => setOptions({ ...options, endpointInsecureOnly: e.target.checked })}
                    className="w-3.5 h-3.5 text-cyan-500 rounded bg-slate-800 border-slate-700"
                  />
                  <span className="text-slate-300 text-[11px]">Include Insecure Endpoints Only (HTTP / Cleartext)</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.permissionDangerousOnly}
                    onChange={(e) => setOptions({ ...options, permissionDangerousOnly: e.target.checked })}
                    className="w-3.5 h-3.5 text-cyan-500 rounded bg-slate-800 border-slate-700"
                  />
                  <span className="text-slate-300 text-[11px]">Include Dangerous Permissions Only</span>
                </label>
              </div>
            </div>

            <div className="flex justify-end gap-3">
              <button
                onClick={() => setActiveTab('export')}
                className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs transition cursor-pointer"
              >
                Apply &amp; Go to Export
              </button>
            </div>
          </div>
        )}

        {/* Tab 3: Live Preview */}
        {activeTab === 'preview' && (
          <div className="flex-1 overflow-y-auto p-6 space-y-5 text-xs font-sans">
            {/* Mock Report Header */}
            <div className="p-5 rounded-xl bg-slate-950 border border-slate-800">
              <div className="flex justify-between items-start flex-wrap gap-4">
                <div>
                  <span className="text-[10px] font-mono uppercase tracking-widest text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/60">
                    Audit Report Document
                  </span>
                  <h2 className="text-lg font-bold text-slate-100 mt-1">{options.reportTitle}</h2>
                  <div className="text-xs text-slate-400 font-mono mt-1 space-y-0.5">
                    <div>Package: <span className="text-slate-200">{analysis.packageName}</span> | Version: {analysis.versionName}</div>
                    <div>Auditor: {options.auditorName} ({options.organization}) | Date: {new Date().toLocaleDateString()}</div>
                  </div>
                </div>

                <div className={`p-3 rounded-xl border text-center ${
                  analysis.securityScore >= 80 ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300' : 'bg-rose-950/40 border-rose-500/40 text-rose-300'
                }`}>
                  <div className="text-[10px] uppercase font-mono font-bold">Security Score</div>
                  <div className="text-2xl font-black font-mono">{analysis.securityScore}/100</div>
                  <div className="text-[10px] font-bold">Grade: {analysis.securityRating}</div>
                </div>
              </div>
            </div>

            {/* Filtered Vulnerabilities Preview */}
            {options.includeVulnerabilities && (
              <div className="space-y-2">
                <div className="flex justify-between items-center font-mono">
                  <h4 className="font-bold text-slate-200 uppercase text-[11px] tracking-wider">
                    Vulnerability Findings ({filteredVulns.length})
                  </h4>
                </div>

                <div className="space-y-2">
                  {filteredVulns.map((v) => (
                    <div key={v.id} className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase font-mono border ${
                          v.severity === 'critical' ? 'bg-rose-500/20 text-rose-400 border-rose-500/30' : 'bg-orange-500/20 text-orange-400 border-orange-500/30'
                        }`}>
                          {v.severity}
                        </span>
                        <span className="font-bold text-slate-100">{v.title}</span>
                        {v.cwe && <span className="text-[10px] font-mono text-slate-400">[{v.cwe}]</span>}
                      </div>
                      <p className="text-slate-300 text-[11px]">{v.description}</p>
                      <div className="text-emerald-400 text-[10px] font-mono mt-1">Fix: {v.recommendation}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Footer Actions */}
        <div className="px-6 py-3.5 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between flex-wrap gap-2 text-xs">
          <div className="flex items-center gap-2">
            <button
              onClick={() => window.print()}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition cursor-pointer"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print</span>
            </button>

            <span className="text-[11px] text-slate-500 hidden sm:inline font-mono">
              {filteredVulns.length} Findings &bull; {filteredEndpoints.length} Endpoints
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleDownloadPdf}
              disabled={isGeneratingPdf}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs shadow-md shadow-cyan-500/20 transition cursor-pointer disabled:opacity-50"
            >
              {isGeneratingPdf ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
              <span>Download PDF</span>
            </button>

            <button
              onClick={onClose}
              className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-xs font-medium transition cursor-pointer"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
