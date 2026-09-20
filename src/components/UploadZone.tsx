import React, { useState, useRef } from 'react';
import {
  Upload,
  FileCode,
  AlertTriangle,
  Cpu,
  Globe,
  Link,
  Download,
  HardDrive,
  Loader2,
  ShieldCheck,
  Server,
} from 'lucide-react';

interface UploadZoneProps {
  onFileSelected: (file: File) => void;
  isAnalyzing: boolean;
  analyzingStep: string;
}

export const UploadZone: React.FC<UploadZoneProps> = ({
  onFileSelected,
  isAnalyzing,
  analyzingStep,
}) => {
  const [activeTab, setActiveTab] = useState<'local' | 'url'>('local');
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // URL Import State
  const [urlInput, setUrlInput] = useState('');
  const [customAuthHeader, setCustomAuthHeader] = useState('');
  const [showAdvancedHeaders, setShowAdvancedHeaders] = useState(false);
  const [isDownloadingUrl, setIsDownloadingUrl] = useState(false);
  const [downloadProgress, setDownloadProgress] = useState<{
    loaded: number;
    total: number;
    percentage: number;
    step: string;
  }>({
    loaded: 0,
    total: 0,
    percentage: 0,
    step: '',
  });
  const [urlError, setUrlError] = useState<string | null>(null);

  const MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024 * 1024; // 2.0 GB

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
  };

  const validateAndProcessFile = (file: File) => {
    if (file.size > MAX_FILE_SIZE_BYTES) {
      alert(
        `File is too large! Selected file is ${(file.size / (1024 * 1024 * 1024)).toFixed(
          2
        )} GB. Maximum allowed upload size is 2.0 GB.`
      );
      return;
    }

    const lower = file.name.toLowerCase();
    if (
      lower.endsWith('.apk') ||
      lower.endsWith('.zip') ||
      lower.endsWith('.xapk') ||
      lower.endsWith('.so') ||
      lower.endsWith('.elf') ||
      lower.endsWith('.bin') ||
      lower.endsWith('.dex') ||
      lower.endsWith('.o') ||
      lower.endsWith('.dll') ||
      lower.endsWith('.dylib')
    ) {
      onFileSelected(file);
    } else {
      alert(
        'Please upload an APK package (.apk, .xapk, .zip) or native binary (.so, .elf, .dex, .bin, .dll).'
      );
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      validateAndProcessFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      validateAndProcessFile(e.target.files[0]);
    }
  };

  // Download and process remote file via URL
  const handleDownloadFromUrl = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!urlInput.trim()) return;

    let targetUrl = urlInput.trim();
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      targetUrl = 'https://' + targetUrl;
    }

    setIsDownloadingUrl(true);
    setUrlError(null);
    setDownloadProgress({
      loaded: 0,
      total: 0,
      percentage: 0,
      step: 'Connecting to remote web server & resolving DNS...',
    });

    try {
      setDownloadProgress((prev) => ({
        ...prev,
        step: 'Connecting to URL (up to 2.0 GB allowed)...',
      }));

      const customHeaders: Record<string, string> = {};
      if (customAuthHeader.trim()) {
        customHeaders['Authorization'] = customAuthHeader.trim();
      }

      const res = await fetch('/api/fetch-remote-file', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: targetUrl,
          customHeaders,
        }),
      });

      if (!res.ok) {
        let errMessage = `Remote server returned status ${res.status}`;
        try {
          const errData = await res.json();
          if (errData.error) errMessage = errData.error;
        } catch {
          // ignore
        }
        throw new Error(errMessage);
      }

      // Extract filename from response header
      let fileName = 'downloaded-app.apk';
      const disposition = res.headers.get('X-File-Name');
      if (disposition) {
        try {
          fileName = decodeURIComponent(disposition);
        } catch {
          fileName = disposition;
        }
      } else {
        const urlParts = targetUrl.split('?')[0].split('/');
        const lastPart = urlParts[urlParts.length - 1];
        if (lastPart && lastPart.includes('.')) {
          fileName = lastPart;
        }
      }

      const contentLengthHeader = res.headers.get('Content-Length');
      const totalBytes = contentLengthHeader ? parseInt(contentLengthHeader, 10) : 0;

      // Read stream with progress
      if (res.body) {
        const reader = res.body.getReader();
        const chunks: Uint8Array[] = [];
        let receivedBytes = 0;

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          chunks.push(value);
          receivedBytes += value.length;

          const percentage = totalBytes > 0 ? Math.round((receivedBytes / totalBytes) * 100) : 0;
          setDownloadProgress({
            loaded: receivedBytes,
            total: totalBytes,
            percentage,
            step: `Downloaded ${(receivedBytes / (1024 * 1024)).toFixed(1)} MB ${
              totalBytes > 0 ? `/ ${(totalBytes / (1024 * 1024)).toFixed(1)} MB (${percentage}%)` : ''
            }`,
          });
        }

        const totalBlob = new Blob(chunks as BlobPart[]);
        const file = new File([totalBlob], fileName, {
          type: res.headers.get('Content-Type') || 'application/vnd.android.package-archive',
        });

        setIsDownloadingUrl(false);
        onFileSelected(file);
      } else {
        const blob = await res.blob();
        const file = new File([blob], fileName, {
          type: res.headers.get('Content-Type') || 'application/vnd.android.package-archive',
        });
        setIsDownloadingUrl(false);
        onFileSelected(file);
      }
    } catch (err: any) {
      console.warn('Backend proxy fetch failed, attempting client-side direct fetch:', err);

      // Fallback: Direct client-side fetch
      try {
        setDownloadProgress((prev) => ({
          ...prev,
          step: 'Attempting direct fetch...',
        }));

        const directRes = await fetch(targetUrl);
        if (!directRes.ok) throw new Error(`HTTP ${directRes.status} ${directRes.statusText}`);

        const blob = await directRes.blob();
        const urlParts = targetUrl.split('?')[0].split('/');
        let fileName = urlParts[urlParts.length - 1] || 'downloaded-app.apk';
        if (!fileName.includes('.')) fileName += '.apk';

        const file = new File([blob], fileName, { type: blob.type || 'application/octet-stream' });
        setIsDownloadingUrl(false);
        onFileSelected(file);
      } catch (fallbackErr: any) {
        setIsDownloadingUrl(false);
        setUrlError(
          `Unable to download binary from link: ${err.message}. Please verify the URL is accessible.`
        );
      }
    }
  };

  return (
    <div className="max-w-4xl mx-auto px-4 py-8">
      {/* Header */}
      <div className="text-center mb-8">
        <h1 className="text-3xl sm:text-4xl font-extrabold text-slate-100 tracking-tight mb-3">
          APK &amp; Binary Decompiler
        </h1>
        <p className="text-slate-400 text-sm sm:text-base max-w-2xl mx-auto leading-relaxed">
          Upload an Android package (<code className="text-cyan-300 font-mono text-xs">.apk</code>, <code className="text-cyan-300 font-mono text-xs">.xapk</code>, <code className="text-cyan-300 font-mono text-xs">.zip</code>) or native binary (<code className="text-cyan-300 font-mono text-xs">.so</code>, <code className="text-cyan-300 font-mono text-xs">.elf</code>, <code className="text-cyan-300 font-mono text-xs">.dex</code>) from your computer or import via a website link.
        </p>

        {/* 2.0 GB Upload Allowance Badge */}
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 mt-3 rounded-xl bg-slate-900/90 border border-slate-700/80 text-xs text-slate-300 shadow-sm">
          <HardDrive className="w-4 h-4 text-cyan-400" />
          <span>Upload Capacity:</span>
          <strong className="text-cyan-300 font-mono">Up to 2.0 GB Supported</strong>
        </div>
      </div>

      {/* Upload Method Tabs */}
      <div className="flex items-center justify-center gap-2 mb-6">
        <div className="p-1.5 bg-slate-900/90 border border-slate-800 rounded-2xl flex items-center gap-1 shadow-lg">
          <button
            onClick={() => setActiveTab('local')}
            className={`flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-semibold transition cursor-pointer ${
              activeTab === 'local'
                ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Upload className="w-4 h-4" />
            <span>Upload Local File</span>
          </button>

          <button
            onClick={() => setActiveTab('url')}
            className={`flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-semibold transition cursor-pointer ${
              activeTab === 'url'
                ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Globe className="w-4 h-4" />
            <span>Import from Website Link / URL</span>
          </button>
        </div>
      </div>

      {/* TAB 1: LOCAL FILE UPLOAD */}
      {activeTab === 'local' && (
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => !isAnalyzing && fileInputRef.current?.click()}
          className={`relative border-2 border-dashed rounded-2xl p-8 sm:p-14 text-center transition-all cursor-pointer ${
            isDragOver
              ? 'border-cyan-400 bg-cyan-500/10 shadow-2xl shadow-cyan-500/20 scale-[1.01]'
              : 'border-slate-800 bg-slate-900/50 hover:border-slate-700 hover:bg-slate-900/80 shadow-xl'
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".apk,.xapk,.zip,.so,.elf,.bin,.dex,.o,.dll,.dylib"
            onChange={handleFileChange}
            className="hidden"
            disabled={isAnalyzing}
          />

          {isAnalyzing ? (
            <div className="py-8 flex flex-col items-center">
              <div className="relative w-20 h-20 mb-6 flex items-center justify-center">
                <div className="absolute inset-0 rounded-full border border-cyan-500/30 animate-ping" />
                <div className="absolute inset-2 rounded-full border border-cyan-400/50 animate-pulse" />
                <div className="w-12 h-12 rounded-full bg-cyan-500/20 flex items-center justify-center border border-cyan-400 text-cyan-300 shadow-lg shadow-cyan-500/30">
                  <Cpu className="w-6 h-6 animate-spin" />
                </div>
              </div>

              <h3 className="text-lg font-semibold text-slate-100 mb-2">
                Decompiling &amp; Auditing Binary...
              </h3>
              <p className="text-sm font-mono text-cyan-400 bg-cyan-950/40 px-3 py-1 rounded-md border border-cyan-500/30 mb-4">
                {analyzingStep || 'Parsing Dalvik bytecode & AXML...'}
              </p>

              <div className="w-64 bg-slate-800 rounded-full h-1.5 overflow-hidden">
                <div className="bg-gradient-to-r from-cyan-500 to-blue-500 h-full w-full animate-[shimmer_2s_infinite]" />
              </div>
            </div>
          ) : (
            <div className="py-6 flex flex-col items-center">
              <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-cyan-500/10 to-blue-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 mb-4 shadow-inner">
                <Upload className="w-8 h-8" />
              </div>
              <h3 className="text-lg font-semibold text-slate-100 mb-1">
                Drag &amp; drop your APK or Native Binary file here
              </h3>
              <p className="text-xs text-slate-400 mb-5 max-w-md mx-auto">
                Supports APKs, XAPKs, Split APKs, and native binaries (.so, .elf, .dex) up to <strong className="text-slate-200">2.0 GB</strong>
              </p>
              <div className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold text-xs shadow-lg shadow-cyan-500/25 transition">
                <FileCode className="w-4 h-4" />
                Browse Device for Files (Max 2.0 GB)
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 2: IMPORT FROM WEB LINK / URL */}
      {activeTab === 'url' && (
        <div className="p-6 sm:p-8 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-xl space-y-6">
          <div>
            <div className="flex items-center gap-2.5 mb-2">
              <Globe className="w-5 h-5 text-cyan-400" />
              <h3 className="text-base font-bold text-slate-100">
                Import Binary from Website Link / URL
              </h3>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Enter any direct download link, release artifact URL, or cloud storage link. Files up to <strong className="text-slate-200">2.0 GB</strong> are supported.
            </p>
          </div>

          {urlError && (
            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <strong className="font-semibold">Download Failed:</strong>
                <div>{urlError}</div>
              </div>
            </div>
          )}

          {isDownloadingUrl ? (
            <div className="p-8 rounded-xl bg-slate-950/60 border border-slate-800 text-center space-y-4">
              <div className="relative w-16 h-16 mx-auto flex items-center justify-center">
                <div className="absolute inset-0 rounded-full border border-cyan-500/30 animate-ping" />
                <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
              </div>

              <div>
                <h4 className="text-sm font-semibold text-slate-200">
                  Downloading Remote File...
                </h4>
                <p className="text-xs font-mono text-cyan-400 mt-1">
                  {downloadProgress.step}
                </p>
              </div>

              {downloadProgress.total > 0 && (
                <div className="max-w-md mx-auto space-y-1.5">
                  <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                    <div
                      className="bg-gradient-to-r from-cyan-500 to-blue-500 h-full transition-all duration-300"
                      style={{ width: `${downloadProgress.percentage}%` }}
                    />
                  </div>
                  <div className="flex justify-between text-[11px] font-mono text-slate-400">
                    <span>{(downloadProgress.loaded / (1024 * 1024)).toFixed(1)} MB</span>
                    <span>{downloadProgress.percentage}% of {(downloadProgress.total / (1024 * 1024)).toFixed(1)} MB</span>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <form onSubmit={handleDownloadFromUrl} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-2">
                  File Download URL (HTTPS / HTTP):
                </label>
                <div className="relative">
                  <Link className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                  <input
                    type="text"
                    placeholder="https://example.com/downloads/application.apk"
                    value={urlInput}
                    onChange={(e) => setUrlInput(e.target.value)}
                    className="w-full pl-10 pr-4 py-2.5 bg-slate-950 border border-slate-700 rounded-xl text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 font-mono shadow-inner"
                    disabled={isDownloadingUrl}
                  />
                </div>
              </div>

              {/* Optional Advanced Request Headers */}
              <div className="pt-2">
                <button
                  type="button"
                  onClick={() => setShowAdvancedHeaders(!showAdvancedHeaders)}
                  className="text-xs text-slate-400 hover:text-slate-200 inline-flex items-center gap-1.5 cursor-pointer"
                >
                  <Server className="w-3.5 h-3.5 text-cyan-400" />
                  <span>{showAdvancedHeaders ? 'Hide' : 'Add'} Optional Authorization Header (e.g. Bearer Token)</span>
                </button>

                {showAdvancedHeaders && (
                  <div className="mt-3 p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
                    <label className="block text-[11px] font-semibold text-slate-300">
                      Authorization Header:
                    </label>
                    <input
                      type="text"
                      placeholder="Bearer token_here"
                      value={customAuthHeader}
                      onChange={(e) => setCustomAuthHeader(e.target.value)}
                      className="w-full px-3 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder:text-slate-600 font-mono focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                )}
              </div>

              <div className="flex items-center justify-between pt-2">
                <div className="text-[11px] text-slate-400 flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  <span>Max 2.0 GB allowed</span>
                </div>

                <button
                  type="submit"
                  disabled={!urlInput.trim() || isDownloadingUrl}
                  className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 text-white font-semibold text-xs shadow-lg shadow-cyan-500/25 transition cursor-pointer"
                >
                  <Download className="w-4 h-4" />
                  <span>Download &amp; Decompile</span>
                </button>
              </div>
            </form>
          )}
        </div>
      )}
    </div>
  );
};
