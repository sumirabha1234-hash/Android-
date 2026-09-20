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
  ArrowRight,
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
      step: 'Resolving DNS & establishing connection...',
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
    <div className="grid grid-cols-1 lg:grid-cols-[1fr_450px] gap-10 lg:gap-14 items-center py-6 sm:py-12 relative z-10">
      {/* Left Column: Hero Text */}
      <div className="hero-text space-y-6">
        <div className="font-mono text-[0.65rem] uppercase tracking-[0.18em] text-[#edeff2]/50 flex items-center gap-2">
          <span className="inline-block w-1.5 h-1.5 bg-[#00f2ff] rounded-full animate-pulse" />
          // Security Audit Platform
        </div>

        <h2 className="font-syne text-4xl sm:text-6xl md:text-7xl font-extrabold uppercase tracking-[-0.06em] leading-[0.88] text-[#edeff2]">
          APK &amp; Binary<br />Decompiler
        </h2>

        <p className="text-[#edeff2]/60 text-base sm:text-lg leading-relaxed max-w-xl font-normal">
          Upload an Android package (<code className="font-mono text-[#00f2ff] bg-[#00f2ff]/10 px-1.5 py-0.5 rounded text-sm">.apk</code>, <code className="font-mono text-[#00f2ff] bg-[#00f2ff]/10 px-1.5 py-0.5 rounded text-sm">.xapk</code>, <code className="font-mono text-[#00f2ff] bg-[#00f2ff]/10 px-1.5 py-0.5 rounded text-sm">.zip</code>) or native binary (<code className="font-mono text-[#00f2ff] bg-[#00f2ff]/10 px-1.5 py-0.5 rounded text-sm">.so</code>, <code className="font-mono text-[#00f2ff] bg-[#00f2ff]/10 px-1.5 py-0.5 rounded text-sm">.elf</code>, <code className="font-mono text-[#00f2ff] bg-[#00f2ff]/10 px-1.5 py-0.5 rounded text-sm">.dex</code>) from your computer or import via a website link.
        </p>

        {/* Technical Stats Grid */}
        <div className="flex flex-wrap items-center gap-6 sm:gap-10 pt-4 border-t border-[#edeff2]/10 font-mono text-[0.7rem] uppercase">
          <div className="text-[#edeff2]/50">
            <strong className="text-[#edeff2] mr-1.5">STATUS:</strong>
            <span className="text-[#00f2ff]">ENGINES_ONLINE</span>
          </div>
          <div className="text-[#edeff2]/50">
            <strong className="text-[#edeff2] mr-1.5">RECOVERY:</strong>
            <span className="text-[#edeff2]">0-100% SSA</span>
          </div>
          <div className="text-[#edeff2]/50">
            <strong className="text-[#edeff2] mr-1.5">SANDBOX:</strong>
            <span className="text-[#edeff2]">ANDROID_14</span>
          </div>
        </div>
      </div>

      {/* Right Column: Upload Container */}
      <div className="upload-container w-full">
        {/* Tab Switcher */}
        <div className="flex border border-[#edeff2]/20 mb-6 bg-[#0c0c0e]">
          <button
            onClick={() => setActiveTab('local')}
            className={`flex-1 py-3 px-4 font-mono text-[0.7rem] uppercase tracking-wider text-center transition cursor-pointer ${
              activeTab === 'local'
                ? 'bg-[#edeff2] text-[#0c0c0e] font-bold'
                : 'text-[#edeff2]/60 hover:text-[#edeff2] hover:bg-[#edeff2]/5'
            }`}
          >
            Local Upload
          </button>
          <button
            onClick={() => setActiveTab('url')}
            className={`flex-1 py-3 px-4 font-mono text-[0.7rem] uppercase tracking-wider text-center transition cursor-pointer ${
              activeTab === 'url'
                ? 'bg-[#edeff2] text-[#0c0c0e] font-bold'
                : 'text-[#edeff2]/60 hover:text-[#edeff2] hover:bg-[#edeff2]/5'
            }`}
          >
            Website Import
          </button>
        </div>

        {/* Tab 1: Local Upload */}
        {activeTab === 'local' && (
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => !isAnalyzing && fileInputRef.current?.click()}
            className={`border-2 border-[#edeff2] bg-[#ffffff]/[0.02] p-8 sm:p-12 relative cursor-pointer transition-all duration-200 ${
              isDragOver
                ? 'bg-[#00f2ff]/10 border-[#00f2ff] shadow-2xl shadow-[#00f2ff]/20'
                : 'hover:bg-[#ffffff]/[0.05]'
            }`}
          >
            {/* System Bracket Label */}
            <div className="absolute -top-3 left-5 bg-[#0c0c0e] px-2 font-mono text-[0.68rem] text-[#edeff2] tracking-wider uppercase">
              [ DRAG_SYSTEM_INPUT ]
            </div>

            <input
              ref={fileInputRef}
              type="file"
              accept=".apk,.xapk,.zip,.so,.elf,.bin,.dex,.o,.dll,.dylib"
              onChange={handleFileChange}
              className="hidden"
              disabled={isAnalyzing}
            />

            {isAnalyzing ? (
              <div className="py-6 flex flex-col items-center text-center">
                <div className="w-16 h-16 rounded-full bg-[#00f2ff]/10 border border-[#00f2ff] flex items-center justify-center text-[#00f2ff] mb-5 shadow-lg shadow-[#00f2ff]/20">
                  <Cpu className="w-8 h-8 animate-spin" />
                </div>
                <h3 className="font-syne text-lg font-bold uppercase text-[#edeff2] tracking-tight mb-2">
                  Decompiling &amp; Auditing...
                </h3>
                <p className="font-mono text-xs text-[#00f2ff] bg-[#00f2ff]/10 border border-[#00f2ff]/30 px-3 py-1.5 rounded mb-4">
                  {analyzingStep || 'Parsing Dalvik bytecode & AXML...'}
                </p>
                <div className="w-full bg-[#edeff2]/10 h-1 overflow-hidden">
                  <div className="bg-[#00f2ff] h-full w-full animate-pulse" />
                </div>
              </div>
            ) : (
              <div>
                <div className="upload-icon mb-6 text-[#00f2ff]">
                  <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                    <polyline points="17 8 12 3 7 8" />
                    <line x1="12" y1="3" x2="12" y2="15" />
                  </svg>
                </div>

                <h3 className="font-syne text-lg font-bold uppercase tracking-tight text-[#edeff2] mb-2">
                  Transfer Data
                </h3>

                <p className="text-xs text-[#edeff2]/60 leading-relaxed">
                  Drag &amp; drop your APK or Native Binary file here. Supports APKs, XAPKs, Split APKs, and native binaries up to 2.0 GB.
                </p>

                <div className="inline-block mt-6 font-mono text-[0.65rem] text-[#edeff2]/60 border-l-2 border-[#00f2ff] pl-3 py-0.5">
                  UPLOAD_CAPACITY: <span className="text-[#edeff2] font-semibold">2.0 GB Supported</span>
                </div>

                <button
                  type="button"
                  className="browse-btn block w-full mt-8 bg-[#00f2ff] text-[#0c0c0e] py-4 text-center font-syne font-extrabold uppercase tracking-wider text-sm hover:brightness-110 active:scale-[0.99] transition cursor-pointer"
                >
                  Browse Device
                </button>
              </div>
            )}
          </div>
        )}

        {/* Tab 2: Website Import */}
        {activeTab === 'url' && (
          <div className="border-2 border-[#edeff2] bg-[#ffffff]/[0.02] p-6 sm:p-8 relative">
            <div className="absolute -top-3 left-5 bg-[#0c0c0e] px-2 font-mono text-[0.68rem] text-[#edeff2] tracking-wider uppercase">
              [ REMOTE_STREAM_INPUT ]
            </div>

            <h3 className="font-syne text-base font-bold uppercase tracking-tight text-[#edeff2] mb-1 flex items-center gap-2">
              <Globe className="w-4 h-4 text-[#00f2ff]" />
              <span>Import from Website Link</span>
            </h3>
            <p className="text-xs text-[#edeff2]/60 leading-relaxed mb-4">
              Enter any direct download URL, GitHub release artifact, or Cloud Storage link (up to 2.0 GB).
            </p>

            {urlError && (
              <div className="p-3 mb-4 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                <div>{urlError}</div>
              </div>
            )}

            {isDownloadingUrl ? (
              <div className="py-6 text-center space-y-3">
                <Loader2 className="w-8 h-8 text-[#00f2ff] animate-spin mx-auto" />
                <div className="font-syne font-bold uppercase text-sm text-[#edeff2]">
                  Streaming Remote Binary...
                </div>
                <div className="font-mono text-xs text-[#00f2ff]">
                  {downloadProgress.step}
                </div>
                {downloadProgress.total > 0 && (
                  <div className="w-full bg-[#edeff2]/10 h-1.5 overflow-hidden rounded">
                    <div
                      className="bg-[#00f2ff] h-full transition-all duration-300"
                      style={{ width: `${downloadProgress.percentage}%` }}
                    />
                  </div>
                )}
              </div>
            ) : (
              <form onSubmit={handleDownloadFromUrl} className="space-y-4">
                <div>
                  <label className="block font-mono text-[0.68rem] uppercase tracking-wider text-[#edeff2]/70 mb-1.5">
                    File Download URL:
                  </label>
                  <div className="relative">
                    <Link className="w-4 h-4 text-[#edeff2]/40 absolute left-3 top-3" />
                    <input
                      type="text"
                      placeholder="https://example.com/builds/app-release.apk"
                      value={urlInput}
                      onChange={(e) => setUrlInput(e.target.value)}
                      className="w-full pl-9 pr-3 py-2.5 bg-[#0c0c0e] border border-[#edeff2]/30 text-xs text-[#edeff2] font-mono placeholder:text-[#edeff2]/30 focus:outline-none focus:border-[#00f2ff]"
                      disabled={isDownloadingUrl}
                    />
                  </div>
                </div>

                <div>
                  <button
                    type="button"
                    onClick={() => setShowAdvancedHeaders(!showAdvancedHeaders)}
                    className="font-mono text-[0.65rem] text-[#edeff2]/60 hover:text-[#00f2ff] inline-flex items-center gap-1.5 cursor-pointer uppercase tracking-wider"
                  >
                    <Server className="w-3.5 h-3.5" />
                    <span>{showAdvancedHeaders ? '[-] Hide' : '[+] Add'} Authorization Token</span>
                  </button>

                  {showAdvancedHeaders && (
                    <div className="mt-2 p-3 bg-[#0c0c0e] border border-[#edeff2]/20 space-y-1.5">
                      <label className="block font-mono text-[0.62rem] uppercase text-[#edeff2]/60">
                        Authorization Header (Optional):
                      </label>
                      <input
                        type="text"
                        placeholder="Bearer token_xxxxxxxx"
                        value={customAuthHeader}
                        onChange={(e) => setCustomAuthHeader(e.target.value)}
                        className="w-full px-2.5 py-1.5 bg-[#141418] border border-[#edeff2]/20 text-xs font-mono text-[#edeff2] focus:outline-none focus:border-[#00f2ff]"
                      />
                    </div>
                  )}
                </div>

                <div className="font-mono text-[0.65rem] text-[#edeff2]/50 border-l-2 border-[#00f2ff] pl-2 py-0.5">
                  STREAM_LIMIT: 2.0 GB Supported
                </div>

                <button
                  type="submit"
                  disabled={!urlInput.trim() || isDownloadingUrl}
                  className="w-full bg-[#00f2ff] text-[#0c0c0e] py-3.5 text-center font-syne font-extrabold uppercase tracking-wider text-xs hover:brightness-110 disabled:opacity-50 transition cursor-pointer"
                >
                  Fetch &amp; Decompile
                </button>
              </form>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
