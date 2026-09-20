import React, { useState } from 'react';
import {
  Cpu,
  Terminal,
  ShieldAlert,
  ShieldCheck,
  FileCode,
  Layers,
  Search,
  Zap,
  Lock,
  Code2,
  Copy,
  Check,
  ArrowRight,
  AlertTriangle,
  FileText,
  Activity,
  Binary,
  Hash,
  Eye,
  Sliders,
  ChevronRight,
  ShieldOff
} from 'lucide-react';
import { ApkAnalysisResult, BinaryDecompileResult, DecompiledFunction, BinarySymbol, ElfSection } from '../types';

interface BinaryDecompilerTabProps {
  analysis: ApkAnalysisResult;
  onNavigateToCode?: (path: string) => void;
}

export const BinaryDecompilerTab: React.FC<BinaryDecompilerTabProps> = ({
  analysis,
  onNavigateToCode,
}) => {
  const binaryResults = analysis.binaryAnalysis || [];
  const [selectedBinaryIndex, setSelectedBinaryIndex] = useState<number>(0);
  const [activeSubTab, setActiveSubTab] = useState<'decompiler' | 'disasm' | 'headers' | 'symbols' | 'strings' | 'hex'>('decompiler');
  const [selectedFunctionId, setSelectedFunctionId] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [copied, setCopied] = useState<boolean>(false);
  const [filterType, setFilterType] = useState<'all' | 'jni' | 'imported' | 'security'>('all');

  const currentBinary: BinaryDecompileResult | undefined = binaryResults[selectedBinaryIndex] || binaryResults[0];

  // If no binary available, fallback gracefully
  if (!currentBinary) {
    return (
      <div className="p-8 text-center bg-slate-900/60 rounded-2xl border border-slate-800">
        <Cpu className="w-12 h-12 text-slate-500 mx-auto mb-3" />
        <h3 className="text-lg font-semibold text-slate-200">No Native ELF Binaries Detected</h3>
        <p className="text-sm text-slate-400 max-w-md mx-auto mt-1">
          This APK does not bundle native shared libraries (.so). You can upload a standalone binary (.so, .elf, .bin, .dex) to decompile directly.
        </p>
      </div>
    );
  }

  const selectedFunction: DecompiledFunction =
    currentBinary.functions.find((f) => f.id === selectedFunctionId) ||
    currentBinary.functions[0] ||
    ({
      id: 'default',
      name: 'No Functions Found',
      demangledName: '',
      address: '0x00000000',
      size: 0,
      returnType: 'void',
      parameters: [],
      isJniExport: false,
      assemblyInstructions: [],
      cDecompiledCode: '// No functions decompiled',
      securityNotes: [],
      complexity: 1,
      cfgNodesCount: 1,
    } as DecompiledFunction);

  const handleCopyCode = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Filter symbols based on search and type
  const filteredSymbols = currentBinary.symbols.filter((sym) => {
    const matchesSearch =
      sym.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (sym.demangledName && sym.demangledName.toLowerCase().includes(searchQuery.toLowerCase())) ||
      sym.address.toLowerCase().includes(searchQuery.toLowerCase());

    if (!matchesSearch) return false;
    if (filterType === 'jni') return sym.isJniExport;
    if (filterType === 'imported') return sym.isImported;
    if (filterType === 'security') return !!sym.riskTag;
    return true;
  });

  // Filter strings
  const filteredStrings = currentBinary.strings.filter((str) =>
    str.value.toLowerCase().includes(searchQuery.toLowerCase()) ||
    (str.category && str.category.toLowerCase().includes(searchQuery.toLowerCase())) ||
    str.offset.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Top Banner: Binary Selector & 0-100% Decompilation Retrieval Fidelity Meter */}
      <div className="p-5 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900/90 to-cyan-950/40 border border-slate-800 shadow-xl flex flex-col lg:flex-row lg:items-center justify-between gap-6">
        <div className="flex items-center gap-4">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-inner">
            <Cpu className="w-7 h-7" />
          </div>
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                <span>{currentBinary.fileName}</span>
              </h2>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                {currentBinary.header.machine}
              </span>
              <span className="px-2 py-0.5 rounded-md text-[11px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                {currentBinary.header.class} &bull; {currentBinary.header.data}
              </span>
            </div>
            <div className="flex items-center gap-3 text-xs text-slate-400 mt-1 font-mono flex-wrap">
              <span>Path: {currentBinary.filePath}</span>
              <span>&bull;</span>
              <span>Size: {(currentBinary.fileSize / 1024).toFixed(1)} KB</span>
              <span>&bull;</span>
              <span>SHA-256: {currentBinary.sha256.slice(0, 16)}...</span>
            </div>
          </div>
        </div>

        {/* Binary Decompilation Retrieval Gauge */}
        <div className="flex items-center gap-4 bg-slate-950/70 p-3.5 rounded-xl border border-slate-800/80">
          <div className="text-right">
            <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
              Binary Retrieval Fidelity
            </div>
            <div className="text-2xl font-black font-mono text-cyan-400">
              {currentBinary.decompilationScore}%
            </div>
            <div className="text-[10px] text-emerald-400 font-medium">
              High-Precision CFG &amp; C-AST Reconstructed
            </div>
          </div>
          <div className="relative w-14 h-14 flex items-center justify-center">
            <svg className="w-14 h-14 transform -rotate-90">
              <circle
                cx="28"
                cy="28"
                r="22"
                stroke="currentColor"
                strokeWidth="4"
                className="text-slate-800"
                fill="transparent"
              />
              <circle
                cx="28"
                cy="28"
                r="22"
                stroke="currentColor"
                strokeWidth="4"
                className="text-cyan-400 transition-all duration-1000 ease-out"
                fill="transparent"
                strokeDasharray={138.2}
                strokeDashoffset={138.2 - (138.2 * currentBinary.decompilationScore) / 100}
                strokeLinecap="round"
              />
            </svg>
            <Zap className="w-5 h-5 text-cyan-400 absolute" />
          </div>
        </div>
      </div>

      {/* Multiple Binary Switcher (if APK has multiple native libraries) */}
      {binaryResults.length > 1 && (
        <div className="flex items-center gap-2 overflow-x-auto pb-1">
          <span className="text-xs font-semibold text-slate-400 whitespace-nowrap mr-1">
            Native Binaries ({binaryResults.length}):
          </span>
          {binaryResults.map((bin, idx) => (
            <button
              key={bin.filePath || idx}
              onClick={() => {
                setSelectedBinaryIndex(idx);
                setSelectedFunctionId('');
              }}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-medium border transition cursor-pointer whitespace-nowrap ${
                selectedBinaryIndex === idx
                  ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40 shadow-sm'
                  : 'bg-slate-900/60 text-slate-400 border-slate-800 hover:text-slate-200'
              }`}
            >
              <Cpu className="w-3.5 h-3.5" />
              <span>{bin.fileName}</span>
              <span className="text-[10px] font-mono px-1 rounded bg-slate-800 text-slate-300">
                {bin.architecture}
              </span>
            </button>
          ))}
        </div>
      )}

      {/* Sub-Navigation Tabs */}
      <div className="flex items-center gap-1.5 p-1.5 rounded-2xl bg-slate-900/90 border border-slate-800 overflow-x-auto">
        <button
          onClick={() => setActiveSubTab('decompiler')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold whitespace-nowrap transition cursor-pointer ${
            activeSubTab === 'decompiler'
              ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Code2 className="w-4 h-4" />
          <span>C / C++ Pseudocode</span>
        </button>

        <button
          onClick={() => setActiveSubTab('disasm')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold whitespace-nowrap transition cursor-pointer ${
            activeSubTab === 'disasm'
              ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Terminal className="w-4 h-4" />
          <span>Disassembly (ASM)</span>
        </button>

        <button
          onClick={() => setActiveSubTab('headers')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold whitespace-nowrap transition cursor-pointer ${
            activeSubTab === 'headers'
              ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Sliders className="w-4 h-4" />
          <span>ELF Headers &amp; Mitigations</span>
        </button>

        <button
          onClick={() => setActiveSubTab('symbols')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold whitespace-nowrap transition cursor-pointer ${
            activeSubTab === 'symbols'
              ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Hash className="w-4 h-4" />
          <span>Dynamic Symbols ({currentBinary.symbols.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('strings')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold whitespace-nowrap transition cursor-pointer ${
            activeSubTab === 'strings'
              ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <FileText className="w-4 h-4" />
          <span>Strings Matrix ({currentBinary.strings.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('hex')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold whitespace-nowrap transition cursor-pointer ${
            activeSubTab === 'hex'
              ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Binary className="w-4 h-4" />
          <span>Hex Inspector</span>
        </button>
      </div>

      {/* Main Content Area */}
      {activeSubTab === 'decompiler' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Function Selector Sidebar */}
          <div className="lg:col-span-4 space-y-3">
            <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800">
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3 flex items-center justify-between">
                <span>Functions ({currentBinary.functions.length})</span>
                <span className="text-[10px] text-cyan-400 font-mono">AST Recovered</span>
              </h3>

              <div className="space-y-1.5 max-h-[480px] overflow-y-auto pr-1">
                {currentBinary.functions.map((fn) => {
                  const isSelected = fn.id === selectedFunction.id;
                  return (
                    <button
                      key={fn.id}
                      onClick={() => setSelectedFunctionId(fn.id)}
                      className={`w-full text-left p-2.5 rounded-xl border transition cursor-pointer text-xs ${
                        isSelected
                          ? 'bg-cyan-500/20 border-cyan-500/40 text-cyan-200 shadow-sm'
                          : 'bg-slate-950/40 border-slate-800/80 text-slate-300 hover:bg-slate-800/50 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-1 mb-1">
                        <span className="font-mono text-[11px] text-cyan-400 font-semibold truncate">
                          {fn.address}
                        </span>
                        {fn.isJniExport && (
                          <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                            JNI EXPORT
                          </span>
                        )}
                      </div>
                      <div className="font-mono text-xs font-semibold text-slate-100 truncate">
                        {fn.name}
                      </div>
                      <div className="flex items-center gap-2 mt-1 text-[10px] text-slate-400">
                        <span>Returns: {fn.returnType}</span>
                        <span>&bull;</span>
                        <span>CFG Nodes: {fn.cfgNodesCount}</span>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Retrieval Quality Metrics Box */}
            <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-3">
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                Decompilation Fidelity Breakdown
              </h4>
              <div className="space-y-2 text-xs">
                <div>
                  <div className="flex justify-between text-slate-300 mb-1">
                    <span>Symbol Table Reconstruction</span>
                    <span className="font-mono text-cyan-400 font-bold">
                      {currentBinary.retrievalMetrics.symbolRecoveryRate}%
                    </span>
                  </div>
                  <div className="w-full bg-slate-800 rounded-full h-1.5">
                    <div
                      className="bg-cyan-400 h-1.5 rounded-full"
                      style={{ width: `${currentBinary.retrievalMetrics.symbolRecoveryRate}%` }}
                    />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-slate-300 mb-1">
                    <span>Control Flow Graph (CFG) Structuring</span>
                    <span className="font-mono text-blue-400 font-bold">
                      {currentBinary.retrievalMetrics.cfgReconstructionRate}%
                    </span>
                  </div>
                  <div className="w-full bg-slate-800 rounded-full h-1.5">
                    <div
                      className="bg-blue-400 h-1.5 rounded-full"
                      style={{ width: `${currentBinary.retrievalMetrics.cfgReconstructionRate}%` }}
                    />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-slate-300 mb-1">
                    <span>C/C++ AST High-Level Lifting</span>
                    <span className="font-mono text-emerald-400 font-bold">
                      {currentBinary.retrievalMetrics.cCodeLiftingRate}%
                    </span>
                  </div>
                  <div className="w-full bg-slate-800 rounded-full h-1.5">
                    <div
                      className="bg-emerald-400 h-1.5 rounded-full"
                      style={{ width: `${currentBinary.retrievalMetrics.cCodeLiftingRate}%` }}
                    />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-slate-300 mb-1">
                    <span>String Cross-Reference Linking</span>
                    <span className="font-mono text-amber-400 font-bold">
                      {currentBinary.retrievalMetrics.stringCrossReferenceRate}%
                    </span>
                  </div>
                  <div className="w-full bg-slate-800 rounded-full h-1.5">
                    <div
                      className="bg-amber-400 h-1.5 rounded-full"
                      style={{ width: `${currentBinary.retrievalMetrics.stringCrossReferenceRate}%` }}
                    />
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Decompiled C/C++ Code View */}
          <div className="lg:col-span-8 space-y-4">
            <div className="rounded-2xl bg-slate-900/90 border border-slate-800 overflow-hidden shadow-xl">
              {/* Header Bar */}
              <div className="px-4 py-3 bg-slate-950/80 border-b border-slate-800 flex items-center justify-between flex-wrap gap-2">
                <div className="flex items-center gap-2">
                  <Code2 className="w-4 h-4 text-cyan-400" />
                  <span className="text-xs font-mono font-bold text-slate-200">
                    {selectedFunction.name}
                  </span>
                  <span className="text-[11px] font-mono text-slate-400">
                    @{selectedFunction.address} ({selectedFunction.size} bytes)
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleCopyCode(selectedFunction.cDecompiledCode)}
                    className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 transition cursor-pointer"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copied ? 'Copied' : 'Copy C Code'}</span>
                  </button>
                </div>
              </div>

              {/* Security Annotations (if any) */}
              {selectedFunction.securityNotes && selectedFunction.securityNotes.length > 0 && (
                <div className="px-4 py-2.5 bg-amber-500/10 border-b border-amber-500/20 text-xs text-amber-300 flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  <div>
                    <strong className="font-semibold">Security &amp; Reverse Engineering Notes:</strong>
                    <ul className="list-disc list-inside mt-1 space-y-0.5 text-amber-200/90">
                      {selectedFunction.securityNotes.map((note, idx) => (
                        <li key={idx}>{note}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}

              {/* Code Display */}
              <div className="p-4 bg-slate-950 font-mono text-xs overflow-x-auto max-h-[560px]">
                <pre className="text-slate-200 leading-relaxed">
                  <code>{selectedFunction.cDecompiledCode}</code>
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Disassembly View (ASM) */}
      {activeSubTab === 'disasm' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-4 space-y-3">
            <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800">
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3">
                Routine Disassembly Targets
              </h3>
              <div className="space-y-1.5 max-h-[480px] overflow-y-auto pr-1">
                {currentBinary.functions.map((fn) => {
                  const isSelected = fn.id === selectedFunction.id;
                  return (
                    <button
                      key={fn.id}
                      onClick={() => setSelectedFunctionId(fn.id)}
                      className={`w-full text-left p-2.5 rounded-xl border transition cursor-pointer text-xs ${
                        isSelected
                          ? 'bg-cyan-500/20 border-cyan-500/40 text-cyan-200 shadow-sm'
                          : 'bg-slate-950/40 border-slate-800/80 text-slate-300 hover:bg-slate-800/50 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-1 mb-1">
                        <span className="font-mono text-[11px] text-cyan-400 font-semibold truncate">
                          {fn.address}
                        </span>
                        <span className="text-[10px] font-mono text-slate-400">
                          {fn.assemblyInstructions.length} insts
                        </span>
                      </div>
                      <div className="font-mono text-xs font-semibold text-slate-100 truncate">
                        {fn.name}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          <div className="lg:col-span-8">
            <div className="rounded-2xl bg-slate-900/90 border border-slate-800 overflow-hidden shadow-xl">
              <div className="px-4 py-3 bg-slate-950/80 border-b border-slate-800 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-cyan-400" />
                  <span className="text-xs font-mono font-bold text-slate-200">
                    {selectedFunction.name} &bull; {currentBinary.header.machine} Machine Code
                  </span>
                </div>
              </div>

              <div className="p-4 bg-slate-950 font-mono text-xs overflow-x-auto max-h-[580px]">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-slate-800 text-[11px] text-slate-500 uppercase tracking-wider">
                      <th className="py-2 px-2">Offset</th>
                      <th className="py-2 px-2">Hex Bytes</th>
                      <th className="py-2 px-2">Mnemonic</th>
                      <th className="py-2 px-2">Operands</th>
                      <th className="py-2 px-2">Comment / XRef</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-900 text-xs">
                    {selectedFunction.assemblyInstructions.map((inst, idx) => (
                      <tr
                        key={idx}
                        className={`hover:bg-slate-900/50 transition-colors ${
                          inst.isBranch || inst.isCall ? 'bg-cyan-950/20' : ''
                        }`}
                      >
                        <td className="py-1.5 px-2 text-cyan-400 font-semibold">{inst.address}</td>
                        <td className="py-1.5 px-2 text-slate-500">{inst.bytes}</td>
                        <td className="py-1.5 px-2 text-amber-300 font-bold">{inst.mnemonic}</td>
                        <td className="py-1.5 px-2 text-slate-200 font-medium">{inst.operands}</td>
                        <td className="py-1.5 px-2 text-emerald-400/90 text-[11px]">
                          {inst.comment && <span>// {inst.comment}</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ELF Headers & Security Mitigations Tab */}
      {activeSubTab === 'headers' && (
        <div className="space-y-6">
          {/* Mitigations Dashboard */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            <div className={`p-4 rounded-2xl border ${currentBinary.mitigations.nx ? 'bg-emerald-950/20 border-emerald-500/30' : 'bg-rose-950/20 border-rose-500/30'}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold text-slate-300">NX (No-eXecute)</span>
                {currentBinary.mitigations.nx ? (
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                ) : (
                  <ShieldOff className="w-4 h-4 text-rose-400" />
                )}
              </div>
              <div className={`text-sm font-bold font-mono ${currentBinary.mitigations.nx ? 'text-emerald-300' : 'text-rose-300'}`}>
                {currentBinary.mitigations.nx ? 'ENABLED' : 'DISABLED'}
              </div>
              <div className="text-[10px] text-slate-400 mt-1">Stack Execution Blocked</div>
            </div>

            <div className={`p-4 rounded-2xl border ${currentBinary.mitigations.pie ? 'bg-emerald-950/20 border-emerald-500/30' : 'bg-rose-950/20 border-rose-500/30'}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold text-slate-300">PIE</span>
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="text-sm font-bold font-mono text-emerald-300">ENABLED</div>
              <div className="text-[10px] text-slate-400 mt-1">ASLR Compatible</div>
            </div>

            <div className={`p-4 rounded-2xl border ${currentBinary.mitigations.relro === 'Full RELRO' ? 'bg-emerald-950/20 border-emerald-500/30' : 'bg-amber-950/20 border-amber-500/30'}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold text-slate-300">RELRO</span>
                <ShieldCheck className="w-4 h-4 text-amber-400" />
              </div>
              <div className="text-sm font-bold font-mono text-amber-300">
                {currentBinary.mitigations.relro}
              </div>
              <div className="text-[10px] text-slate-400 mt-1">GOT Write Protection</div>
            </div>

            <div className={`p-4 rounded-2xl border ${currentBinary.mitigations.canary ? 'bg-emerald-950/20 border-emerald-500/30' : 'bg-rose-950/20 border-rose-500/30'}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold text-slate-300">Stack Canary</span>
                {currentBinary.mitigations.canary ? (
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                ) : (
                  <AlertTriangle className="w-4 h-4 text-rose-400" />
                )}
              </div>
              <div className={`text-sm font-bold font-mono ${currentBinary.mitigations.canary ? 'text-emerald-300' : 'text-rose-300'}`}>
                {currentBinary.mitigations.canary ? 'PRESENT' : 'MISSING'}
              </div>
              <div className="text-[10px] text-slate-400 mt-1">__stack_chk_fail</div>
            </div>

            <div className={`p-4 rounded-2xl border ${currentBinary.mitigations.fortify ? 'bg-emerald-950/20 border-emerald-500/30' : 'bg-slate-900 border-slate-800'}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold text-slate-300">FORTIFY_SOURCE</span>
                <ShieldCheck className="w-4 h-4 text-slate-400" />
              </div>
              <div className="text-sm font-bold font-mono text-slate-300">
                {currentBinary.mitigations.fortify ? 'ENABLED' : 'STANDARD'}
              </div>
              <div className="text-[10px] text-slate-400 mt-1">Buffer Bounds Checks</div>
            </div>

            <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold text-slate-300">Symbol Stripped</span>
                <Zap className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="text-sm font-bold font-mono text-cyan-300">
                {currentBinary.mitigations.stripped ? 'YES (DYN ONLY)' : 'NO (.symtab)'}
              </div>
              <div className="text-[10px] text-slate-400 mt-1">Production Stripped</div>
            </div>
          </div>

          {/* ELF Header Details Table */}
          <div className="rounded-2xl bg-slate-900/80 border border-slate-800 p-5">
            <h3 className="text-sm font-bold text-slate-200 mb-4 flex items-center gap-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              <span>ELF Binary Header Specification</span>
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs font-mono">
              <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800">
                <div className="text-slate-400 text-[11px]">ELF Magic</div>
                <div className="text-cyan-400 font-bold mt-0.5">{currentBinary.header.magic}</div>
              </div>

              <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800">
                <div className="text-slate-400 text-[11px]">Class &amp; Architecture</div>
                <div className="text-slate-200 font-bold mt-0.5">
                  {currentBinary.header.class} &bull; {currentBinary.header.machine}
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800">
                <div className="text-slate-400 text-[11px]">Data Endianness</div>
                <div className="text-slate-200 font-bold mt-0.5">{currentBinary.header.data}</div>
              </div>

              <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800">
                <div className="text-slate-400 text-[11px]">OS / ABI Target</div>
                <div className="text-slate-200 font-bold mt-0.5">{currentBinary.header.osAbi}</div>
              </div>

              <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800">
                <div className="text-slate-400 text-[11px]">Entry Point Address</div>
                <div className="text-emerald-400 font-bold mt-0.5">{currentBinary.header.entryPoint}</div>
              </div>

              <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800">
                <div className="text-slate-400 text-[11px]">Header Size / Program Headers</div>
                <div className="text-slate-200 font-bold mt-0.5">
                  {currentBinary.header.headerSize} bytes (Offset: 0x{currentBinary.header.programHeaderOffset.toString(16)})
                </div>
              </div>
            </div>
          </div>

          {/* Section Headers Table */}
          <div className="rounded-2xl bg-slate-900/80 border border-slate-800 overflow-hidden">
            <div className="p-4 bg-slate-950/80 border-b border-slate-800 flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                <span>ELF Sections Table &amp; Entropy Meters</span>
              </h3>
            </div>

            <div className="p-4 overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-[11px] text-slate-500 uppercase tracking-wider">
                    <th className="py-2 px-3">Section Name</th>
                    <th className="py-2 px-3">Type</th>
                    <th className="py-2 px-3">Flags</th>
                    <th className="py-2 px-3">Memory Address</th>
                    <th className="py-2 px-3">Size</th>
                    <th className="py-2 px-3">Entropy</th>
                    <th className="py-2 px-3">Purpose</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 font-mono">
                  {currentBinary.sections.map((sec, idx) => (
                    <tr key={idx} className="hover:bg-slate-950/50">
                      <td className="py-2.5 px-3 text-cyan-400 font-bold">{sec.name}</td>
                      <td className="py-2.5 px-3 text-slate-300">{sec.type}</td>
                      <td className="py-2.5 px-3 text-amber-400">{sec.flags}</td>
                      <td className="py-2.5 px-3 text-slate-400">{sec.address}</td>
                      <td className="py-2.5 px-3 text-slate-300">{sec.size} bytes</td>
                      <td className="py-2.5 px-3">
                        <div className="flex items-center gap-2">
                          <span className={sec.entropy > 7.0 ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                            {sec.entropy}
                          </span>
                          <div className="w-12 bg-slate-800 rounded-full h-1.5">
                            <div
                              className={`h-1.5 rounded-full ${sec.entropy > 7.0 ? 'bg-rose-500' : 'bg-cyan-500'}`}
                              style={{ width: `${(sec.entropy / 8.0) * 100}%` }}
                            />
                          </div>
                        </div>
                      </td>
                      <td className="py-2.5 px-3 font-sans text-slate-400 text-[11px]">
                        {sec.description}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Dynamic Symbols Tab */}
      {activeSubTab === 'symbols' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-4 rounded-2xl bg-slate-900/80 border border-slate-800">
            <div className="relative w-full sm:w-80">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search symbols, JNI methods, addresses..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-700 rounded-xl text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex items-center gap-1.5 self-start sm:self-auto flex-wrap">
              <button
                onClick={() => setFilterType('all')}
                className={`px-3 py-1 rounded-xl text-xs font-semibold transition cursor-pointer ${
                  filterType === 'all'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'bg-slate-950 text-slate-400 border border-slate-800'
                }`}
              >
                All ({currentBinary.symbols.length})
              </button>
              <button
                onClick={() => setFilterType('jni')}
                className={`px-3 py-1 rounded-xl text-xs font-semibold transition cursor-pointer ${
                  filterType === 'jni'
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                    : 'bg-slate-950 text-slate-400 border border-slate-800'
                }`}
              >
                JNI Exports ({currentBinary.symbols.filter((s) => s.isJniExport).length})
              </button>
              <button
                onClick={() => setFilterType('imported')}
                className={`px-3 py-1 rounded-xl text-xs font-semibold transition cursor-pointer ${
                  filterType === 'imported'
                    ? 'bg-blue-500/20 text-blue-300 border border-blue-500/40'
                    : 'bg-slate-950 text-slate-400 border border-slate-800'
                }`}
              >
                Imported Libc ({currentBinary.symbols.filter((s) => s.isImported).length})
              </button>
            </div>
          </div>

          <div className="rounded-2xl bg-slate-900/80 border border-slate-800 overflow-hidden shadow-xl">
            <div className="p-4 overflow-x-auto max-h-[580px]">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-[11px] text-slate-500 uppercase tracking-wider">
                    <th className="py-2 px-3">Address</th>
                    <th className="py-2 px-3">Type</th>
                    <th className="py-2 px-3">Binding</th>
                    <th className="py-2 px-3">Symbol Name</th>
                    <th className="py-2 px-3">Demangled Signature / Tag</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 font-mono">
                  {filteredSymbols.map((sym, idx) => (
                    <tr key={idx} className="hover:bg-slate-950/50">
                      <td className="py-2.5 px-3 text-cyan-400 font-semibold">{sym.address}</td>
                      <td className="py-2.5 px-3">
                        <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300">
                          {sym.type}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-400">{sym.binding}</td>
                      <td className="py-2.5 px-3">
                        <div className="flex items-center gap-2">
                          <span className={sym.isJniExport ? 'text-amber-300 font-bold' : 'text-slate-200'}>
                            {sym.name}
                          </span>
                          {sym.isJniExport && (
                            <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                              JNI
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                        {sym.demangledName || sym.riskTag || '-'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Strings Matrix Tab */}
      {activeSubTab === 'strings' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-4 rounded-2xl bg-slate-900/80 border border-slate-800">
            <div className="relative w-full sm:w-80">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search strings, URLs, encryption keys..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-700 rounded-xl text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div className="text-xs font-mono text-slate-400">
              Showing {filteredStrings.length} extracted strings
            </div>
          </div>

          <div className="rounded-2xl bg-slate-900/80 border border-slate-800 overflow-hidden shadow-xl">
            <div className="p-4 overflow-x-auto max-h-[580px]">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-[11px] text-slate-500 uppercase tracking-wider">
                    <th className="py-2 px-3">Offset</th>
                    <th className="py-2 px-3">Section</th>
                    <th className="py-2 px-3">Category</th>
                    <th className="py-2 px-3">Extracted Value</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 font-mono">
                  {filteredStrings.map((item, idx) => (
                    <tr key={idx} className="hover:bg-slate-950/50">
                      <td className="py-2 px-3 text-cyan-400 font-semibold">{item.offset}</td>
                      <td className="py-2 px-3 text-slate-400">{item.section}</td>
                      <td className="py-2 px-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            item.category === 'Crypto Key'
                              ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                              : item.category === 'URL'
                              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                              : item.category === 'System Command'
                              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                              : 'bg-slate-800 text-slate-300'
                          }`}
                        >
                          {item.category || 'General'}
                        </span>
                      </td>
                      <td className="py-2 px-3 text-slate-200 break-all select-all">
                        {item.value}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Hex Inspector Tab */}
      {activeSubTab === 'hex' && (
        <div className="rounded-2xl bg-slate-900/90 border border-slate-800 overflow-hidden shadow-xl">
          <div className="px-4 py-3 bg-slate-950/80 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Binary className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-mono font-bold text-slate-200">
                Raw Hex Bytecode Stream (Offset &bull; Hex Bytes &bull; ASCII Representation)
              </span>
            </div>
            <button
              onClick={() => handleCopyCode(currentBinary.rawHexSnippet)}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 transition cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy Hex'}</span>
            </button>
          </div>

          <div className="p-4 bg-slate-950 font-mono text-xs overflow-x-auto max-h-[580px]">
            <pre className="text-cyan-300 leading-relaxed font-mono">
              <code>{currentBinary.rawHexSnippet}</code>
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};
