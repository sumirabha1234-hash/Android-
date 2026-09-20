import React, { useState } from 'react';
import { Lock, ShieldCheck, ShieldAlert, AlertTriangle, Key, Calendar, FileText, Copy, Check, Award } from 'lucide-react';
import { SignatureDetails } from '../types';

interface SignatureTabProps {
  signature: SignatureDetails;
}

export const SignatureTab: React.FC<SignatureTabProps> = ({ signature }) => {
  const [copiedFingerprint, setCopiedFingerprint] = useState<string | null>(null);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedFingerprint(label);
    setTimeout(() => setCopiedFingerprint(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="p-6 rounded-2xl bg-slate-900/70 border border-slate-800 shadow-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className={`w-14 h-14 rounded-2xl flex items-center justify-center border ${
            signature.warnings.length === 0
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
              : 'bg-amber-500/10 border-amber-500/30 text-amber-400'
          }`}>
            <Award className="w-8 h-8" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base sm:text-lg font-bold text-slate-100">
                APK Code Signing Certificate
              </h3>
              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                signature.isSelfSigned
                  ? 'bg-amber-500/20 text-amber-400 border-amber-500/30'
                  : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
              }`}>
                {signature.isSelfSigned ? 'Self-Signed / Debug' : 'CA-Signed Release'}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Signing Scheme: <strong className="text-cyan-300 font-mono">{signature.schemeVersion}</strong> &bull; Algorithm: <strong className="text-slate-300 font-mono">{signature.algorithm}</strong>
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <div className="px-3 py-1.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300">
            Key Size: <span className="font-bold text-cyan-300">{signature.keySize} bits</span>
          </div>
        </div>
      </div>

      {/* Signature Warnings */}
      {signature.warnings.length > 0 && (
        <div className="p-4 rounded-xl bg-amber-950/20 border border-amber-500/30 text-xs">
          <div className="font-bold text-amber-300 flex items-center gap-2 mb-2 font-mono uppercase text-[11px] tracking-wider">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            Signature Integrity &amp; Hardening Warnings
          </div>
          <ul className="space-y-1.5 pl-6 list-disc text-amber-200/90">
            {signature.warnings.map((warn, idx) => (
              <li key={idx}>{warn}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Certificate Details Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Certificate Identity */}
        <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
          <div className="flex items-center gap-2 text-slate-200 font-semibold text-sm">
            <FileText className="w-4 h-4 text-cyan-400" />
            Signer &amp; Issuer Identity
          </div>

          <div className="space-y-3 text-xs font-mono">
            <div>
              <div className="text-slate-400 text-[11px] mb-1">Subject Distinguished Name (DN)</div>
              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 text-slate-200 break-all select-all">
                {signature.subject}
              </div>
            </div>

            <div>
              <div className="text-slate-400 text-[11px] mb-1">Issuer Distinguished Name (DN)</div>
              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 text-slate-200 break-all select-all">
                {signature.issuer}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3 pt-2">
              <div>
                <div className="text-slate-400 text-[11px] mb-1 flex items-center gap-1">
                  <Calendar className="w-3 h-3 text-cyan-400" /> Valid From
                </div>
                <div className="p-2 rounded bg-slate-950 border border-slate-800 text-slate-300 text-[11px]">
                  {signature.validFrom}
                </div>
              </div>

              <div>
                <div className="text-slate-400 text-[11px] mb-1 flex items-center gap-1">
                  <Calendar className="w-3 h-3 text-cyan-400" /> Valid To
                </div>
                <div className="p-2 rounded bg-slate-950 border border-slate-800 text-slate-300 text-[11px]">
                  {signature.validTo}
                </div>
              </div>
            </div>

            <div>
              <div className="text-slate-400 text-[11px] mb-1">Serial Number</div>
              <div className="p-2 rounded bg-slate-950 border border-slate-800 text-slate-300 text-[11px] select-all">
                {signature.serialNumber}
              </div>
            </div>
          </div>
        </div>

        {/* Certificate Fingerprints */}
        <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
          <div className="flex items-center gap-2 text-slate-200 font-semibold text-sm">
            <Key className="w-4 h-4 text-cyan-400" />
            Certificate Fingerprints &amp; Checksums
          </div>

          <div className="space-y-3 text-xs font-mono">
            {/* SHA-256 Fingerprint */}
            <div>
              <div className="flex justify-between items-center text-[11px] text-slate-400 mb-1">
                <span>SHA-256 Fingerprint</span>
                <button
                  onClick={() => copyToClipboard(signature.sha256Fingerprint, 'sha256')}
                  className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer"
                >
                  {copiedFingerprint === 'sha256' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  {copiedFingerprint === 'sha256' ? 'Copied' : 'Copy'}
                </button>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-cyan-300 text-[11px] break-all select-all font-bold">
                {signature.sha256Fingerprint}
              </div>
            </div>

            {/* SHA-1 Fingerprint */}
            <div>
              <div className="flex justify-between items-center text-[11px] text-slate-400 mb-1">
                <span>SHA-1 Fingerprint</span>
                <button
                  onClick={() => copyToClipboard(signature.sha1Fingerprint, 'sha1')}
                  className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer"
                >
                  {copiedFingerprint === 'sha1' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  {copiedFingerprint === 'sha1' ? 'Copied' : 'Copy'}
                </button>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 text-[11px] break-all select-all">
                {signature.sha1Fingerprint}
              </div>
            </div>

            {/* MD5 Fingerprint */}
            <div>
              <div className="flex justify-between items-center text-[11px] text-slate-400 mb-1">
                <span>MD5 Fingerprint</span>
                <button
                  onClick={() => copyToClipboard(signature.md5Fingerprint, 'md5')}
                  className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer"
                >
                  {copiedFingerprint === 'md5' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  {copiedFingerprint === 'md5' ? 'Copied' : 'Copy'}
                </button>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 text-[11px] break-all select-all">
                {signature.md5Fingerprint}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
