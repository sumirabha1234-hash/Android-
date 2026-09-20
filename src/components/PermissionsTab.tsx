import React, { useState } from 'react';
import { ShieldAlert, ShieldCheck, Lock, AlertTriangle, Search, Info, Eye, Smartphone, Wifi, HardDrive, Bell } from 'lucide-react';
import { AndroidPermission } from '../types';

interface PermissionsTabProps {
  permissions: AndroidPermission[];
}

export const PermissionsTab: React.FC<PermissionsTabProps> = ({ permissions }) => {
  const [filterType, setFilterType] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const dangerousCount = permissions.filter((p) => p.isDangerous).length;
  const normalCount = permissions.filter((p) => p.protectionLevel === 'normal').length;
  const systemCount = permissions.filter((p) => p.protectionLevel === 'signature' || p.protectionLevel === 'signatureOrSystem').length;

  const filteredPermissions = permissions.filter((perm) => {
    const matchesFilter =
      filterType === 'all' ||
      (filterType === 'dangerous' && perm.isDangerous) ||
      (filterType === 'normal' && perm.protectionLevel === 'normal') ||
      (filterType === 'system' && (perm.protectionLevel === 'signature' || perm.protectionLevel === 'signatureOrSystem'));
    const matchesSearch =
      searchQuery === '' ||
      perm.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      perm.shortName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      perm.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      perm.riskAssessment.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  const getCategoryIcon = (cat: AndroidPermission['category']) => {
    switch (cat) {
      case 'Privacy': return <Eye className="w-3.5 h-3.5" />;
      case 'Network': return <Wifi className="w-3.5 h-3.5" />;
      case 'Storage': return <HardDrive className="w-3.5 h-3.5" />;
      case 'Hardware': return <Smartphone className="w-3.5 h-3.5" />;
      default: return <Bell className="w-3.5 h-3.5" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Danger Summary Matrix */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-between">
          <div>
            <div className="text-xs font-mono uppercase text-rose-300 font-semibold">Dangerous / High-Risk</div>
            <div className="text-2xl font-bold font-mono text-rose-200 mt-1">{dangerousCount}</div>
            <div className="text-[11px] text-rose-400/80">Requires runtime user grant</div>
          </div>
          <ShieldAlert className="w-8 h-8 text-rose-400 opacity-80" />
        </div>

        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-between">
          <div>
            <div className="text-xs font-mono uppercase text-emerald-300 font-semibold">Normal / Standard</div>
            <div className="text-2xl font-bold font-mono text-emerald-200 mt-1">{normalCount}</div>
            <div className="text-[11px] text-emerald-400/80">Granted at installation</div>
          </div>
          <ShieldCheck className="w-8 h-8 text-emerald-400 opacity-80" />
        </div>

        <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-between">
          <div>
            <div className="text-xs font-mono uppercase text-amber-300 font-semibold">System / Signature</div>
            <div className="text-2xl font-bold font-mono text-amber-200 mt-1">{systemCount}</div>
            <div className="text-[11px] text-amber-400/80">Privileged device capabilities</div>
          </div>
          <Lock className="w-8 h-8 text-amber-400 opacity-80" />
        </div>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-col sm:flex-row gap-3 sm:items-center sm:justify-between p-4 rounded-xl bg-slate-900/60 border border-slate-800">
        <div className="relative flex-1 sm:w-72">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search requested permissions..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>

        <div className="flex items-center p-1 rounded-lg bg-slate-950 border border-slate-800 text-xs">
          <button
            onClick={() => setFilterType('all')}
            className={`px-3 py-1 rounded-md text-[11px] font-mono transition cursor-pointer ${
              filterType === 'all'
                ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            All ({permissions.length})
          </button>
          <button
            onClick={() => setFilterType('dangerous')}
            className={`px-3 py-1 rounded-md text-[11px] font-mono transition cursor-pointer ${
              filterType === 'dangerous'
                ? 'bg-rose-500/20 text-rose-300 font-bold border border-rose-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Dangerous ({dangerousCount})
          </button>
          <button
            onClick={() => setFilterType('normal')}
            className={`px-3 py-1 rounded-md text-[11px] font-mono transition cursor-pointer ${
              filterType === 'normal'
                ? 'bg-emerald-500/20 text-emerald-300 font-bold border border-emerald-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Normal ({normalCount})
          </button>
        </div>
      </div>

      {/* Permissions Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filteredPermissions.map((perm) => (
          <div
            key={perm.name}
            className={`p-4 rounded-xl border transition ${
              perm.isDangerous
                ? 'bg-rose-950/10 border-rose-500/30 hover:border-rose-500/50'
                : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-start justify-between gap-2 mb-2">
              <div className="flex items-center gap-2">
                <span className={`p-1.5 rounded-lg border ${
                  perm.isDangerous
                    ? 'bg-rose-500/20 text-rose-400 border-rose-500/30'
                    : 'bg-slate-800 text-slate-300 border-slate-700'
                }`}>
                  {getCategoryIcon(perm.category)}
                </span>
                <div>
                  <div className="text-xs font-bold font-mono text-slate-100">
                    {perm.shortName}
                  </div>
                  <div className="text-[10px] font-mono text-slate-400 truncate max-w-[240px]">
                    {perm.name}
                  </div>
                </div>
              </div>

              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                perm.isDangerous
                  ? 'bg-rose-500/20 text-rose-400 border-rose-500/40'
                  : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
              }`}>
                {perm.protectionLevel}
              </span>
            </div>

            <div className="text-xs text-slate-300 mb-2 leading-relaxed">
              {perm.description}
            </div>

            <div className="pt-2 border-t border-slate-800/80 text-[11px] flex items-start gap-1.5 text-slate-400">
              <Info className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
              <span><strong className="text-slate-300">Risk Vector:</strong> {perm.riskAssessment}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
