import React, { useState } from 'react';
import { Globe, Server, Cloud, ShieldAlert, Copy, Check, ExternalLink, Search, Radio, Wifi, Lock } from 'lucide-react';
import { ExtractedEndpoint } from '../types';

interface EndpointsTabProps {
  endpoints: ExtractedEndpoint[];
}

export const EndpointsTab: React.FC<EndpointsTabProps> = ({ endpoints }) => {
  const [selectedType, setSelectedType] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [copiedUrl, setCopiedUrl] = useState<string | null>(null);

  const copyEndpoint = (url: string) => {
    navigator.clipboard.writeText(url);
    setCopiedUrl(url);
    setTimeout(() => setCopiedUrl(null), 2000);
  };

  const internalCount = endpoints.filter((e) => e.type === 'internal_api').length;
  const externalCount = endpoints.filter((e) => e.type === 'external_url').length;
  const ipCount = endpoints.filter((e) => e.type === 'ip_address').length;
  const insecureCount = endpoints.filter((e) => e.isInsecure).length;

  const filteredEndpoints = endpoints.filter((ep) => {
    const matchesType =
      selectedType === 'all' ||
      (selectedType === 'internal' && ep.type === 'internal_api') ||
      (selectedType === 'external' && ep.type === 'external_url') ||
      (selectedType === 'ip' && ep.type === 'ip_address') ||
      (selectedType === 'insecure' && ep.isInsecure);
    const matchesSearch =
      searchQuery === '' ||
      ep.url.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (ep.host && ep.host.toLowerCase().includes(searchQuery.toLowerCase())) ||
      ep.category.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesType && matchesSearch;
  });

  const getCategoryBadge = (cat: ExtractedEndpoint['category']) => {
    switch (cat) {
      case 'Cloud Storage':
        return 'bg-purple-500/20 text-purple-300 border-purple-500/30';
      case 'Auth Service':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/30';
      case 'Analytics & Ads':
        return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
      case 'IP Host':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/30';
      default:
        return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30';
    }
  };

  return (
    <div className="space-y-6">
      {/* Overview Stat Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>External URLs</span>
            <Globe className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100 mt-2">{externalCount}</div>
          <div className="text-[10px] text-slate-500">Contacted web services</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>Internal API Routes</span>
            <Server className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100 mt-2">{internalCount}</div>
          <div className="text-[10px] text-slate-500">Extracted REST paths</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>IP Addresses</span>
            <Radio className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100 mt-2">{ipCount}</div>
          <div className="text-[10px] text-slate-500">Hardcoded hosts</div>
        </div>

        <div className="p-4 rounded-xl bg-rose-950/20 border border-rose-500/30">
          <div className="flex items-center justify-between text-xs text-rose-300 font-mono">
            <span>Insecure (HTTP/Cleartext)</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-200 mt-2">{insecureCount}</div>
          <div className="text-[10px] text-rose-400/80">MitM risk detected</div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-3 sm:items-center sm:justify-between p-4 rounded-xl bg-slate-900/60 border border-slate-800">
        <div className="relative flex-1 sm:w-72">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search URLs, hosts, paths, cloud services..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>

        <div className="flex flex-wrap items-center p-1 rounded-lg bg-slate-950 border border-slate-800 text-xs">
          <button
            onClick={() => setSelectedType('all')}
            className={`px-2.5 py-1 rounded-md text-[11px] font-mono transition cursor-pointer ${
              selectedType === 'all'
                ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            All ({endpoints.length})
          </button>
          <button
            onClick={() => setSelectedType('external')}
            className={`px-2.5 py-1 rounded-md text-[11px] font-mono transition cursor-pointer ${
              selectedType === 'external'
                ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            External URLs ({externalCount})
          </button>
          <button
            onClick={() => setSelectedType('internal')}
            className={`px-2.5 py-1 rounded-md text-[11px] font-mono transition cursor-pointer ${
              selectedType === 'internal'
                ? 'bg-emerald-500/20 text-emerald-300 font-bold border border-emerald-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Internal APIs ({internalCount})
          </button>
          <button
            onClick={() => setSelectedType('insecure')}
            className={`px-2.5 py-1 rounded-md text-[11px] font-mono transition cursor-pointer ${
              selectedType === 'insecure'
                ? 'bg-rose-500/20 text-rose-300 font-bold border border-rose-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Insecure ({insecureCount})
          </button>
        </div>
      </div>

      {/* Endpoints Table / List */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/50 overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase text-[10px] tracking-wider">
              <tr>
                <th className="p-3.5">Endpoint / URL / Route</th>
                <th className="p-3.5">Protocol &amp; Security</th>
                <th className="p-3.5">Category</th>
                <th className="p-3.5">Source File</th>
                <th className="p-3.5 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredEndpoints.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-slate-500">
                    No network endpoints found matching criteria.
                  </td>
                </tr>
              ) : (
                filteredEndpoints.map((ep, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/40 transition">
                    <td className="p-3.5 max-w-[320px] sm:max-w-md">
                      <div className="font-semibold text-slate-200 truncate select-all" title={ep.url}>
                        {ep.url}
                      </div>
                      {ep.host && (
                        <div className="text-[10px] text-slate-400 truncate mt-0.5">
                          Host: {ep.host}
                        </div>
                      )}
                    </td>

                    <td className="p-3.5 whitespace-nowrap">
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold border ${
                        ep.isInsecure
                          ? 'bg-rose-500/20 text-rose-400 border-rose-500/30'
                          : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                      }`}>
                        {ep.isInsecure ? (
                          <ShieldAlert className="w-3 h-3 text-rose-400" />
                        ) : (
                          <Lock className="w-3 h-3 text-emerald-400" />
                        )}
                        {ep.protocol}
                      </span>
                    </td>

                    <td className="p-3.5 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getCategoryBadge(ep.category)}`}>
                        {ep.category}
                      </span>
                    </td>

                    <td className="p-3.5 whitespace-nowrap text-slate-400 text-[11px]">
                      {ep.sourceFile || 'classes.dex'}
                    </td>

                    <td className="p-3.5 text-right whitespace-nowrap">
                      <button
                        onClick={() => copyEndpoint(ep.url)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-[11px] transition cursor-pointer"
                      >
                        {copiedUrl === ep.url ? (
                          <>
                            <Check className="w-3 h-3 text-emerald-400" />
                            <span>Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" />
                            <span>Copy</span>
                          </>
                        )}
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
