import React, { useState } from 'react';
import { ShieldAlert, AlertTriangle, Info, CheckCircle2, FileCode, Tag, Search, Filter, ArrowUpRight, Shield } from 'lucide-react';
import { SecurityVulnerability, VulnerabilitySeverity } from '../types';

interface VulnerabilitiesTabProps {
  vulnerabilities: SecurityVulnerability[];
  onViewInCode?: (filePath: string) => void;
}

export const VulnerabilitiesTab: React.FC<VulnerabilitiesTabProps> = ({
  vulnerabilities,
  onViewInCode,
}) => {
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const filteredVulnerabilities = vulnerabilities.filter((vuln) => {
    const matchesSeverity = selectedSeverity === 'all' || vuln.severity === selectedSeverity;
    const matchesCategory = selectedCategory === 'all' || vuln.category === selectedCategory;
    const matchesSearch =
      searchQuery === '' ||
      vuln.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      vuln.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (vuln.cwe && vuln.cwe.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (vuln.masvsId && vuln.masvsId.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesSeverity && matchesCategory && matchesSearch;
  });

  const getSeverityBadge = (sev: VulnerabilitySeverity) => {
    switch (sev) {
      case 'critical':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
      case 'high':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      case 'medium':
        return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40';
      case 'low':
        return 'bg-blue-500/20 text-blue-300 border-blue-500/40';
      default:
        return 'bg-slate-500/20 text-slate-300 border-slate-500/40';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Filter Controls */}
      <div className="flex flex-col sm:flex-row gap-3 sm:items-center sm:justify-between p-4 rounded-xl bg-slate-900/60 border border-slate-800">
        <div className="flex items-center gap-2">
          <div className="relative flex-1 sm:w-64">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search CVE, CWE, MASVS, keywords..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Severity Buttons */}
          <div className="flex items-center p-1 rounded-lg bg-slate-950 border border-slate-800 text-xs">
            {['all', 'critical', 'high', 'medium', 'low'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSelectedSeverity(sev)}
                className={`px-2.5 py-1 rounded-md capitalize font-mono text-[11px] transition cursor-pointer ${
                  selectedSeverity === sev
                    ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Category Dropdown */}
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500 cursor-pointer"
          >
            <option value="all">All Categories</option>
            <option value="manifest">Manifest &amp; Components</option>
            <option value="crypto">Cryptography</option>
            <option value="network">Network Security</option>
            <option value="secret">Hardcoded Secrets</option>
            <option value="code">Code &amp; WebViews</option>
            <option value="permission">Permissions</option>
          </select>
        </div>
      </div>

      {/* Vulnerabilities List */}
      {filteredVulnerabilities.length === 0 ? (
        <div className="p-12 text-center rounded-2xl bg-slate-900/40 border border-slate-800">
          <CheckCircle2 className="w-12 h-12 text-emerald-400 mx-auto mb-3" />
          <h4 className="text-base font-semibold text-slate-200">No vulnerabilities found in this filter</h4>
          <p className="text-xs text-slate-400 mt-1">Try changing your severity or category filter criteria.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {filteredVulnerabilities.map((vuln) => (
            <div
              key={vuln.id}
              className="p-5 rounded-2xl bg-slate-900/70 border border-slate-800/90 shadow-md hover:border-slate-700/90 transition"
            >
              {/* Card Top Title & Badges */}
              <div className="flex flex-wrap items-start justify-between gap-3 mb-3">
                <div className="flex items-start gap-3">
                  <span className={`px-2.5 py-1 rounded-md text-xs font-mono font-bold uppercase tracking-wider border ${getSeverityBadge(vuln.severity)}`}>
                    {vuln.severity}
                  </span>
                  <div>
                    <h3 className="text-sm sm:text-base font-bold text-slate-100">{vuln.title}</h3>
                    <div className="flex flex-wrap items-center gap-2 mt-1">
                      {vuln.cwe && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                          {vuln.cwe}
                        </span>
                      )}
                      {vuln.masvsId && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-300 border border-cyan-800/60">
                          OWASP {vuln.masvsId}
                        </span>
                      )}
                      <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800">
                        Category: {vuln.category}
                      </span>
                    </div>
                  </div>
                </div>

                {vuln.location && onViewInCode && (
                  <button
                    onClick={() => onViewInCode(vuln.location || '')}
                    className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 font-mono transition cursor-pointer"
                  >
                    <span>{vuln.location.split(' ')[0]}</span>
                    <ArrowUpRight className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>

              {/* Description */}
              <div className="mb-3 text-xs text-slate-300 leading-relaxed">
                {vuln.description}
              </div>

              {/* Impact Section */}
              <div className="mb-3 p-3 rounded-xl bg-slate-950/60 border border-rose-950/50 text-xs">
                <div className="font-semibold text-rose-300 flex items-center gap-1.5 mb-1 font-mono text-[11px] uppercase tracking-wide">
                  <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                  Exploitation &amp; Impact
                </div>
                <div className="text-slate-300 text-xs leading-relaxed">{vuln.impact}</div>
              </div>

              {/* Code Snippet if available */}
              {vuln.codeSnippet && (
                <div className="mb-3">
                  <div className="text-[11px] font-mono text-slate-400 mb-1 flex items-center gap-1">
                    <FileCode className="w-3.5 h-3.5 text-slate-500" />
                    Vulnerable Code Snippet / Manifest Entry
                  </div>
                  <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-[11px] font-mono text-cyan-300 overflow-x-auto selection:bg-cyan-900/50">
                    <code>{vuln.codeSnippet}</code>
                  </pre>
                </div>
              )}

              {/* Remediation Guide */}
              <div className="p-3 rounded-xl bg-emerald-950/20 border border-emerald-900/40 text-xs">
                <div className="font-semibold text-emerald-300 flex items-center gap-1.5 mb-1 font-mono text-[11px] uppercase tracking-wide">
                  <Shield className="w-3.5 h-3.5 text-emerald-400" />
                  Remediation &amp; Mitigation Guidance
                </div>
                <div className="text-emerald-100/90 text-xs leading-relaxed font-sans">{vuln.recommendation}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
