import { useEffect, useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { Search, ChevronUp, ChevronDown, ChevronLeft, ChevronRight, Play } from 'lucide-react';
import { CVSSBadge, VendorSeverityBadge, VEXBadge } from '../components/SeverityBadge';
import { getTriageQueue, TriageFilter } from '../api/client';
import type { Finding } from '../types';

type SortField = 'cveId' | 'cvss3Score' | 'severity' | 'packageName' | 'serverName';
type SortDirection = 'asc' | 'desc';

const ITEMS_PER_PAGE = 15;

export default function Triage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [filter, setFilter] = useState<TriageFilter | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [hideNotAffected, setHideNotAffected] = useState(true);

  // Filtering, sorting, pagination
  const [searchQuery, setSearchQuery] = useState('');
  const [sortField, setSortField] = useState<SortField>('cvss3Score');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');
  const [currentPage, setCurrentPage] = useState(1);

  useEffect(() => {
    async function fetchData() {
      setLoading(true);
      try {
        const data = await getTriageQueue({ limit: 1000, hideVexNotAffected: hideNotAffected });
        setFindings(data.findings || []);
        setTotal(data.total);
        setFilter(data.filter);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load triage queue');
      } finally {
        setLoading(false);
      }
    }
    fetchData();
  }, [hideNotAffected]);

  // Reset page when search changes
  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery]);

  // Filter findings by search query
  const filteredFindings = useMemo(() => {
    if (!searchQuery.trim()) return findings;
    const query = searchQuery.toLowerCase();
    return findings.filter(f => 
      f.cveId.toLowerCase().includes(query) ||
      f.packageName.toLowerCase().includes(query) ||
      f.serverName?.toLowerCase().includes(query) ||
      f.severity?.toLowerCase().includes(query) ||
      f.summary?.toLowerCase().includes(query)
    );
  }, [findings, searchQuery]);

  // Sort findings
  const sortedFindings = useMemo(() => {
    const sorted = [...filteredFindings].sort((a, b) => {
      let aVal: string | number | null = null;
      let bVal: string | number | null = null;

      switch (sortField) {
        case 'cveId':
          aVal = a.cveId;
          bVal = b.cveId;
          break;
        case 'cvss3Score':
          aVal = a.nvdCvss3Score ?? a.cvss3Score ?? 0;
          bVal = b.nvdCvss3Score ?? b.cvss3Score ?? 0;
          break;
        case 'severity':
          aVal = a.severity || '';
          bVal = b.severity || '';
          break;
        case 'packageName':
          aVal = a.packageName;
          bVal = b.packageName;
          break;
        case 'serverName':
          aVal = a.serverName || '';
          bVal = b.serverName || '';
          break;
      }

      if (aVal === null && bVal === null) return 0;
      if (aVal === null) return 1;
      if (bVal === null) return -1;

      if (typeof aVal === 'string' && typeof bVal === 'string') {
        return sortDirection === 'asc' 
          ? aVal.localeCompare(bVal)
          : bVal.localeCompare(aVal);
      }

      return sortDirection === 'asc' 
        ? (aVal as number) - (bVal as number)
        : (bVal as number) - (aVal as number);
    });
    return sorted;
  }, [filteredFindings, sortField, sortDirection]);

  // Pagination
  const totalPages = Math.ceil(sortedFindings.length / ITEMS_PER_PAGE);
  const paginatedFindings = useMemo(() => {
    const start = (currentPage - 1) * ITEMS_PER_PAGE;
    return sortedFindings.slice(start, start + ITEMS_PER_PAGE);
  }, [sortedFindings, currentPage]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  const SortHeader = ({ field, children }: { field: SortField; children: React.ReactNode }) => (
    <th 
      className="table-header text-left py-3 px-4 cursor-pointer hover:bg-[#1a2420] select-none"
      onClick={() => handleSort(field)}
    >
      <div className="flex items-center gap-1">
        {children}
        {sortField === field && (
          sortDirection === 'asc' 
            ? <ChevronUp className="w-4 h-4" />
            : <ChevronDown className="w-4 h-4" />
        )}
      </div>
    </th>
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-[#a5d6a7]">Loading triage queue...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[#e8f5e9]">Triage Queue</h1>
          <p className="text-[#a5d6a7] mt-1">
            {total} CVEs pending assessment {filter && (
              filter.mode === 'cvss' 
                ? `(CVSS ≥ ${filter.threshold?.toFixed(1) ?? '7.0'})`
                : `(Vendor: ${filter.severities?.map(s => s.charAt(0).toUpperCase() + s.slice(1)).join(', ') || 'None'}${filter.includeUnrated ? ' + Unrated' : ''})`
            )}
          </p>
        </div>
        
        <div className="flex items-center gap-4">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#6b7280]" />
            <input
              type="text"
              placeholder="Search queue..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10 pr-4 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] placeholder-[#6b7280] focus:outline-none focus:border-[#4ade80] w-64"
            />
          </div>

          {/* VEX toggle */}
          <label className="flex items-center gap-2 cursor-pointer text-sm text-[#a5d6a7]">
            <input
              type="checkbox"
              className="w-4 h-4 rounded border-[#2d3f36] bg-[#0a0f0d] text-[#4ade80] focus:ring-[#4ade80]"
              checked={hideNotAffected}
              onChange={(e) => { setHideNotAffected(e.target.checked); setCurrentPage(1); }}
            />
            Hide "Not Affected"
          </label>

          {/* Start Triage Button */}
          {findings.length > 0 && (
            <Link
              to={`/triage/${findings[0]?.cveId}`}
              className="btn flex items-center gap-2 bg-[#4ade80] text-[#0a0f0d] font-semibold hover:bg-[#22c55e]"
            >
              <Play className="w-4 h-4" />
              Start Triage
            </Link>
          )}
        </div>
      </div>

      {error && (
        <div className="card border-red-600/50 bg-red-600/5">
          <p className="text-red-400">{error}</p>
        </div>
      )}

      {/* Queue Table */}
      <div className="card">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#2d3f36]">
                <SortHeader field="cveId">CVE ID</SortHeader>
                <SortHeader field="cvss3Score">CVSS</SortHeader>
                <SortHeader field="severity">Vendor</SortHeader>
                <SortHeader field="packageName">Package</SortHeader>
                <SortHeader field="serverName">Example Server</SortHeader>
                <th className="table-header text-left py-3 px-4">VEX</th>
                <th className="table-header text-left py-3 px-4">Summary</th>
                <th className="table-header text-left py-3 px-4">Action</th>
              </tr>
            </thead>
            <tbody>
              {paginatedFindings.map((finding) => (
                <tr key={finding.cveId} className="table-row">
                  <td className="py-3 px-4 font-mono text-[#4ade80]">
                    {finding.cveId}
                  </td>
                  <td className="py-3 px-4">
                    <CVSSBadge score={finding.nvdCvss3Score ?? finding.cvss3Score} cveId={finding.cveId} />
                  </td>
                  <td className="py-3 px-4">
                    <VendorSeverityBadge severity={finding.severity} sourceLink={finding.sourceLink} />
                  </td>
                  <td className="py-3 px-4 font-mono text-sm text-[#a5d6a7]">
                    {finding.packageName}
                  </td>
                  <td className="py-3 px-4 text-[#a5d6a7]">
                    {finding.serverName}
                  </td>
                  <td className="py-3 px-4">
                    <VEXBadge status={finding.vexStatus} justification={finding.vexJustification} />
                  </td>
                  <td className="py-3 px-4 max-w-xs">
                    <span className="text-sm text-[#a5d6a7] truncate block">
                      {finding.summary || '-'}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <Link
                      to={`/triage/${finding.cveId}`}
                      className="px-3 py-1 rounded bg-[#4ade80]/20 text-[#4ade80] hover:bg-[#4ade80]/30 text-sm font-medium"
                    >
                      Assess
                    </Link>
                  </td>
                </tr>
              ))}
              {paginatedFindings.length === 0 && (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-[#6b7280]">
                    {searchQuery 
                      ? 'No CVEs match your search' 
                      : 'All caught up! No high-severity findings require assessment.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between mt-4 pt-4 border-t border-[#2d3f36]">
            <div className="text-sm text-[#6b7280]">
              Showing {((currentPage - 1) * ITEMS_PER_PAGE) + 1} to {Math.min(currentPage * ITEMS_PER_PAGE, sortedFindings.length)} of {sortedFindings.length} CVEs
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setCurrentPage(1)}
                disabled={currentPage === 1}
                className="px-3 py-1 rounded bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36] disabled:opacity-50 disabled:cursor-not-allowed"
              >
                First
              </button>
              <button
                onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                disabled={currentPage === 1}
                className="p-1 rounded bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36] disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ChevronLeft className="w-5 h-5" />
              </button>
              <span className="px-3 py-1 text-[#e8f5e9]">
                Page {currentPage} of {totalPages}
              </span>
              <button
                onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                disabled={currentPage === totalPages}
                className="p-1 rounded bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36] disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ChevronRight className="w-5 h-5" />
              </button>
              <button
                onClick={() => setCurrentPage(totalPages)}
                disabled={currentPage === totalPages}
                className="px-3 py-1 rounded bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36] disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Last
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
