import { useEffect, useState } from 'react';
import { Search, ChevronUp, ChevronDown, ChevronLeft, ChevronRight, X, Database, ExternalLink, AlertTriangle } from 'lucide-react';
import { getOVALDefinitions, getOVALDefinition, getOVALSources, type OVALDefinitionFilter } from '../api/client';
import type { OVALDefinition } from '../types';

const ITEMS_PER_PAGE = 50;

export default function OVALDatabase() {
  const [definitions, setDefinitions] = useState<OVALDefinition[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [total, setTotal] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  
  // Filter state
  const [filters, setFilters] = useState<OVALDefinitionFilter>({
    limit: ITEMS_PER_PAGE,
    offset: 0,
    sortBy: 'createdAt',
    sortOrder: 'desc',
  });
  
  // Available filter options (from sources)
  const [availableDistributions, setAvailableDistributions] = useState<string[]>([]);
  const [availableVersions, setAvailableVersions] = useState<string[]>([]);
  const [availableCodenames, setAvailableCodenames] = useState<string[]>([]);
  const [availableSeverities, setAvailableSeverities] = useState<string[]>([]);
  
  // Detail modal
  const [selectedDefinition, setSelectedDefinition] = useState<OVALDefinition | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // Load filter options
  useEffect(() => {
    async function loadFilterOptions() {
      try {
        const sources = await getOVALSources();
        const distros = [...new Set(sources.sources.map(s => s.distribution))].sort();
        const versions = [...new Set(sources.sources.map(s => s.version))].sort();
        const codenames = [...new Set(sources.sources.map(s => s.codename).filter(Boolean))].sort();
        
        setAvailableDistributions(distros);
        setAvailableVersions(versions);
        setAvailableCodenames(codenames);
        setAvailableSeverities(['critical', 'high', 'medium', 'low']); // Common severities
      } catch (err) {
        console.error('Failed to load filter options:', err);
      }
    }
    loadFilterOptions();
  }, []);

  // Load definitions
  useEffect(() => {
    async function fetchData() {
      setLoading(true);
      setError(null);
      try {
        const offset = (currentPage - 1) * ITEMS_PER_PAGE;
        const data = await getOVALDefinitions({
          ...filters,
          limit: ITEMS_PER_PAGE,
          offset,
        });
        setDefinitions(data.definitions || []);
        setTotal(data.total || 0);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load OVAL definitions');
      } finally {
        setLoading(false);
      }
    }
    fetchData();
  }, [currentPage, filters]);

  const handleFilterChange = (key: keyof OVALDefinitionFilter, value: string | boolean | undefined) => {
    setFilters(prev => ({
      ...prev,
      [key]: value === undefined || value === '' ? undefined : value,
    }));
    setCurrentPage(1);
  };

  const clearFilters = () => {
    setFilters({
      limit: ITEMS_PER_PAGE,
      offset: 0,
      sortBy: 'createdAt',
      sortOrder: 'desc',
    });
    setCurrentPage(1);
  };

  const handleSort = (field: 'cveId' | 'severity' | 'createdAt') => {
    setFilters(prev => ({
      ...prev,
      sortBy: field,
      sortOrder: prev.sortBy === field && prev.sortOrder === 'desc' ? 'asc' : 'desc',
    }));
  };

  const handleRowClick = async (definition: OVALDefinition) => {
    setDetailLoading(true);
    try {
      const detail = await getOVALDefinition(definition.id);
      setSelectedDefinition(detail);
    } catch (err) {
      console.error('Failed to load definition details:', err);
    } finally {
      setDetailLoading(false);
    }
  };

  const totalPages = Math.ceil(total / ITEMS_PER_PAGE);
  const hasActiveFilters = !!(
    filters.distribution || filters.version || filters.codename ||
    filters.cveId || filters.severity || filters.sourceType || filters.package || filters.search || filters.hasExploit
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <div className="w-12 h-12 bg-[#1a2420] rounded-lg flex items-center justify-center">
          <Database className="w-6 h-6 text-[#4ade80]" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-[#e8f5e9]">OVAL Database</h1>
          <p className="text-[#a5d6a7]">Browse vulnerability definitions from OVAL feeds</p>
        </div>
      </div>

      {/* Global Search */}
      <div className="card">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-[#6b7280]" />
          <input
            type="text"
            placeholder="Search by CVE ID, title, or description..."
            value={filters.search || ''}
            onChange={(e) => handleFilterChange('search', e.target.value)}
            className="w-full pl-10 pr-4 py-3 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] placeholder-[#6b7280] focus:outline-none focus:border-[#4ade80]"
          />
        </div>
      </div>

      {/* Filters */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-[#e8f5e9]">Filters</h2>
          {hasActiveFilters && (
            <button
              onClick={clearFilters}
              className="text-sm text-[#4ade80] hover:underline flex items-center gap-1"
            >
              <X className="w-4 h-4" />
              Clear all
            </button>
          )}
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Distribution */}
          <div>
            <label className="block text-sm text-[#6b7280] mb-2">Distribution</label>
            <select
              value={filters.distribution || ''}
              onChange={(e) => handleFilterChange('distribution', e.target.value)}
              className="w-full px-3 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] focus:outline-none focus:border-[#4ade80]"
            >
              <option value="">All</option>
              {availableDistributions.map(d => (
                <option key={d} value={d}>{d}</option>
              ))}
            </select>
          </div>

          {/* Version */}
          <div>
            <label className="block text-sm text-[#6b7280] mb-2">Version</label>
            <select
              value={filters.version || ''}
              onChange={(e) => handleFilterChange('version', e.target.value)}
              className="w-full px-3 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] focus:outline-none focus:border-[#4ade80]"
            >
              <option value="">All</option>
              {availableVersions.map(v => (
                <option key={v} value={v}>{v}</option>
              ))}
            </select>
          </div>

          {/* Codename */}
          <div>
            <label className="block text-sm text-[#6b7280] mb-2">Codename</label>
            <select
              value={filters.codename || ''}
              onChange={(e) => handleFilterChange('codename', e.target.value)}
              className="w-full px-3 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] focus:outline-none focus:border-[#4ade80]"
            >
              <option value="">All</option>
              {availableCodenames.map(c => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
          </div>

          {/* Severity */}
          <div>
            <label className="block text-sm text-[#6b7280] mb-2">Severity</label>
            <select
              value={filters.severity || ''}
              onChange={(e) => handleFilterChange('severity', e.target.value)}
              className="w-full px-3 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] focus:outline-none focus:border-[#4ade80]"
            >
              <option value="">All</option>
              {availableSeverities.map(s => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>

          {/* Source (USN / CVE) */}
          <div>
            <label className="block text-sm text-[#6b7280] mb-2">Source</label>
            <select
              value={filters.sourceType || ''}
              onChange={(e) => handleFilterChange('sourceType', e.target.value)}
              className="w-full px-3 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] focus:outline-none focus:border-[#4ade80]"
            >
              <option value="">All</option>
              <option value="usn">USN</option>
              <option value="cve">CVE</option>
            </select>
          </div>

          {/* Package */}
          <div>
            <label className="block text-sm text-[#6b7280] mb-2">Affected Package</label>
            <input
              type="text"
              placeholder="openssl, kernel..."
              value={filters.package || ''}
              onChange={(e) => handleFilterChange('package', e.target.value)}
              className="w-full px-3 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] placeholder-[#6b7280] focus:outline-none focus:border-[#4ade80]"
            />
          </div>

          {/* CVE ID */}
          <div>
            <label className="block text-sm text-[#6b7280] mb-2">CVE ID</label>
            <input
              type="text"
              placeholder="CVE-2024-..."
              value={filters.cveId || ''}
              onChange={(e) => handleFilterChange('cveId', e.target.value)}
              className="w-full px-3 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] placeholder-[#6b7280] focus:outline-none focus:border-[#4ade80]"
            />
          </div>

          {/* Has Exploit */}
          <div className="flex items-end">
            <label className="flex items-center gap-2 cursor-pointer py-2">
              <input
                type="checkbox"
                checked={filters.hasExploit ?? false}
                onChange={(e) => handleFilterChange('hasExploit', e.target.checked)}
                className="w-4 h-4 rounded bg-[#1a2420] border-[#2d3f36] text-[#4ade80] focus:ring-[#4ade80]"
              />
              <span className="text-sm text-[#e8f5e9]">Has known exploit</span>
            </label>
          </div>
        </div>
      </div>

      {/* Results */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-[#e8f5e9]">
            Definitions ({total.toLocaleString()})
          </h2>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-12">
            <div className="text-[#a5d6a7]">Loading definitions...</div>
          </div>
        ) : error ? (
          <div className="card border-red-600/50 bg-red-600/5">
            <p className="text-red-400">{error}</p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-[#2d3f36]">
                    <th 
                      className="table-header text-left py-3 px-4 cursor-pointer hover:bg-[#1a2420] select-none"
                      onClick={() => handleSort('cveId')}
                    >
                      <div className="flex items-center gap-1">
                        CVE IDs
                        {filters.sortBy === 'cveId' && (
                          filters.sortOrder === 'asc' ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />
                        )}
                      </div>
                    </th>
                    <th className="table-header text-left py-3 px-4">Distribution</th>
                    <th className="table-header text-left py-3 px-4">Version</th>
                    <th className="table-header text-left py-3 px-4">Source</th>
                    <th className="table-header text-left py-3 px-4">Title</th>
                    <th 
                      className="table-header text-left py-3 px-4 cursor-pointer hover:bg-[#1a2420] select-none"
                      onClick={() => handleSort('severity')}
                    >
                      <div className="flex items-center gap-1">
                        Severity
                        {filters.sortBy === 'severity' && (
                          filters.sortOrder === 'asc' ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />
                        )}
                      </div>
                    </th>
                    <th className="table-header text-left py-3 px-4">Affected Packages</th>
                  </tr>
                </thead>
                <tbody>
                  {definitions.map((def) => (
                    <tr 
                      key={def.id} 
                      className="table-row cursor-pointer hover:bg-[#1a2420]"
                      onClick={() => handleRowClick(def)}
                    >
                      <td className="py-3 px-4">
                        <div className="flex flex-wrap gap-1">
                          {(def.cveIds || []).slice(0, 5).map((cveId) => (
                            <span 
                              key={cveId}
                              className="px-2 py-1 bg-[#0d1512] rounded text-xs text-[#4ade80] font-mono border border-[#2d3f36]"
                            >
                              {cveId}
                            </span>
                          ))}
                          {def.cveIds && def.cveIds.length > 5 && (
                            <span className="px-2 py-1 text-xs text-[#6b7280]">
                              +{def.cveIds.length - 5}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-4 text-sm text-[#a5d6a7]">{def.distribution}</td>
                      <td className="py-3 px-4 text-sm text-[#6b7280]">
                        {def.version} {def.codename && `(${def.codename})`}
                      </td>
                      <td className="py-3 px-4">
                        {def.sourceType && (
                          <span className={`px-2 py-1 rounded text-xs font-medium ${
                            def.sourceType === 'usn' ? 'bg-amber-600/20 text-amber-400' : 'bg-sky-600/20 text-sky-400'
                          }`}>
                            {def.sourceType.toUpperCase()}
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-sm text-[#e8f5e9]">{def.title || '-'}</td>
                      <td className="py-3 px-4">
                        {def.severity && (
                          <span className={`px-2 py-1 rounded text-xs font-medium ${
                            def.severity === 'critical' ? 'bg-red-600/20 text-red-400' :
                            def.severity === 'high' ? 'bg-orange-600/20 text-orange-400' :
                            def.severity === 'medium' ? 'bg-yellow-600/20 text-yellow-400' :
                            'bg-blue-600/20 text-blue-400'
                          }`}>
                            {def.severity}
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex flex-wrap gap-1">
                          {(def.affectedPackages || []).slice(0, 5).map((pkg) => (
                            <span 
                              key={pkg}
                              className="px-2 py-1 bg-[#0d1512] rounded text-xs text-[#a5d6a7] font-mono border border-[#2d3f36]"
                            >
                              {pkg}
                            </span>
                          ))}
                          {def.affectedPackages && def.affectedPackages.length > 5 && (
                            <span className="px-2 py-1 text-xs text-[#6b7280]">
                              +{def.affectedPackages.length - 5}
                            </span>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                  {definitions.length === 0 && (
                    <tr>
                      <td colSpan={7} className="py-8 text-center text-[#6b7280]">
                        No definitions found
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
                  Showing {((currentPage - 1) * ITEMS_PER_PAGE) + 1} to {Math.min(currentPage * ITEMS_PER_PAGE, total)} of {total}
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
                    onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
                    disabled={currentPage === 1}
                    className="p-1 rounded bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36] disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <ChevronLeft className="w-5 h-5" />
                  </button>
                  <span className="px-3 py-1 text-[#e8f5e9]">
                    Page {currentPage} of {totalPages}
                  </span>
                  <button
                    onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
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
          </>
        )}
      </div>

      {/* Detail Modal */}
      {selectedDefinition && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" onClick={() => setSelectedDefinition(null)}>
          <div className="bg-[#0d1512] border border-[#2d3f36] rounded-lg max-w-4xl w-full max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <div className="sticky top-0 bg-[#0d1512] border-b border-[#2d3f36] p-6 flex items-center justify-between">
              <h2 className="text-xl font-bold text-[#e8f5e9]">OVAL Definition Details</h2>
              <button
                onClick={() => setSelectedDefinition(null)}
                className="text-[#6b7280] hover:text-[#e8f5e9]"
              >
                <X className="w-6 h-6" />
              </button>
            </div>
            
            {detailLoading ? (
              <div className="p-6 text-center text-[#a5d6a7]">Loading details...</div>
            ) : (
              <div className="p-6 space-y-6">
                {/* Basic Info */}
                <div>
                  <h3 className="text-lg font-semibold text-[#e8f5e9] mb-3">Basic Information</h3>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <div className="text-xs text-[#6b7280] uppercase tracking-wide mb-1">Distribution</div>
                      <div className="text-sm text-[#e8f5e9]">{selectedDefinition.distribution} {selectedDefinition.version} {selectedDefinition.codename && `(${selectedDefinition.codename})`}</div>
                    </div>
                    <div>
                      <div className="text-xs text-[#6b7280] uppercase tracking-wide mb-1">Source</div>
                      <div className="text-sm">
                        {selectedDefinition.sourceType ? (
                          <span className={`px-2 py-1 rounded text-xs font-medium ${
                            selectedDefinition.sourceType === 'usn' ? 'bg-amber-600/20 text-amber-400' : 'bg-sky-600/20 text-sky-400'
                          }`}>
                            {selectedDefinition.sourceType.toUpperCase()}
                          </span>
                        ) : (
                          <span className="text-[#6b7280]">-</span>
                        )}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-[#6b7280] uppercase tracking-wide mb-1">Severity</div>
                      <div className="text-sm text-[#e8f5e9]">{selectedDefinition.severity || '-'}</div>
                    </div>
                    <div>
                      <div className="text-xs text-[#6b7280] uppercase tracking-wide mb-1">OVAL ID</div>
                      <div className="text-sm text-[#e8f5e9] font-mono">{selectedDefinition.ovalId}</div>
                    </div>
                    <div>
                      <div className="text-xs text-[#6b7280] uppercase tracking-wide mb-1">Class</div>
                      <div className="text-sm text-[#e8f5e9]">{selectedDefinition.class}</div>
                    </div>
                  </div>
                </div>

                {/* Title */}
                <div>
                  <h3 className="text-lg font-semibold text-[#e8f5e9] mb-2">Title</h3>
                  <p className="text-[#a5d6a7]">{selectedDefinition.title || '-'}</p>
                </div>

                {/* Description */}
                <div>
                  <h3 className="text-lg font-semibold text-[#e8f5e9] mb-2">Description</h3>
                  <p className="text-[#a5d6a7] whitespace-pre-wrap">{selectedDefinition.description || '-'}</p>
                </div>

                {/* CVE IDs */}
                <div>
                  <h3 className="text-lg font-semibold text-[#e8f5e9] mb-2">CVE IDs</h3>
                  <div className="flex flex-wrap gap-2">
                    {(selectedDefinition.cveIds || []).map((cveId) => (
                      <span 
                        key={cveId}
                        className="px-3 py-1 bg-[#1a2420] rounded text-sm text-[#4ade80] font-mono border border-[#2d3f36]"
                      >
                        {cveId}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Known Exploits */}
                <div>
                  <h3 className="text-lg font-semibold text-[#e8f5e9] mb-2">Known Exploits</h3>
                  {selectedDefinition.hasExploit ? (
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium bg-red-600/20 text-red-400 border border-red-600/50">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        {selectedDefinition.exploitCount} exploit{selectedDefinition.exploitCount !== 1 ? 's' : ''} known
                        {selectedDefinition.verifiedExploit && (
                          <span className="text-[#fbbf24]"> (verified)</span>
                        )}
                      </span>
                      {(selectedDefinition.cveIds?.length ?? 0) > 0 && (
                        <a
                          href={`https://www.exploit-db.com/search?cve=${encodeURIComponent(selectedDefinition.cveIds![0])}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-[#4ade80] hover:underline text-xs"
                        >
                          <ExternalLink className="w-3.5 h-3.5" />
                          View on Exploit-DB
                        </a>
                      )}
                      {(selectedDefinition.exploitIds?.length ?? 0) > 0 && (
                        <span className="flex flex-wrap gap-1">
                          {selectedDefinition.exploitIds?.slice(0, 5).map((edbId) => (
                            <a
                              key={edbId}
                              href={`https://www.exploit-db.com/exploits/${edbId}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-[#6b7280] hover:text-[#4ade80] font-mono text-xs"
                            >
                              EDB-{edbId}
                            </a>
                          ))}
                          {(selectedDefinition.exploitIds?.length ?? 0) > 5 && (
                            <span className="text-[#6b7280] text-xs">+{selectedDefinition.exploitIds!.length - 5} more</span>
                          )}
                        </span>
                      )}
                    </div>
                  ) : (
                    <span className="text-[#6b7280]">No known exploits</span>
                  )}
                </div>

                {/* Affected Packages */}
                <div>
                  <h3 className="text-lg font-semibold text-[#e8f5e9] mb-2">Affected Packages</h3>
                  <div className="flex flex-wrap gap-2">
                    {(selectedDefinition.affectedPackages || []).length > 0 ? (
                      (selectedDefinition.affectedPackages || []).map((pkg) => (
                        <span 
                          key={pkg}
                          className="px-3 py-1 bg-[#1a2420] rounded text-sm text-[#a5d6a7] font-mono border border-[#2d3f36]"
                        >
                          {pkg}
                        </span>
                      ))
                    ) : (
                      // Check if this is a kernel test
                      selectedDefinition.tests && selectedDefinition.tests.some(
                        (test) => test.testType === 'uname_test' || test.testType === 'variable_test'
                      ) ? (
                        <span className="px-3 py-1 bg-[#1a2420] rounded text-sm text-[#a5d6a7] font-mono border border-[#2d3f36]">
                          Kernel
                        </span>
                      ) : (
                        <span className="text-sm text-[#6b7280] italic">No packages affected</span>
                      )
                    )}
                  </div>
                </div>

                {/* Tests */}
                {selectedDefinition.tests && selectedDefinition.tests.length > 0 && (
                  <div>
                    <h3 className="text-lg font-semibold text-[#e8f5e9] mb-2">OVAL Tests</h3>
                    <div className="space-y-3">
                      {selectedDefinition.tests.map((test) => (
                        <div key={test.id} className="bg-[#1a2420] rounded-lg p-4 border border-[#2d3f36]">
                          <div className="grid grid-cols-2 gap-4 mb-2">
                            <div>
                              <div className="text-xs text-[#6b7280] uppercase tracking-wide mb-1">
                                {(test.testType === 'uname_test' || test.testType === 'variable_test')
                                  ? 'Target'
                                  : `Package${test.packageNames && test.packageNames.length > 1 ? 's' : ''}`
                                }
                              </div>
                              <div className="text-sm text-[#e8f5e9] font-mono">
                                {(test.testType === 'uname_test' || test.testType === 'variable_test')
                                  ? 'Kernel'
                                  : (test.packageNames && test.packageNames.length > 0
                                      ? test.packageNames.join(', ')
                                      : test.packageName || '-'
                                    )
                                }
                              </div>
                            </div>
                            <div>
                              <div className="text-xs text-[#6b7280] uppercase tracking-wide mb-1">Version Condition</div>
                              <div className="text-sm text-[#e8f5e9]">
                                {test.evrOperation && test.evrValue 
                                  ? `${test.evrOperation} ${test.evrValue}`
                                  : '-'
                                }
                              </div>
                            </div>
                          </div>
                          {test.comment && (
                            <div className="text-sm text-[#a5d6a7] mt-2">{test.comment}</div>
                          )}
                          <div className="text-xs text-[#6b7280] font-mono mt-2">{test.ovalId}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
