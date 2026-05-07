import { useEffect, useState, useCallback, useRef, Fragment } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Search, ChevronUp, ChevronDown, ChevronLeft, ChevronRight, X, ExternalLink, AlertTriangle } from 'lucide-react';
import { CVSSBadge, VendorSeverityBadge, FixStateBadge, VEXBadge } from '../components/SeverityBadge';
import { getFindings, getFinding, getFindingsGrouped } from '../api/client';
import type { Finding, GroupedFinding } from '../types';

type SortField = 'cveId' | 'serverName' | 'packageName' | 'cvss3Score' | 'severity' | 'fixState' | 'fixedIn' | 'firstSeenAt';
type SortDirection = 'asc' | 'desc';

const ITEMS_PER_PAGE = 15;
const GROUP_BY_CVE_STORAGE_KEY = 'vultrack.findings.groupByCve';

// Sort fields that don't make sense in grouped mode (multi-value per group).
const GROUPED_DISABLED_SORT_FIELDS: SortField[] = ['packageName', 'fixState', 'fixedIn'];

export default function Findings() {
  const [searchParams] = useSearchParams();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [groups, setGroups] = useState<GroupedFinding[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters (server-side)
  const [severity, setSeverity] = useState('');
  const [minCvss, setMinCvss] = useState(0);
  const [includeResolved, setIncludeResolved] = useState(false);
  const [vexStatusFilter, setVexStatusFilter] = useState('');

  // View mode: group rows by (server, CVE) — default ON, persisted in localStorage.
  const [groupByCve, setGroupByCve] = useState<boolean>(() => {
    const stored = typeof window !== 'undefined' ? window.localStorage.getItem(GROUP_BY_CVE_STORAGE_KEY) : null;
    return stored === null ? true : stored === 'true';
  });
  // Expanded group keys ("serverId:cveId") — UI state only.
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());

  // Search (server-side with debounce)
  const [searchQuery, setSearchQuery] = useState(searchParams.get('search') || '');
  const [debouncedSearch, setDebouncedSearch] = useState(searchQuery);

  // Sorting (server-side)
  const [sortField, setSortField] = useState<SortField>('cvss3Score');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');

  // Pagination (server-side)
  const [currentPage, setCurrentPage] = useState(1);

  // Finding detail modal
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // Persist groupByCve toggle and reset paging when it flips.
  useEffect(() => {
    if (typeof window !== 'undefined') {
      window.localStorage.setItem(GROUP_BY_CVE_STORAGE_KEY, String(groupByCve));
    }
    setCurrentPage(1);
    setExpandedGroups(new Set());
    // If currently sorting by a package-level field while switching INTO grouped mode,
    // fall back to CVSS — those fields don't have a single value per group.
    if (groupByCve && GROUPED_DISABLED_SORT_FIELDS.includes(sortField)) {
      setSortField('cvss3Score');
      setSortDirection('desc');
    }
  }, [groupByCve]);  // eslint-disable-line react-hooks/exhaustive-deps

  // Debounce search input
  const debounceRef = useRef<ReturnType<typeof setTimeout>>();
  useEffect(() => {
    debounceRef.current = setTimeout(() => {
      setDebouncedSearch(searchQuery);
      setCurrentPage(1);
    }, 300);
    return () => clearTimeout(debounceRef.current);
  }, [searchQuery]);

  // Update search query when URL params change
  useEffect(() => {
    const urlSearch = searchParams.get('search');
    if (urlSearch) {
      setSearchQuery(urlSearch);
    }
  }, [searchParams]);

  // Reset page when filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [severity, minCvss, includeResolved, vexStatusFilter]);

  // Fetch findings from server
  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = {
        severity: severity || undefined,
        minCvss: minCvss || undefined,
        includeResolved,
        search: debouncedSearch || undefined,
        sortBy: sortField,
        sortOrder: sortDirection,
        limit: ITEMS_PER_PAGE,
        offset: (currentPage - 1) * ITEMS_PER_PAGE,
        vexStatus: vexStatusFilter || undefined,
      };
      if (groupByCve) {
        const data = await getFindingsGrouped(params);
        setGroups(data.groups || []);
        setFindings([]);
        setTotal(data.total);
      } else {
        const data = await getFindings(params);
        setFindings(data.findings || []);
        setGroups([]);
        setTotal(data.total);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load findings');
    } finally {
      setLoading(false);
    }
  }, [severity, minCvss, includeResolved, debouncedSearch, sortField, sortDirection, currentPage, vexStatusFilter, groupByCve]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const totalPages = Math.ceil(total / ITEMS_PER_PAGE);

  const handleSort = (field: SortField) => {
    if (groupByCve && GROUPED_DISABLED_SORT_FIELDS.includes(field)) {
      return; // package-level fields have no single value per group
    }
    if (sortField === field) {
      setSortDirection(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
    setCurrentPage(1);
  };

  const handleFindingClick = async (finding: Finding) => {
    setDetailLoading(true);
    setSelectedFinding(finding); // Show immediately with list data
    try {
      const full = await getFinding(finding.id);
      setSelectedFinding(full);
    } catch {
      // Keep the list-level data if detail fetch fails
    } finally {
      setDetailLoading(false);
    }
  };

  // Open the detail modal for a package row inside a group. We only have the
  // finding ID at this point; the GET /findings/:id endpoint enriches it fully.
  const handlePackageClick = async (findingId: number) => {
    setDetailLoading(true);
    setSelectedFinding({ id: findingId } as Finding); // placeholder
    try {
      const full = await getFinding(findingId);
      setSelectedFinding(full);
    } catch {
      setSelectedFinding(null);
    } finally {
      setDetailLoading(false);
    }
  };

  const toggleGroupExpansion = (key: string) => {
    setExpandedGroups(prev => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  };

  const SortHeader = ({ field, children, disabled }: { field: SortField; children: React.ReactNode; disabled?: boolean }) => {
    if (disabled) {
      return (
        <th className="table-header text-left py-3 px-4 select-none text-[#6b7280]">
          <div className="flex items-center gap-1">{children}</div>
        </th>
      );
    }
    return (
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
  };

  // Render a "fix state" cell for a group: show one badge if all packages share a state,
  // or a "mixed" indicator listing the distinct states.
  const renderGroupFixState = (group: GroupedFinding) => {
    if (group.fixStates.length === 0) {
      return <span className="text-[#6b7280]">-</span>;
    }
    if (group.fixStates.length === 1) {
      return <FixStateBadge fixState={group.fixStates[0]} />;
    }
    return (
      <div className="flex flex-col gap-1" title={group.fixStates.join(', ')}>
        <span className="px-2 py-0.5 rounded text-xs font-medium bg-amber-600/20 text-amber-400 inline-block w-fit">
          mixed
        </span>
        <span className="text-xs text-[#6b7280]">{group.fixStates.length} states</span>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[#e8f5e9]">Findings</h1>
          <p className="text-[#a5d6a7] mt-1">All vulnerability findings across your infrastructure</p>
        </div>
        
        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#6b7280]" />
          <input
            type="text"
            placeholder="Search findings..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10 pr-4 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] placeholder-[#6b7280] focus:outline-none focus:border-[#4ade80] w-64"
          />
        </div>
      </div>

      {/* Filters */}
      <div className="card">
        <div className="flex flex-wrap gap-4">
          <div>
            <label className="block text-sm text-[#a5d6a7] mb-1">Vendor Severity</label>
            <select
              className="input"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              <option value="">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
          <div>
            <label className="block text-sm text-[#a5d6a7] mb-1">Min CVSS</label>
            <input
              type="number"
              className="input w-24"
              min="0"
              max="10"
              step="0.1"
              value={minCvss}
              onChange={(e) => setMinCvss(parseFloat(e.target.value) || 0)}
            />
          </div>
          <div>
            <label className="block text-sm text-[#a5d6a7] mb-1">VEX Status</label>
            <select
              className="input"
              value={vexStatusFilter}
              onChange={(e) => setVexStatusFilter(e.target.value)}
            >
              <option value="">All</option>
              <option value="not_affected">Not Affected</option>
              <option value="will_not_fix">Will Not Fix</option>
              <option value="under_investigation">Under Investigation</option>
            </select>
          </div>
          <div className="flex items-end">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                className="w-4 h-4 rounded border-[#2d3f36] bg-[#0a0f0d] text-[#4ade80] focus:ring-[#4ade80]"
                checked={includeResolved}
                onChange={(e) => setIncludeResolved(e.target.checked)}
              />
              <span className="text-sm text-[#a5d6a7]">Include resolved</span>
            </label>
          </div>
          <div className="flex items-end ml-auto">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                className="w-4 h-4 rounded border-[#2d3f36] bg-[#0a0f0d] text-[#4ade80] focus:ring-[#4ade80]"
                checked={groupByCve}
                onChange={(e) => setGroupByCve(e.target.checked)}
              />
              <span className="text-sm text-[#a5d6a7]">Group by CVE</span>
            </label>
          </div>
        </div>
      </div>

      {/* Results */}
      {error ? (
        <div className="card border-red-600/50 bg-red-600/5">
          <p className="text-red-400">{error}</p>
        </div>
      ) : loading ? (
        <div className="flex items-center justify-center h-64">
          <div className="text-[#a5d6a7]">Loading findings...</div>
        </div>
      ) : (
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-[#e8f5e9]">
              Results ({total})
            </h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#2d3f36]">
                  {groupByCve && <th className="w-8 py-3 px-2"></th>}
                  <SortHeader field="cveId">CVE ID</SortHeader>
                  <SortHeader field="serverName">Server</SortHeader>
                  <SortHeader field="packageName" disabled={groupByCve}>
                    {groupByCve ? 'Packages' : 'Package'}
                  </SortHeader>
                  {!groupByCve && <th className="table-header text-left py-3 px-4">Version</th>}
                  <SortHeader field="fixedIn" disabled={groupByCve}>Fixed In</SortHeader>
                  <SortHeader field="fixState" disabled={groupByCve}>Fix State</SortHeader>
                  <SortHeader field="cvss3Score">CVSS</SortHeader>
                  <SortHeader field="severity">Vendor</SortHeader>
                  <th className="table-header text-left py-3 px-4">Status</th>
                </tr>
              </thead>
              <tbody>
                {!groupByCve && findings.map((finding) => (
                  <tr
                    key={finding.id}
                    className="table-row cursor-pointer hover:bg-[#1a2420]"
                    onClick={() => handleFindingClick(finding)}
                  >
                    <td className="py-3 px-4 font-mono text-[#4ade80]">
                      {finding.cveId}
                    </td>
                    <td className="py-3 px-4">
                      <Link
                        to={`/servers/${finding.serverId}`}
                        className="text-[#4ade80] hover:underline"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {finding.serverName}
                      </Link>
                    </td>
                    <td className="py-3 px-4 font-mono text-sm text-[#a5d6a7]">
                      {finding.packageName}
                    </td>
                    <td className="py-3 px-4 font-mono text-xs text-[#6b7280]">
                      {finding.packageVersion || '-'}
                    </td>
                    <td className="py-3 px-4 font-mono text-xs text-[#4ade80]">
                      {finding.fixedIn || '-'}
                    </td>
                    <td className="py-3 px-4">
                      <FixStateBadge fixState={finding.fixState} />
                    </td>
                    <td className="py-3 px-4">
                      <CVSSBadge score={finding.nvdCvss3Score ?? finding.cvss3Score} cveId={finding.cveId} />
                    </td>
                    <td className="py-3 px-4">
                      <VendorSeverityBadge severity={finding.severity} sourceLink={finding.sourceLink} />
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex flex-wrap gap-1">
                        {finding.resolvedAt ? (
                          <span className="px-2 py-1 rounded text-xs font-medium bg-green-600/20 text-green-400">
                            Resolved
                          </span>
                        ) : (
                          <span className="px-2 py-1 rounded text-xs font-medium bg-red-600/20 text-red-400">
                            Active
                          </span>
                        )}
                        <VEXBadge status={finding.vexStatus} justification={finding.vexJustification} />
                      </div>
                    </td>
                  </tr>
                ))}
                {groupByCve && groups.map((group) => {
                  const groupKey = `${group.serverId}:${group.cveId}`;
                  const isExpanded = expandedGroups.has(groupKey);
                  const sharedVexStatus = group.vexStatuses.length === 1 ? group.vexStatuses[0] : null;
                  return (
                    <Fragment key={groupKey}>
                      <tr
                        className="table-row cursor-pointer hover:bg-[#1a2420]"
                        onClick={() => toggleGroupExpansion(groupKey)}
                      >
                        <td className="py-3 px-2 text-[#6b7280]">
                          {isExpanded
                            ? <ChevronDown className="w-4 h-4" />
                            : <ChevronRight className="w-4 h-4" />}
                        </td>
                        <td className="py-3 px-4 font-mono text-[#4ade80]">
                          {group.cveId}
                        </td>
                        <td className="py-3 px-4">
                          <Link
                            to={`/servers/${group.serverId}`}
                            className="text-[#4ade80] hover:underline"
                            onClick={(e) => e.stopPropagation()}
                          >
                            {group.serverName}
                          </Link>
                        </td>
                        <td className="py-3 px-4 text-sm text-[#a5d6a7]">
                          {group.packageCount} package{group.packageCount !== 1 ? 's' : ''}
                          {group.activeCount !== group.packageCount && (
                            <span className="text-xs text-[#6b7280] ml-1">
                              ({group.activeCount} active)
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-xs text-[#6b7280]">—</td>
                        <td className="py-3 px-4">{renderGroupFixState(group)}</td>
                        <td className="py-3 px-4">
                          <CVSSBadge score={group.nvdCvss3Score ?? group.cvss3Score} cveId={group.cveId} />
                        </td>
                        <td className="py-3 px-4">
                          <VendorSeverityBadge severity={group.severity} sourceLink={group.sourceLink} />
                        </td>
                        <td className="py-3 px-4">
                          <div className="flex flex-wrap gap-1">
                            {group.allResolved ? (
                              <span className="px-2 py-1 rounded text-xs font-medium bg-green-600/20 text-green-400">
                                Resolved
                              </span>
                            ) : (
                              <span className="px-2 py-1 rounded text-xs font-medium bg-red-600/20 text-red-400">
                                Active
                              </span>
                            )}
                            {sharedVexStatus && <VEXBadge status={sharedVexStatus} />}
                            {group.vexStatuses.length > 1 && (
                              <span className="px-2 py-1 rounded text-xs font-medium bg-amber-600/20 text-amber-400" title={group.vexStatuses.join(', ')}>
                                VEX: mixed
                              </span>
                            )}
                          </div>
                        </td>
                      </tr>
                      {isExpanded && group.packages.map((pkg) => (
                        <tr
                          key={pkg.id}
                          className="bg-[#0a0f0d] hover:bg-[#1a2420] cursor-pointer border-b border-[#1a2420]"
                          onClick={() => handlePackageClick(pkg.id)}
                        >
                          {/* 9 cells, matching the grouped-mode header (no "Version" column).
                              Package name + version share one cell under the "Packages" header. */}
                          <td></td>
                          <td className="py-2 px-4"></td>
                          <td className="py-2 px-4"></td>
                          <td className="py-2 px-4 font-mono text-sm text-[#a5d6a7] pl-8">
                            <span className="text-[#6b7280]">↳ </span>{pkg.name}
                            {pkg.version && (
                              <span className="text-xs text-[#6b7280] ml-2">{pkg.version}</span>
                            )}
                          </td>
                          <td className="py-2 px-4 font-mono text-xs text-[#4ade80]">
                            {pkg.fixedIn || '-'}
                          </td>
                          <td className="py-2 px-4">
                            <FixStateBadge fixState={pkg.fixState} />
                          </td>
                          <td className="py-2 px-4"></td>
                          <td className="py-2 px-4"></td>
                          <td className="py-2 px-4">
                            <div className="flex flex-wrap gap-1">
                              {pkg.resolvedAt ? (
                                <span className="px-2 py-0.5 rounded text-xs font-medium bg-green-600/20 text-green-400">
                                  Resolved
                                </span>
                              ) : (
                                <span className="px-2 py-0.5 rounded text-xs font-medium bg-red-600/20 text-red-400">
                                  Active
                                </span>
                              )}
                              <VEXBadge status={pkg.vexStatus} justification={pkg.vexJustification} />
                            </div>
                          </td>
                        </tr>
                      ))}
                    </Fragment>
                  );
                })}
                {((groupByCve && groups.length === 0) || (!groupByCve && findings.length === 0)) && (
                  <tr>
                    <td colSpan={groupByCve ? 10 : 9} className="py-8 text-center text-[#6b7280]">
                      {debouncedSearch ? 'No findings match your search' : 'No findings match your filters'}
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
                Showing {((currentPage - 1) * ITEMS_PER_PAGE) + 1} to {Math.min(currentPage * ITEMS_PER_PAGE, total)} of {total} findings
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
      )}

      {/* Finding Detail Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" onClick={() => setSelectedFinding(null)}>
          <div className="bg-[#0d1512] border border-[#2d3f36] rounded-lg max-w-4xl w-full max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <div className="sticky top-0 bg-[#0d1512] border-b border-[#2d3f36] p-6 flex items-center justify-between">
              <h2 className="text-xl font-bold text-[#e8f5e9]">Finding Details</h2>
              <button
                onClick={() => setSelectedFinding(null)}
                className="text-[#6b7280] hover:text-[#e8f5e9]"
              >
                <X className="w-6 h-6" />
              </button>
            </div>
            <div className="p-6 space-y-6">
              {detailLoading && (
                <div className="text-sm text-[#6b7280]">Loading details...</div>
              )}

              {/* Basic Info */}
              <div>
                <h3 className="text-lg font-semibold text-[#e8f5e9] mb-3">Basic Information</h3>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <div className="text-xs text-[#6b7280] uppercase tracking-wide mb-1">CVE ID</div>
                    <div className="text-sm text-[#4ade80] font-mono">{selectedFinding.cveId}</div>
                  </div>
                  <div>
                    <div className="text-xs text-[#6b7280] uppercase tracking-wide mb-1">Server</div>
                    <div className="text-sm">
                      <Link
                        to={`/servers/${selectedFinding.serverId}`}
                        className="text-[#4ade80] hover:underline"
                        onClick={() => setSelectedFinding(null)}
                      >
                        {selectedFinding.serverName}
                      </Link>
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-[#6b7280] uppercase tracking-wide mb-1">Source</div>
                    <div className="text-sm">
                      {selectedFinding.sourceType ? (
                        <span className={`px-2 py-1 rounded text-xs font-medium ${
                          selectedFinding.sourceType === 'usn' ? 'bg-amber-600/20 text-amber-400' : 'bg-sky-600/20 text-sky-400'
                        }`}>
                          {selectedFinding.sourceType.toUpperCase()}
                        </span>
                      ) : (
                        <span className="text-[#6b7280]">-</span>
                      )}
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-[#6b7280] uppercase tracking-wide mb-1">Status</div>
                    <div className="text-sm">
                      {selectedFinding.resolvedAt ? (
                        <span className="px-2 py-1 rounded text-xs font-medium bg-green-600/20 text-green-400">Resolved</span>
                      ) : (
                        <span className="px-2 py-1 rounded text-xs font-medium bg-red-600/20 text-red-400">Active</span>
                      )}
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-[#6b7280] uppercase tracking-wide mb-1">Package</div>
                    <div className="text-sm text-[#e8f5e9] font-mono">{selectedFinding.packageName}</div>
                  </div>
                  <div>
                    <div className="text-xs text-[#6b7280] uppercase tracking-wide mb-1">Installed Version</div>
                    <div className="text-sm text-[#e8f5e9] font-mono">{selectedFinding.packageVersion || '-'}</div>
                  </div>
                  <div>
                    <div className="text-xs text-[#6b7280] uppercase tracking-wide mb-1">Fixed In</div>
                    <div className="text-sm text-[#4ade80] font-mono">{selectedFinding.fixedIn || '-'}</div>
                  </div>
                  <div>
                    <div className="text-xs text-[#6b7280] uppercase tracking-wide mb-1">Fix State</div>
                    <div className="text-sm"><FixStateBadge fixState={selectedFinding.fixState} /></div>
                  </div>
                  <div>
                    <div className="text-xs text-[#6b7280] uppercase tracking-wide mb-1">Vendor Severity</div>
                    <div className="text-sm">
                      <VendorSeverityBadge severity={selectedFinding.severity} sourceLink={selectedFinding.sourceLink || undefined} />
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-[#6b7280] uppercase tracking-wide mb-1">CVSS 3</div>
                    <div className="text-sm">
                      <CVSSBadge score={selectedFinding.nvdCvss3Score ?? selectedFinding.cvss3Score} cveId={selectedFinding.cveId} />
                    </div>
                  </div>
                  <div className="col-span-2">
                    <div className="text-xs text-[#6b7280] uppercase tracking-wide mb-1">Known Exploits</div>
                    <div className="text-sm">
                      {selectedFinding.hasExploit ? (
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium bg-red-600/20 text-red-400 border border-red-600/50">
                            <AlertTriangle className="w-3.5 h-3.5" />
                            {selectedFinding.exploitCount} exploit{selectedFinding.exploitCount !== 1 ? 's' : ''} known
                            {selectedFinding.verifiedExploit && (
                              <span className="text-[#fbbf24]"> (verified)</span>
                            )}
                          </span>
                          <a
                            href={`https://www.exploit-db.com/search?cve=${encodeURIComponent(selectedFinding.cveId)}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 text-[#4ade80] hover:underline text-xs"
                          >
                            <ExternalLink className="w-3.5 h-3.5" />
                            View on Exploit-DB
                          </a>
                          {(selectedFinding.exploitIds?.length ?? 0) > 0 && (
                            <span className="flex flex-wrap gap-1">
                              {selectedFinding.exploitIds?.slice(0, 5).map((edbId) => (
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
                              {(selectedFinding.exploitIds?.length ?? 0) > 5 && (
                                <span className="text-[#6b7280] text-xs">+{selectedFinding.exploitIds!.length - 5} more</span>
                              )}
                            </span>
                          )}
                        </div>
                      ) : (
                        <span className="text-[#6b7280]">No known exploits</span>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              {/* VEX Status */}
              {selectedFinding.vexStatus && (
                <div>
                  <h3 className="text-lg font-semibold text-[#e8f5e9] mb-3">Ubuntu VEX Assessment</h3>
                  <div className="space-y-2">
                    <div className="flex items-center gap-3">
                      <VEXBadge status={selectedFinding.vexStatus} />
                    </div>
                    {selectedFinding.vexJustification && (
                      <p className="text-sm text-[#a5d6a7] mt-2">{selectedFinding.vexJustification}</p>
                    )}
                  </div>
                </div>
              )}

              {/* Description (OVAL preferred, NVD fallback) */}
              {(selectedFinding.description || selectedFinding.nvdDescription || selectedFinding.summary) && (
                <div>
                  <h3 className="text-lg font-semibold text-[#e8f5e9] mb-2">Description</h3>
                  <p className="text-[#a5d6a7] whitespace-pre-wrap">{selectedFinding.description || selectedFinding.nvdDescription || selectedFinding.summary}</p>
                </div>
              )}

              {/* Source Link */}
              {selectedFinding.sourceLink && (
                <div>
                  <h3 className="text-lg font-semibold text-[#e8f5e9] mb-2">Source</h3>
                  <a
                    href={selectedFinding.sourceLink}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[#4ade80] hover:underline font-mono text-sm break-all"
                  >
                    {selectedFinding.sourceLink}
                  </a>
                </div>
              )}

              {/* Timestamps */}
              <div>
                <h3 className="text-lg font-semibold text-[#e8f5e9] mb-3">Timeline</h3>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <div className="text-xs text-[#6b7280] uppercase tracking-wide mb-1">First Seen</div>
                    <div className="text-sm text-[#e8f5e9]">{new Date(selectedFinding.firstSeenAt).toLocaleString()}</div>
                  </div>
                  <div>
                    <div className="text-xs text-[#6b7280] uppercase tracking-wide mb-1">Last Seen</div>
                    <div className="text-sm text-[#e8f5e9]">{new Date(selectedFinding.lastSeenAt).toLocaleString()}</div>
                  </div>
                  {selectedFinding.resolvedAt && (
                    <div>
                      <div className="text-xs text-[#6b7280] uppercase tracking-wide mb-1">Resolved</div>
                      <div className="text-sm text-[#e8f5e9]">{new Date(selectedFinding.resolvedAt).toLocaleString()}</div>
                    </div>
                  )}
                  {selectedFinding.cvePublishedAt && (
                    <div>
                      <div className="text-xs text-[#6b7280] uppercase tracking-wide mb-1">CVE Published</div>
                      <div className="text-sm text-[#e8f5e9]">{new Date(selectedFinding.cvePublishedAt).toLocaleString()}</div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
