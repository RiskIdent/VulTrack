import { useEffect, useState, useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, Server as ServerIcon, Search, ChevronUp, ChevronDown, ChevronLeft, ChevronRight, Tags, Package, RefreshCw, X, ExternalLink, AlertTriangle } from 'lucide-react';
import { CVSSBadge, VendorSeverityBadge, FixStateBadge } from '../components/SeverityBadge';
import { getServer, getServerFindings, getServerGroupsForServer, getServerPackages, triggerServerScan, getFinding } from '../api/client';
import type { Server, Finding, ServerGroup, ServerPackage } from '../types';

type Tab = 'findings' | 'packages';
type FindingSortField = 'cveId' | 'packageName' | 'severity' | 'cvss3Score' | 'fixState' | 'fixedIn' | 'firstSeenAt';
type PackageSortField = 'name' | 'version' | 'arch' | 'sourcePackage';
type SortDirection = 'asc' | 'desc';

const ITEMS_PER_PAGE = 15;

export default function ServerDetail() {
  const { id } = useParams<{ id: string }>();
  const [server, setServer] = useState<Server | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [packages, setPackages] = useState<ServerPackage[]>([]);
  const [groups, setGroups] = useState<ServerGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [packagesLoading, setPackagesLoading] = useState(false);
  const [packagesLoaded, setPackagesLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  // Tab state
  const [activeTab, setActiveTab] = useState<Tab>('findings');
  
  // Findings filtering, sorting, pagination
  const [findingsSearch, setFindingsSearch] = useState('');
  const [findingsSortField, setFindingsSortField] = useState<FindingSortField>('cvss3Score');
  const [findingsSortDirection, setFindingsSortDirection] = useState<SortDirection>('desc');
  const [findingsPage, setFindingsPage] = useState(1);

  // Packages filtering, sorting, pagination
  const [packagesSearch, setPackagesSearch] = useState('');
  const [packagesSortField, setPackagesSortField] = useState<PackageSortField>('name');
  const [packagesSortDirection, setPackagesSortDirection] = useState<SortDirection>('asc');
  const [packagesPage, setPackagesPage] = useState(1);

  // Rescan state
  const [rescanning, setRescanning] = useState(false);
  const [rescanMessage, setRescanMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Finding detail modal
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const handleFindingClick = async (finding: Finding) => {
    setSelectedFinding(finding); // Show immediately with list data
    setDetailLoading(true);
    try {
      const full = await getFinding(finding.id);
      setSelectedFinding(full);
    } catch {
      // Keep the list-level data if detail fetch fails
    } finally {
      setDetailLoading(false);
    }
  };

  // Load server, findings, and groups on mount
  useEffect(() => {
    async function fetchData() {
      if (!id) return;
      try {
        const [serverData, findingsData, groupsData] = await Promise.all([
          getServer(parseInt(id)),
          getServerFindings(parseInt(id), { limit: 10000 }),
          getServerGroupsForServer(parseInt(id)),
        ]);
        setServer(serverData);
        setFindings(findingsData.findings || []);
        setGroups(groupsData.groups || []);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load server');
      } finally {
        setLoading(false);
      }
    }
    fetchData();
  }, [id]);

  // Load packages lazily when tab is switched
  useEffect(() => {
    async function fetchPackages() {
      if (!id || packagesLoaded || activeTab !== 'packages') return;
      setPackagesLoading(true);
      try {
        const data = await getServerPackages(parseInt(id));
        setPackages(data.packages || []);
        setPackagesLoaded(true);
      } catch (err) {
        console.error('Failed to load packages:', err);
      } finally {
        setPackagesLoading(false);
      }
    }
    fetchPackages();
  }, [id, activeTab, packagesLoaded]);

  // Reset page when search changes
  useEffect(() => { setFindingsPage(1); }, [findingsSearch]);
  useEffect(() => { setPackagesPage(1); }, [packagesSearch]);

  async function handleRescan() {
    if (!id || !server) return;
    setRescanMessage(null);
    setRescanning(true);
    try {
      await triggerServerScan(parseInt(id));
      setRescanMessage({ type: 'success', text: 'Rescan started. The scan runs in the background. Refresh or revisit this page to see updated results.' });
      // Refetch server and findings after a delay (scan is async)
      setTimeout(async () => {
        try {
          const [serverData, findingsData] = await Promise.all([
            getServer(parseInt(id)),
            getServerFindings(parseInt(id), { limit: 10000 }),
          ]);
          setServer(serverData);
          setFindings(findingsData.findings || []);
        } catch {
          // ignore
        }
      }, 3000);
    } catch (err) {
      setRescanMessage({ type: 'error', text: err instanceof Error ? err.message : 'Failed to trigger rescan' });
    } finally {
      setRescanning(false);
    }
  }

  // Filter and sort findings
  const filteredFindings = useMemo(() => {
    if (!findingsSearch.trim()) return findings;
    const query = findingsSearch.toLowerCase();
    return findings.filter(f => 
      f.cveId.toLowerCase().includes(query) ||
      f.packageName.toLowerCase().includes(query) ||
      f.packageVersion?.toLowerCase().includes(query) ||
      f.severity?.toLowerCase().includes(query) ||
      f.fixState?.toLowerCase().includes(query) ||
      f.fixedIn?.toLowerCase().includes(query)
    );
  }, [findings, findingsSearch]);

  const sortedFindings = useMemo(() => {
    const sorted = [...filteredFindings].sort((a, b) => {
      let aVal: string | number | null = null;
      let bVal: string | number | null = null;

      switch (findingsSortField) {
        case 'cveId': aVal = a.cveId; bVal = b.cveId; break;
        case 'packageName': aVal = a.packageName; bVal = b.packageName; break;
        case 'severity': aVal = a.severity || ''; bVal = b.severity || ''; break;
        case 'cvss3Score': aVal = a.nvdCvss3Score ?? a.cvss3Score ?? 0; bVal = b.nvdCvss3Score ?? b.cvss3Score ?? 0; break;
        case 'fixState': aVal = a.fixState || ''; bVal = b.fixState || ''; break;
        case 'fixedIn': aVal = a.fixedIn || ''; bVal = b.fixedIn || ''; break;
        case 'firstSeenAt': aVal = new Date(a.firstSeenAt).getTime(); bVal = new Date(b.firstSeenAt).getTime(); break;
      }

      if (aVal === null && bVal === null) return 0;
      if (aVal === null) return 1;
      if (bVal === null) return -1;

      if (typeof aVal === 'string' && typeof bVal === 'string') {
        return findingsSortDirection === 'asc' ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
      }
      return findingsSortDirection === 'asc' ? (aVal as number) - (bVal as number) : (bVal as number) - (aVal as number);
    });
    return sorted;
  }, [filteredFindings, findingsSortField, findingsSortDirection]);

  const findingsTotalPages = Math.ceil(sortedFindings.length / ITEMS_PER_PAGE);
  const paginatedFindings = useMemo(() => {
    const start = (findingsPage - 1) * ITEMS_PER_PAGE;
    return sortedFindings.slice(start, start + ITEMS_PER_PAGE);
  }, [sortedFindings, findingsPage]);

  // Filter and sort packages
  const filteredPackages = useMemo(() => {
    if (!packagesSearch.trim()) return packages;
    const query = packagesSearch.toLowerCase();
    return packages.filter(p => 
      p.name.toLowerCase().includes(query) ||
      p.version.toLowerCase().includes(query) ||
      p.arch.toLowerCase().includes(query) ||
      p.sourcePackage.toLowerCase().includes(query)
    );
  }, [packages, packagesSearch]);

  const sortedPackages = useMemo(() => {
    const sorted = [...filteredPackages].sort((a, b) => {
      let aVal: string = '';
      let bVal: string = '';

      switch (packagesSortField) {
        case 'name': aVal = a.name; bVal = b.name; break;
        case 'version': aVal = a.version; bVal = b.version; break;
        case 'arch': aVal = a.arch; bVal = b.arch; break;
        case 'sourcePackage': aVal = a.sourcePackage; bVal = b.sourcePackage; break;
      }

      return packagesSortDirection === 'asc' ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
    });
    return sorted;
  }, [filteredPackages, packagesSortField, packagesSortDirection]);

  const packagesTotalPages = Math.ceil(sortedPackages.length / ITEMS_PER_PAGE);
  const paginatedPackages = useMemo(() => {
    const start = (packagesPage - 1) * ITEMS_PER_PAGE;
    return sortedPackages.slice(start, start + ITEMS_PER_PAGE);
  }, [sortedPackages, packagesPage]);

  // Sort handlers
  const handleFindingsSort = (field: FindingSortField) => {
    if (findingsSortField === field) {
      setFindingsSortDirection(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setFindingsSortField(field);
      setFindingsSortDirection('desc');
    }
  };

  const handlePackagesSort = (field: PackageSortField) => {
    if (packagesSortField === field) {
      setPackagesSortDirection(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setPackagesSortField(field);
      setPackagesSortDirection('asc');
    }
  };

  // Sort header components
  const FindingsSortHeader = ({ field, children }: { field: FindingSortField; children: React.ReactNode }) => (
    <th 
      className="table-header text-left py-3 px-4 cursor-pointer hover:bg-[#1a2420] select-none"
      onClick={() => handleFindingsSort(field)}
    >
      <div className="flex items-center gap-1">
        {children}
        {findingsSortField === field && (
          findingsSortDirection === 'asc' ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />
        )}
      </div>
    </th>
  );

  const PackagesSortHeader = ({ field, children }: { field: PackageSortField; children: React.ReactNode }) => (
    <th 
      className="table-header text-left py-3 px-4 cursor-pointer hover:bg-[#1a2420] select-none"
      onClick={() => handlePackagesSort(field)}
    >
      <div className="flex items-center gap-1">
        {children}
        {packagesSortField === field && (
          packagesSortDirection === 'asc' ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />
        )}
      </div>
    </th>
  );

  // Pagination component
  const Pagination = ({ 
    currentPage, 
    totalPages, 
    totalItems, 
    onPageChange 
  }: { 
    currentPage: number; 
    totalPages: number; 
    totalItems: number;
    onPageChange: (page: number) => void;
  }) => {
    if (totalPages <= 1) return null;
    return (
      <div className="flex items-center justify-between mt-4 pt-4 border-t border-[#2d3f36]">
        <div className="text-sm text-[#6b7280]">
          Showing {((currentPage - 1) * ITEMS_PER_PAGE) + 1} to {Math.min(currentPage * ITEMS_PER_PAGE, totalItems)} of {totalItems}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => onPageChange(1)}
            disabled={currentPage === 1}
            className="px-3 py-1 rounded bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36] disabled:opacity-50 disabled:cursor-not-allowed"
          >
            First
          </button>
          <button
            onClick={() => onPageChange(Math.max(1, currentPage - 1))}
            disabled={currentPage === 1}
            className="p-1 rounded bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36] disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <ChevronLeft className="w-5 h-5" />
          </button>
          <span className="px-3 py-1 text-[#e8f5e9]">
            Page {currentPage} of {totalPages}
          </span>
          <button
            onClick={() => onPageChange(Math.min(totalPages, currentPage + 1))}
            disabled={currentPage === totalPages}
            className="p-1 rounded bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36] disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <ChevronRight className="w-5 h-5" />
          </button>
          <button
            onClick={() => onPageChange(totalPages)}
            disabled={currentPage === totalPages}
            className="px-3 py-1 rounded bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36] disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Last
          </button>
        </div>
      </div>
    );
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-[#a5d6a7]">Loading server details...</div>
      </div>
    );
  }

  if (error || !server) {
    return (
      <div className="space-y-4">
        <Link to="/servers" className="inline-flex items-center gap-2 text-[#4ade80] hover:underline">
          <ArrowLeft className="w-4 h-4" />
          Back to servers
        </Link>
        <div className="card border-red-600/50 bg-red-600/5">
          <p className="text-red-400">{error || 'Server not found'}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Back button */}
      <Link to="/servers" className="inline-flex items-center gap-2 text-[#4ade80] hover:underline">
        <ArrowLeft className="w-4 h-4" />
        Back to servers
      </Link>

      {/* Server Info */}
      <div className="card">
        {rescanMessage && (
          <div className={`mb-4 p-3 rounded-lg text-sm ${rescanMessage.type === 'success' ? 'bg-[#4ade80]/10 text-[#4ade80] border border-[#4ade80]/30' : 'bg-red-600/10 text-red-400 border border-red-600/30'}`}>
            {rescanMessage.text}
            <button type="button" onClick={() => setRescanMessage(null)} className="ml-2 underline opacity-80 hover:opacity-100">Dismiss</button>
          </div>
        )}
        <div className="flex items-start gap-4">
          <div className="w-16 h-16 bg-[#1a2420] rounded-lg flex items-center justify-center flex-shrink-0">
            <ServerIcon className="w-8 h-8 text-[#4ade80]" />
          </div>
          <div className="flex-1">
            <h1 className="text-2xl font-bold text-[#e8f5e9]">{server.name}</h1>
            <p className="text-[#a5d6a7]">
              {server.osFamily} {server.osRelease}
              {server.osCodename && ` (${server.osCodename})`}
            </p>
            
            {/* System Details */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4 p-3 bg-[#1a2420] rounded-lg">
              <div>
                <div className="text-xs text-[#6b7280] uppercase tracking-wide">Architecture</div>
                <div className="text-sm text-[#e8f5e9] font-mono">{server.arch || '-'}</div>
              </div>
              <div>
                <div className="text-xs text-[#6b7280] uppercase tracking-wide">Kernel</div>
                <div className="text-sm text-[#e8f5e9] font-mono">{server.kernel || '-'}</div>
              </div>
              <div>
                <div className="text-xs text-[#6b7280] uppercase tracking-wide">Package Manager</div>
                <div className="text-sm text-[#e8f5e9] font-mono">{server.packageManager || '-'}</div>
              </div>
              <div>
                <div className="text-xs text-[#6b7280] uppercase tracking-wide">Last Scan</div>
                <div className="text-sm text-[#e8f5e9]">
                  {server.lastScanAt ? new Date(server.lastScanAt).toLocaleString() : 'Never'}
                </div>
              </div>
            </div>

            {/* IP Addresses */}
            {server.ipv4Addrs && server.ipv4Addrs.length > 0 && (
              <div className="mt-3">
                <div className="text-xs text-[#6b7280] uppercase tracking-wide mb-1">IP Addresses</div>
                <div className="flex flex-wrap gap-2">
                  {server.ipv4Addrs.map((ip) => (
                    <span key={ip} className="px-2 py-1 bg-[#0d1512] rounded text-xs text-[#a5d6a7] font-mono border border-[#2d3f36]">
                      {ip}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Server Groups */}
            {groups.length > 0 && (
              <div className="flex items-center gap-2 mt-3">
                <Tags className="w-4 h-4 text-[#6b7280]" />
                <div className="flex flex-wrap gap-2">
                  {groups.map((group) => (
                    <span
                      key={group.id}
                      className="px-2 py-1 rounded text-xs font-medium"
                      style={{
                        backgroundColor: `${group.color}20`,
                        color: group.color,
                        border: `1px solid ${group.color}50`,
                      }}
                    >
                      {group.name}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
          <div className="flex flex-col items-end gap-3">
            <button
              type="button"
              onClick={handleRescan}
              disabled={rescanning}
              className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36] hover:text-[#e8f5e9] border border-[#2d3f36] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              title="Run vulnerability scan now"
            >
              <RefreshCw className={`w-4 h-4 ${rescanning ? 'animate-spin' : ''}`} />
              {rescanning ? 'Scanning…' : 'Rescan'}
            </button>
            <div className="flex gap-4">
              <div className="text-center">
                <div className="text-3xl font-bold text-[#e8f5e9]">{server.findingsCount ?? 0}</div>
                <div className="text-sm text-[#6b7280]">Findings</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold text-red-400">{server.criticalCount ?? 0}</div>
                <div className="text-sm text-[#6b7280]">Critical</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold text-orange-400">{server.highCount ?? 0}</div>
                <div className="text-sm text-[#6b7280]">High</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-2">
        <button
          onClick={() => setActiveTab('findings')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-colors ${
            activeTab === 'findings'
              ? 'bg-[#4ade80] text-[#0d1512]'
              : 'bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36]'
          }`}
        >
          <Search className="w-4 h-4" />
          Findings ({findings.length})
        </button>
        <button
          onClick={() => setActiveTab('packages')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-colors ${
            activeTab === 'packages'
              ? 'bg-[#4ade80] text-[#0d1512]'
              : 'bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36]'
          }`}
        >
          <Package className="w-4 h-4" />
          Packages {packagesLoaded ? `(${packages.length})` : ''}
        </button>
      </div>

      {/* Findings Tab */}
      {activeTab === 'findings' && (
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-[#e8f5e9]">
              Findings ({filteredFindings.length}{filteredFindings.length !== findings.length ? ` of ${findings.length}` : ''})
            </h2>
            
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#6b7280]" />
              <input
                type="text"
                placeholder="Search findings..."
                value={findingsSearch}
                onChange={(e) => setFindingsSearch(e.target.value)}
                className="pl-10 pr-4 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] placeholder-[#6b7280] focus:outline-none focus:border-[#4ade80] w-64"
              />
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#2d3f36]">
                  <FindingsSortHeader field="cveId">CVE ID</FindingsSortHeader>
                  <FindingsSortHeader field="packageName">Package</FindingsSortHeader>
                  <th className="table-header text-left py-3 px-4">Version</th>
                  <FindingsSortHeader field="fixedIn">Fixed In</FindingsSortHeader>
                  <FindingsSortHeader field="fixState">Fix State</FindingsSortHeader>
                  <th className="table-header text-left py-3 px-4">Source</th>
                  <FindingsSortHeader field="cvss3Score">CVSS</FindingsSortHeader>
                  <FindingsSortHeader field="severity">Vendor</FindingsSortHeader>
                  <FindingsSortHeader field="firstSeenAt">First Seen</FindingsSortHeader>
                </tr>
              </thead>
              <tbody>
                {paginatedFindings.map((finding) => (
                  <tr
                    key={finding.id}
                    className="table-row cursor-pointer hover:bg-[#1a2420]"
                    onClick={() => handleFindingClick(finding)}
                  >
                    <td className="py-3 px-4 font-mono text-[#4ade80]">{finding.cveId}</td>
                    <td className="py-3 px-4 font-mono text-sm text-[#a5d6a7]">{finding.packageName}</td>
                    <td className="py-3 px-4 font-mono text-xs text-[#6b7280]">{finding.packageVersion || '-'}</td>
                    <td className="py-3 px-4 font-mono text-xs text-[#4ade80]">{finding.fixedIn || '-'}</td>
                    <td className="py-3 px-4">
                      <FixStateBadge fixState={finding.fixState} />
                    </td>
                    <td className="py-3 px-4">
                      {finding.sourceType ? (
                        <span className={`px-2 py-1 rounded text-xs font-medium ${
                          finding.sourceType === 'usn' ? 'bg-amber-600/20 text-amber-400' : 'bg-sky-600/20 text-sky-400'
                        }`}>
                          {finding.sourceType.toUpperCase()}
                        </span>
                      ) : (
                        <span className="text-[#6b7280]">-</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <CVSSBadge score={finding.nvdCvss3Score ?? finding.cvss3Score} cveId={finding.cveId} />
                    </td>
                    <td className="py-3 px-4">
                      <VendorSeverityBadge severity={finding.severity} sourceLink={finding.sourceLink || undefined} />
                    </td>
                    <td className="py-3 px-4 text-sm text-[#6b7280]">
                      {new Date(finding.firstSeenAt).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
                {paginatedFindings.length === 0 && (
                  <tr>
                    <td colSpan={10} className="py-8 text-center text-[#6b7280]">
                      {findingsSearch ? 'No findings match your search' : 'No findings for this server'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          <Pagination
            currentPage={findingsPage}
            totalPages={findingsTotalPages}
            totalItems={sortedFindings.length}
            onPageChange={setFindingsPage}
          />
        </div>
      )}

      {/* Packages Tab */}
      {activeTab === 'packages' && (
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-[#e8f5e9]">
              Installed Packages ({filteredPackages.length}{filteredPackages.length !== packages.length ? ` of ${packages.length}` : ''})
            </h2>
            
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#6b7280]" />
              <input
                type="text"
                placeholder="Search packages..."
                value={packagesSearch}
                onChange={(e) => setPackagesSearch(e.target.value)}
                className="pl-10 pr-4 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] placeholder-[#6b7280] focus:outline-none focus:border-[#4ade80] w-64"
              />
            </div>
          </div>

          {packagesLoading ? (
            <div className="flex items-center justify-center py-12">
              <div className="text-[#a5d6a7]">Loading packages...</div>
            </div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-[#2d3f36]">
                      <PackagesSortHeader field="name">Package</PackagesSortHeader>
                      <PackagesSortHeader field="version">Version</PackagesSortHeader>
                      <PackagesSortHeader field="arch">Architecture</PackagesSortHeader>
                      <PackagesSortHeader field="sourcePackage">Source Package</PackagesSortHeader>
                    </tr>
                  </thead>
                  <tbody>
                    {paginatedPackages.map((pkg) => (
                      <tr key={pkg.id} className="table-row">
                        <td className="py-3 px-4 font-mono text-[#4ade80]">{pkg.name}</td>
                        <td className="py-3 px-4 font-mono text-sm text-[#a5d6a7]">{pkg.version}</td>
                        <td className="py-3 px-4 text-sm text-[#6b7280]">{pkg.arch || '-'}</td>
                        <td className="py-3 px-4 font-mono text-sm text-[#6b7280]">{pkg.sourcePackage || '-'}</td>
                      </tr>
                    ))}
                    {paginatedPackages.length === 0 && (
                      <tr>
                        <td colSpan={4} className="py-8 text-center text-[#6b7280]">
                          {packagesSearch ? 'No packages match your search' : 'No packages found'}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              <Pagination
                currentPage={packagesPage}
                totalPages={packagesTotalPages}
                totalItems={sortedPackages.length}
                onPageChange={setPackagesPage}
              />
            </>
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
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
