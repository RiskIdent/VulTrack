import { useEffect, useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { Server as ServerIcon, Search, ChevronUp, ChevronDown, ChevronLeft, ChevronRight } from 'lucide-react';
import { getServers } from '../api/client';
import type { Server } from '../types';

type SortField = 'name' | 'osFamily' | 'findingsCount' | 'criticalCount' | 'highCount' | 'lastScanAt';
type SortDirection = 'asc' | 'desc';

const ITEMS_PER_PAGE = 25;

export default function Servers() {
  const [servers, setServers] = useState<Server[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // Filtering, sorting, pagination
  const [searchQuery, setSearchQuery] = useState('');
  const [sortField, setSortField] = useState<SortField>('criticalCount');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');
  const [currentPage, setCurrentPage] = useState(1);

  useEffect(() => {
    async function fetchData() {
      try {
        const data = await getServers();
        setServers(data.servers || []);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load servers');
      } finally {
        setLoading(false);
      }
    }
    fetchData();
  }, []);

  // Reset page when search changes
  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery]);

  // Filter servers by search query
  const filteredServers = useMemo(() => {
    if (!searchQuery.trim()) return servers;
    const query = searchQuery.toLowerCase();
    return servers.filter(s => 
      s.name.toLowerCase().includes(query) ||
      s.osFamily?.toLowerCase().includes(query) ||
      s.osRelease?.toLowerCase().includes(query) ||
      s.ipv4Addrs?.some(ip => ip.includes(query))
    );
  }, [servers, searchQuery]);

  // Sort servers
  const sortedServers = useMemo(() => {
    const sorted = [...filteredServers].sort((a, b) => {
      let aVal: string | number | null = null;
      let bVal: string | number | null = null;

      switch (sortField) {
        case 'name':
          aVal = a.name;
          bVal = b.name;
          break;
        case 'osFamily':
          aVal = `${a.osFamily || ''} ${a.osRelease || ''}`;
          bVal = `${b.osFamily || ''} ${b.osRelease || ''}`;
          break;
        case 'findingsCount':
          aVal = a.findingsCount ?? 0;
          bVal = b.findingsCount ?? 0;
          break;
        case 'criticalCount':
          aVal = a.criticalCount ?? 0;
          bVal = b.criticalCount ?? 0;
          break;
        case 'highCount':
          aVal = a.highCount ?? 0;
          bVal = b.highCount ?? 0;
          break;
        case 'lastScanAt':
          aVal = a.lastScanAt ? new Date(a.lastScanAt).getTime() : 0;
          bVal = b.lastScanAt ? new Date(b.lastScanAt).getTime() : 0;
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
  }, [filteredServers, sortField, sortDirection]);

  // Pagination
  const totalPages = Math.ceil(sortedServers.length / ITEMS_PER_PAGE);
  const paginatedServers = useMemo(() => {
    const start = (currentPage - 1) * ITEMS_PER_PAGE;
    return sortedServers.slice(start, start + ITEMS_PER_PAGE);
  }, [sortedServers, currentPage]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  const SortHeader = ({ field, children, className }: { field: SortField; children: React.ReactNode; className?: string }) => (
    <th 
      className={`table-header text-left py-3 px-4 cursor-pointer hover:bg-[#1a2420] select-none ${className || ''}`}
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
        <div className="text-[#a5d6a7]">Loading servers...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card border-red-600/50 bg-red-600/5">
        <p className="text-red-400">{error}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[#e8f5e9]">Servers</h1>
          <p className="text-[#a5d6a7] mt-1">
            {filteredServers.length}{filteredServers.length !== servers.length ? ` of ${servers.length}` : ''} servers
          </p>
        </div>
        
        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#6b7280]" />
          <input
            type="text"
            placeholder="Search servers..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10 pr-4 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] placeholder-[#6b7280] focus:outline-none focus:border-[#4ade80] w-64"
          />
        </div>
      </div>

      {/* Info Banner */}
      <div className="flex items-center gap-2 px-4 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-sm text-[#a5d6a7]">
        <span className="text-[#6b7280]">ℹ</span>
        Critical and High counts are based on vendor severity ratings, not CVSS scores.
      </div>

      {/* Server Table */}
      <div className="card">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#2d3f36]">
                <SortHeader field="name">Server Name</SortHeader>
                <SortHeader field="osFamily">Operating System</SortHeader>
                <th className="table-header text-left py-3 px-4">IP Address</th>
                <SortHeader field="findingsCount">Findings</SortHeader>
                <SortHeader field="criticalCount">Critical</SortHeader>
                <SortHeader field="highCount">High</SortHeader>
                <SortHeader field="lastScanAt">Last Scan</SortHeader>
              </tr>
            </thead>
            <tbody>
              {paginatedServers.map((server) => (
                <tr key={server.id} className="table-row">
                  <td className="py-3 px-4">
                    <Link 
                      to={`/servers/${server.id}`}
                      className="flex items-center gap-2 text-[#4ade80] hover:underline font-medium"
                    >
                      <ServerIcon className="w-4 h-4" />
                      {server.name}
                    </Link>
                  </td>
                  <td className="py-3 px-4 text-[#a5d6a7]">
                    {server.osFamily} {server.osRelease}
                  </td>
                  <td className="py-3 px-4 font-mono text-xs text-[#6b7280]">
                    {server.ipv4Addrs?.[0] || '-'}
                  </td>
                  <td className="py-3 px-4">
                    <span className="text-[#e8f5e9] font-medium">
                      {server.findingsCount ?? 0}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    {(server.criticalCount ?? 0) > 0 ? (
                      <span className="px-2 py-1 rounded text-xs font-bold bg-red-600/20 text-red-400">
                        {server.criticalCount}
                      </span>
                    ) : (
                      <span className="text-[#6b7280]">0</span>
                    )}
                  </td>
                  <td className="py-3 px-4">
                    {(server.highCount ?? 0) > 0 ? (
                      <span className="px-2 py-1 rounded text-xs font-bold bg-orange-600/20 text-orange-400">
                        {server.highCount}
                      </span>
                    ) : (
                      <span className="text-[#6b7280]">0</span>
                    )}
                  </td>
                  <td className="py-3 px-4 text-sm text-[#6b7280]">
                    {server.lastScanAt 
                      ? new Date(server.lastScanAt).toLocaleString()
                      : '-'
                    }
                  </td>
                </tr>
              ))}
              {paginatedServers.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-[#6b7280]">
                    {searchQuery ? 'No servers match your search' : 'No servers found. Import scan results to see your servers here.'}
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
              Showing {((currentPage - 1) * ITEMS_PER_PAGE) + 1} to {Math.min(currentPage * ITEMS_PER_PAGE, sortedServers.length)} of {sortedServers.length} servers
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
