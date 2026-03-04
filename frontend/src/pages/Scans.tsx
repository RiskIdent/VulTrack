import { useEffect, useState, useCallback, useRef } from 'react';
import { Search, ChevronLeft, ChevronRight, XCircle, RotateCcw, Clock, Play, CheckCircle, AlertTriangle, Loader2, X } from 'lucide-react';
import { getScans, getScanStats, cancelScan, retryScan } from '../api/client';
import type { ScanJob, ScanStats } from '../types';

const ITEMS_PER_PAGE = 25;
const AUTO_REFRESH_MS = 5000;

const statusConfig: Record<string, { label: string; classes: string; icon: React.ReactNode }> = {
  queued: {
    label: 'Queued',
    classes: 'bg-blue-600/20 text-blue-400 border-blue-600/50',
    icon: <Clock className="w-3.5 h-3.5" />,
  },
  running: {
    label: 'Running',
    classes: 'bg-yellow-600/20 text-yellow-400 border-yellow-600/50',
    icon: <Loader2 className="w-3.5 h-3.5 animate-spin" />,
  },
  completed: {
    label: 'Completed',
    classes: 'bg-green-600/20 text-green-400 border-green-600/50',
    icon: <CheckCircle className="w-3.5 h-3.5" />,
  },
  failed: {
    label: 'Failed',
    classes: 'bg-red-600/20 text-red-400 border-red-600/50',
    icon: <AlertTriangle className="w-3.5 h-3.5" />,
  },
  cancelled: {
    label: 'Cancelled',
    classes: 'bg-gray-600/20 text-gray-400 border-gray-600/50',
    icon: <XCircle className="w-3.5 h-3.5" />,
  },
};

const triggerLabels: Record<string, string> = {
  agent_report: 'Agent',
  manual: 'Manual',
  scheduled: 'Scheduled',
};

function formatDuration(ms: number | null | undefined): string {
  if (ms == null) return '-';
  if (ms < 1000) return `${ms}ms`;
  const secs = ms / 1000;
  if (secs < 60) return `${secs.toFixed(1)}s`;
  const mins = Math.floor(secs / 60);
  const remainSecs = Math.round(secs % 60);
  return `${mins}m ${remainSecs}s`;
}

function timeAgo(dateStr: string | null | undefined): string {
  if (!dateStr) return '-';
  const diff = Date.now() - new Date(dateStr).getTime();
  const secs = Math.floor(diff / 1000);
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export default function Scans() {
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [total, setTotal] = useState(0);
  const [stats, setStats] = useState<ScanStats | null>(null);
  const [loading, setLoading] = useState(true);

  // Filter state
  const [statusFilter, setStatusFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [currentPage, setCurrentPage] = useState(1);

  // Auto-refresh
  const [autoRefresh, setAutoRefresh] = useState(true);
  const refreshTimer = useRef<ReturnType<typeof setInterval>>();

  // Debounce search
  const debounceRef = useRef<ReturnType<typeof setTimeout>>();
  useEffect(() => {
    debounceRef.current = setTimeout(() => setDebouncedSearch(searchQuery), 300);
    return () => clearTimeout(debounceRef.current);
  }, [searchQuery]);

  // Reset page on filter change
  useEffect(() => {
    setCurrentPage(1);
  }, [debouncedSearch, statusFilter]);

  const fetchData = useCallback(async () => {
    try {
      const [jobsData, statsData] = await Promise.all([
        getScans({
          status: statusFilter || undefined,
          search: debouncedSearch || undefined,
          limit: ITEMS_PER_PAGE,
          offset: (currentPage - 1) * ITEMS_PER_PAGE,
        }),
        getScanStats(),
      ]);
      setJobs(jobsData.jobs || []);
      setTotal(jobsData.total ?? 0);
      setStats(statsData.stats);
    } catch {
      // silent fail on auto-refresh
    } finally {
      setLoading(false);
    }
  }, [statusFilter, debouncedSearch, currentPage]);

  // Initial + on-filter-change fetch
  useEffect(() => {
    setLoading(true);
    fetchData();
  }, [fetchData]);

  // Auto-refresh
  useEffect(() => {
    if (autoRefresh) {
      refreshTimer.current = setInterval(fetchData, AUTO_REFRESH_MS);
    }
    return () => {
      if (refreshTimer.current) clearInterval(refreshTimer.current);
    };
  }, [autoRefresh, fetchData]);

  const totalPages = Math.max(1, Math.ceil(total / ITEMS_PER_PAGE));

  async function handleCancel(jobId: string) {
    try {
      await cancelScan(jobId);
      fetchData();
    } catch { /* noop */ }
  }

  async function handleRetry(jobId: string) {
    try {
      await retryScan(jobId);
      fetchData();
    } catch { /* noop */ }
  }

  const hasActive = stats && (stats.queued > 0 || stats.running > 0);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[#e8f5e9]">Scans</h1>
          <p className="text-[#a5d6a7] mt-1">Vulnerability scan queue and history</p>
        </div>
        <label className="flex items-center gap-2 cursor-pointer select-none">
          <span className="text-sm text-[#a5d6a7]">Auto-refresh</span>
          <div
            onClick={() => setAutoRefresh(v => !v)}
            className={`relative w-10 h-5 rounded-full transition-colors ${autoRefresh ? 'bg-[#4ade80]' : 'bg-[#2d3f36]'}`}
          >
            <div className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform ${autoRefresh ? 'translate-x-5' : ''}`} />
          </div>
        </label>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="card">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-600/20">
                <Clock className="w-5 h-5 text-blue-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-[#e8f5e9]">{stats.queued}</p>
                <p className="text-sm text-[#a5d6a7]">Queued</p>
              </div>
            </div>
          </div>
          <div className="card">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-yellow-600/20">
                <Play className="w-5 h-5 text-yellow-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-[#e8f5e9]">{stats.running}</p>
                <p className="text-sm text-[#a5d6a7]">Running</p>
              </div>
            </div>
          </div>
          <div className="card">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-green-600/20">
                <CheckCircle className="w-5 h-5 text-green-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-[#e8f5e9]">{stats.completed}</p>
                <p className="text-sm text-[#a5d6a7]">Completed (24h)</p>
              </div>
            </div>
          </div>
          <div className="card">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-red-600/20">
                <AlertTriangle className="w-5 h-5 text-red-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-[#e8f5e9]">{stats.failed}</p>
                <p className="text-sm text-[#a5d6a7]">Failed (24h)</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-[#e8f5e9]">Filters</h2>
          {(statusFilter || searchQuery) && (
            <button
              onClick={() => { setStatusFilter(''); setSearchQuery(''); }}
              className="text-sm text-[#4ade80] hover:underline flex items-center gap-1"
            >
              <X className="w-4 h-4" />
              Clear all
            </button>
          )}
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm text-[#6b7280] mb-2">Status</label>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full px-3 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] focus:outline-none focus:border-[#4ade80]"
            >
              <option value="">All</option>
              <option value="queued">Queued</option>
              <option value="running">Running</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
              <option value="cancelled">Cancelled</option>
            </select>
          </div>
          <div>
            <label className="block text-sm text-[#6b7280] mb-2">Search</label>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#6b7280]" />
              <input
                type="text"
                placeholder="Search by server name or job ID..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] placeholder-[#6b7280] focus:outline-none focus:border-[#4ade80]"
              />
            </div>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-[#e8f5e9]">
            Scan Jobs
            {total > 0 && <span className="text-[#a5d6a7] font-normal ml-2 text-sm">({total})</span>}
          </h2>
          {hasActive && (
            <span className="flex items-center gap-2 text-xs text-yellow-400">
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
              Scans in progress
            </span>
          )}
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#2d3f36]">
                <th className="table-header text-left py-3 px-4">Server</th>
                <th className="table-header text-left py-3 px-4">Trigger</th>
                <th className="table-header text-left py-3 px-4">Status</th>
                <th className="table-header text-left py-3 px-4">Duration</th>
                <th className="table-header text-left py-3 px-4">Findings</th>
                <th className="table-header text-left py-3 px-4">Error</th>
                <th className="table-header text-left py-3 px-4">Started</th>
                <th className="table-header text-left py-3 px-4">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading && jobs.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-[#a5d6a7]">
                    Loading scans...
                  </td>
                </tr>
              ) : jobs.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-[#6b7280]">
                    No scan jobs found.
                  </td>
                </tr>
              ) : (
                jobs.map((job) => {
                  const cfg = statusConfig[job.status] || statusConfig.queued;
                  return (
                    <tr key={job.id} className="table-row">
                      <td className="py-3 px-4">
                        <span className="text-[#e8f5e9] font-medium">{job.serverName || `Server #${job.serverId}`}</span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="text-xs text-[#a5d6a7] bg-[#1a2420] px-2 py-1 rounded">
                          {triggerLabels[job.triggerType] || job.triggerType}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium border ${cfg.classes}`}>
                          {cfg.icon}
                          {cfg.label}
                          {job.retryCount > 0 && (
                            <span className="text-[10px] opacity-70">
                              (retry {job.retryCount}/{job.maxRetries})
                            </span>
                          )}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-sm text-[#a5d6a7]">
                        {formatDuration(job.durationMs)}
                      </td>
                      <td className="py-3 px-4">
                        {job.status === 'completed' ? (
                          <div className="text-sm">
                            <span className="text-[#e8f5e9]">{job.newFindings ?? 0}</span>
                            <span className="text-[#6b7280]"> new, </span>
                            <span className="text-green-400">{job.resolvedFindings ?? 0}</span>
                            <span className="text-[#6b7280]"> resolved</span>
                          </div>
                        ) : (
                          <span className="text-sm text-[#6b7280]">-</span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        {job.error ? (
                          <p className="text-xs text-red-400 max-w-xs truncate" title={job.error}>
                            {job.error}
                          </p>
                        ) : (
                          <span className="text-sm text-[#6b7280]">-</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-sm text-[#6b7280]">
                        {job.startedAt ? timeAgo(job.startedAt) : timeAgo(job.createdAt)}
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          {(job.status === 'queued' || job.status === 'running') && (
                            <button
                              onClick={() => handleCancel(job.id)}
                              className="p-1.5 rounded hover:bg-[#2d3f36] text-[#a5d6a7] hover:text-red-400 transition-colors"
                              title="Cancel Scan"
                            >
                              <XCircle className="w-4 h-4" />
                            </button>
                          )}
                          {(job.status === 'failed' || job.status === 'cancelled') && (
                            <button
                              onClick={() => handleRetry(job.id)}
                              className="p-1.5 rounded hover:bg-[#2d3f36] text-[#a5d6a7] hover:text-[#4ade80] transition-colors"
                              title="Retry Scan"
                            >
                              <RotateCcw className="w-4 h-4" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between mt-4 pt-4 border-t border-[#2d3f36]">
            <div className="text-sm text-[#6b7280]">
              Showing {((currentPage - 1) * ITEMS_PER_PAGE) + 1} to {Math.min(currentPage * ITEMS_PER_PAGE, total)} of {total} jobs
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
