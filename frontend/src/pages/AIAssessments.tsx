import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Search, ExternalLink, Eye, X, ChevronLeft, ChevronRight, RefreshCw,
  Clock, CheckCircle2, AlertCircle, Loader2,
} from 'lucide-react';
import { getAIAssessments, requestAIAssessment } from '../api/client';
import { AIAssessmentContent, RecommendedStatusBadge, ConfidenceBadge } from '../components/AIAssessmentCard';
import type { AIAssessment, AIAssessmentStatus } from '../types';

const ITEMS_PER_PAGE = 15;
// How often the table silently refreshes so assessment statuses stay current.
const REFRESH_INTERVAL_MS = 5000;

const statusLabels: Record<AIAssessmentStatus, string> = {
  pending: 'Pending',
  processing: 'In progress',
  completed: 'Completed',
  failed: 'Failed',
};

const statusClasses: Record<AIAssessmentStatus, string> = {
  pending: 'bg-[#1a2420] text-[#a5d6a7] border-[#2d3f36]',
  processing: 'bg-blue-600/20 text-blue-400 border-blue-600/50',
  completed: 'bg-green-600/20 text-green-400 border-green-600/50',
  failed: 'bg-red-600/20 text-red-400 border-red-600/50',
};

function StatusBadge({ status }: { status: AIAssessmentStatus }) {
  const icon =
    status === 'completed' ? <CheckCircle2 className="w-3.5 h-3.5" /> :
    status === 'failed' ? <AlertCircle className="w-3.5 h-3.5" /> :
    status === 'processing' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> :
    <Clock className="w-3.5 h-3.5" />;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium border ${statusClasses[status]}`}>
      {icon}
      {statusLabels[status]}
    </span>
  );
}

export default function AIAssessments() {
  const [assessments, setAssessments] = useState<AIAssessment[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [currentPage, setCurrentPage] = useState(1);

  const [selected, setSelected] = useState<AIAssessment | null>(null);
  const [requesting, setRequesting] = useState(false);

  const debounceRef = useRef<ReturnType<typeof setTimeout>>();
  useEffect(() => {
    debounceRef.current = setTimeout(() => setDebouncedSearch(searchQuery), 300);
    return () => clearTimeout(debounceRef.current);
  }, [searchQuery]);

  useEffect(() => {
    setCurrentPage(1);
  }, [debouncedSearch, statusFilter]);

  const params = useMemo(() => ({
    search: debouncedSearch || undefined,
    status: statusFilter || undefined,
    limit: ITEMS_PER_PAGE,
    offset: (currentPage - 1) * ITEMS_PER_PAGE,
  }), [debouncedSearch, statusFilter, currentPage]);

  // silent=true is used by the auto-refresh so it doesn't flash the loading
  // state or clobber the view with a transient polling error.
  const fetchData = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const data = await getAIAssessments(params);
      setAssessments(data.assessments || []);
      setTotal(data.total ?? 0);
      if (silent) setError(null);
    } catch (err) {
      if (!silent) setError(err instanceof Error ? err.message : 'Failed to load AI assessments');
    } finally {
      if (!silent) setLoading(false);
    }
  }, [params]);

  // Initial load and reload on filter/page change.
  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Auto-refresh the current view so pending/processing assessments update to
  // their final status (and newly queued ones appear) without a manual reload.
  useEffect(() => {
    const id = setInterval(() => fetchData(true), REFRESH_INTERVAL_MS);
    return () => clearInterval(id);
  }, [fetchData]);

  const totalPages = Math.max(1, Math.ceil(total / ITEMS_PER_PAGE));

  async function handleRequestNew(cveId: string) {
    setRequesting(true);
    setError(null);
    try {
      await requestAIAssessment(cveId, true);
      setSelected(null);
      await fetchData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to request AI assessment');
    } finally {
      setRequesting(false);
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-[#e8f5e9]">AI Assessments</h1>
        <p className="text-[#a5d6a7] mt-1">
          {total} CVE{total !== 1 ? 's' : ''} assessed by AI
        </p>
      </div>

      {error && (
        <div className="card border-red-600/50 bg-red-600/5">
          <p className="text-red-400">{error}</p>
        </div>
      )}

      {/* Search + filter */}
      <div className="card">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="md:col-span-3 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-[#6b7280]" />
            <input
              type="text"
              placeholder="Search by CVE ID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-3 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] placeholder-[#6b7280] focus:outline-none focus:border-[#4ade80]"
            />
          </div>
          <div>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full px-3 py-3 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] focus:outline-none focus:border-[#4ade80]"
            >
              <option value="">All statuses</option>
              <option value="pending">Pending</option>
              <option value="processing">In progress</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
            </select>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="card">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#2d3f36]">
                <th className="table-header text-left py-3 px-4">CVE ID</th>
                <th className="table-header text-left py-3 px-4">Status</th>
                <th className="table-header text-left py-3 px-4">Recommended Status</th>
                <th className="table-header text-left py-3 px-4">Confidence</th>
                <th className="table-header text-left py-3 px-4">Model</th>
                <th className="table-header text-left py-3 px-4">Updated</th>
                <th className="table-header text-right py-3 px-4">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-[#a5d6a7]">Loading AI assessments...</td>
                </tr>
              ) : assessments.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-[#6b7280]">No AI assessments match your criteria.</td>
                </tr>
              ) : (
                assessments.map((a) => (
                  <tr key={a.id} className="table-row">
                    <td className="py-3 px-4">
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${a.cveId}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-mono text-[#4ade80] hover:underline flex items-center gap-1"
                      >
                        {a.cveId}
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    </td>
                    <td className="py-3 px-4"><StatusBadge status={a.status} /></td>
                    <td className="py-3 px-4">
                      {a.recommendedStatus ? <RecommendedStatusBadge status={a.recommendedStatus} /> : <span className="text-[#6b7280]">-</span>}
                    </td>
                    <td className="py-3 px-4">
                      {a.confidence ? <ConfidenceBadge confidence={a.confidence} /> : <span className="text-[#6b7280]">-</span>}
                    </td>
                    <td className="py-3 px-4 text-[#a5d6a7] text-sm">{a.model || '-'}</td>
                    <td className="py-3 px-4 text-sm text-[#6b7280]">
                      {a.updatedAt ? new Date(a.updatedAt).toLocaleDateString() : '-'}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => setSelected(a)}
                        className="p-1.5 rounded hover:bg-[#2d3f36] text-[#a5d6a7] hover:text-[#4ade80] transition-colors"
                        title="View details"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
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
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                disabled={currentPage === 1}
                className="p-1 rounded bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36] disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ChevronLeft className="w-5 h-5" />
              </button>
              <span className="px-3 py-1 text-[#e8f5e9]">Page {currentPage} of {totalPages}</span>
              <button
                onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
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

      {/* Detail modal */}
      {selected && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
          <div className="bg-[#111916] border border-[#2d3f36] rounded-xl p-6 w-full max-w-2xl mx-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-start justify-between mb-4">
              <h2 className="text-xl font-bold text-[#e8f5e9] font-mono">{selected.cveId}</h2>
              <button
                onClick={() => setSelected(null)}
                className="p-1 text-[#6b7280] hover:text-[#a5d6a7]"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="mb-4"><StatusBadge status={selected.status} /></div>

            {selected.status === 'completed' ? (
              <AIAssessmentContent assessment={selected} />
            ) : selected.status === 'failed' ? (
              <div className="text-[#a5d6a7]">
                <p className="text-red-400 mb-1">The AI assessment failed.</p>
                {selected.error && <p className="text-xs text-[#6b7280] break-words">{selected.error}</p>}
              </div>
            ) : (
              <p className="text-[#a5d6a7]">Assessment in progress…</p>
            )}

            <div className="flex justify-end gap-3 mt-6">
              <button
                onClick={() => setSelected(null)}
                className="btn bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36]"
              >
                Close
              </button>
              <button
                onClick={() => handleRequestNew(selected.cveId)}
                disabled={requesting || selected.status === 'pending' || selected.status === 'processing'}
                className="btn btn-primary flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <RefreshCw className={`w-4 h-4 ${requesting ? 'animate-spin' : ''}`} />
                Request new assessment
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
