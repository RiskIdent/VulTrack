import { useEffect, useState, useCallback, useRef, useMemo } from 'react';
import { Search, ChevronUp, ChevronDown, ChevronLeft, ChevronRight, RotateCcw, Edit2, ExternalLink, CheckCircle, XCircle, AlertTriangle, X, Wrench, Activity } from 'lucide-react';
import { CVSSBadge, VendorSeverityBadge } from '../components/SeverityBadge';
import { getAssessments, updateAssessment, deleteAssessment, getReasonTemplates } from '../api/client';
import { useAuth } from '../context/AuthContext';
import type { AssessmentFilterParams } from '../api/client';
import type { Assessment, ReasonTemplate, AssessmentStatus } from '../types';

type SortField = 'cveId' | 'status' | 'cvss3Score' | 'severity' | 'assessedAt' | 'affectedServers';
type SortDirection = 'asc' | 'desc';

const ITEMS_PER_PAGE = 25;

const statusIcons: Record<string, React.ReactNode> = {
  relevant: <AlertTriangle className="w-4 h-4 text-red-400" />,
  not_relevant: <XCircle className="w-4 h-4 text-green-400" />,
  accepted_risk: <CheckCircle className="w-4 h-4 text-yellow-400" />,
};

const statusLabels: Record<string, string> = {
  relevant: 'Relevant',
  not_relevant: 'Not Relevant',
  accepted_risk: 'Accepted Risk',
};

const statusClasses: Record<string, string> = {
  relevant: 'bg-red-600/20 text-red-400 border-red-600/50',
  not_relevant: 'bg-green-600/20 text-green-400 border-green-600/50',
  accepted_risk: 'bg-yellow-600/20 text-yellow-400 border-yellow-600/50',
};

export default function Assessments() {
  const { user } = useAuth();
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Server-side filter state
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [minCvss, setMinCvss] = useState('');
  const [findingActiveFilter, setFindingActiveFilter] = useState('');
  const [hasFixFilter, setHasFixFilter] = useState('');

  // Server-side sort / pagination
  const [sortField, setSortField] = useState<SortField>('assessedAt');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');
  const [currentPage, setCurrentPage] = useState(1);

  // Edit modal state
  const [showEditModal, setShowEditModal] = useState(false);
  const [editingAssessment, setEditingAssessment] = useState<Assessment | null>(null);
  const [editStatus, setEditStatus] = useState<AssessmentStatus>('pending');
  const [editComment, setEditComment] = useState('');
  const [editTicketUrl, setEditTicketUrl] = useState('');
  const [selectedReason, setSelectedReason] = useState('');
  const [reasonTemplates, setReasonTemplates] = useState<ReasonTemplate[]>([]);
  const [saving, setSaving] = useState(false);

  // Reset confirmation modal
  const [showResetModal, setShowResetModal] = useState(false);
  const [resettingAssessment, setResettingAssessment] = useState<Assessment | null>(null);

  // Debounce search input
  const debounceRef = useRef<ReturnType<typeof setTimeout>>();
  useEffect(() => {
    debounceRef.current = setTimeout(() => setDebouncedSearch(searchQuery), 300);
    return () => clearTimeout(debounceRef.current);
  }, [searchQuery]);

  // Reset page when any filter changes
  useEffect(() => {
    setCurrentPage(1);
  }, [debouncedSearch, statusFilter, severityFilter, minCvss, findingActiveFilter, hasFixFilter]);

  // Build API params
  const apiParams: AssessmentFilterParams = useMemo(() => ({
    search: debouncedSearch || undefined,
    status: statusFilter || undefined,
    severity: severityFilter || undefined,
    minCvss: minCvss || undefined,
    findingActive: findingActiveFilter || undefined,
    hasFixAvailable: hasFixFilter || undefined,
    sortBy: sortField,
    sortOrder: sortDirection,
    limit: ITEMS_PER_PAGE,
    offset: (currentPage - 1) * ITEMS_PER_PAGE,
  }), [debouncedSearch, statusFilter, severityFilter, minCvss, findingActiveFilter, hasFixFilter, sortField, sortDirection, currentPage]);

  const fetchAssessments = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getAssessments(apiParams);
      setAssessments(data.assessments || []);
      setTotal(data.total ?? 0);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load assessments');
    } finally {
      setLoading(false);
    }
  }, [apiParams]);

  // Load templates once
  useEffect(() => {
    getReasonTemplates()
      .then(d => setReasonTemplates(d.templates || []))
      .catch(() => {});
  }, []);

  // Fetch assessments on any param change
  useEffect(() => {
    fetchAssessments();
  }, [fetchAssessments]);

  const totalPages = Math.max(1, Math.ceil(total / ITEMS_PER_PAGE));

  function handleSort(field: SortField) {
    if (sortField === field) {
      setSortDirection(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  }

  function SortHeader({ field, children }: { field: SortField; children: React.ReactNode }) {
    return (
      <th
        className="table-header text-left py-3 px-4 cursor-pointer hover:bg-[#1a2420] select-none"
        onClick={() => handleSort(field)}
      >
        <div className="flex items-center gap-1">
          {children}
          {sortField === field && (
            sortDirection === 'asc' ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />
          )}
        </div>
      </th>
    );
  }

  function openEditModal(assessment: Assessment) {
    setEditingAssessment(assessment);
    setEditStatus(assessment.status as AssessmentStatus);
    setEditComment(assessment.comment || '');
    setEditTicketUrl(assessment.ticketUrl || '');
    setSelectedReason('');
    setShowEditModal(true);
  }

  async function handleSaveEdit() {
    if (!editingAssessment) return;

    const finalComment = selectedReason || editComment;

    setSaving(true);
    try {
      await updateAssessment(editingAssessment.cveId, {
        status: editStatus,
        comment: finalComment,
        ticketUrl: editTicketUrl,
        assessedBy: user?.name || user?.email || 'anonymous',
      });
      await fetchAssessments();
      setShowEditModal(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update assessment');
    } finally {
      setSaving(false);
    }
  }

  function openResetModal(assessment: Assessment) {
    setResettingAssessment(assessment);
    setShowResetModal(true);
  }

  async function handleReset() {
    if (!resettingAssessment) return;

    setSaving(true);
    try {
      await deleteAssessment(resettingAssessment.cveId);
      await fetchAssessments();
      setShowResetModal(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to reset assessment');
    } finally {
      setSaving(false);
    }
  }

  const filteredTemplates = reasonTemplates.filter(t =>
    t.isActive && (t.appliesTo === editStatus || t.appliesTo === 'both')
  );

  const activeFilterCount = [statusFilter, severityFilter, minCvss, findingActiveFilter, hasFixFilter].filter(Boolean).length;

  function clearAllFilters() {
    setSearchQuery('');
    setStatusFilter('');
    setSeverityFilter('');
    setMinCvss('');
    setFindingActiveFilter('');
    setHasFixFilter('');
  }

  if (error && !showEditModal && !showResetModal && !assessments.length) {
    return (
      <div className="card border-red-600/50 bg-red-600/5">
        <p className="text-red-400">{error}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-[#e8f5e9]">Assessments</h1>
        <p className="text-[#a5d6a7] mt-1">
          {total} CVE{total !== 1 ? 's' : ''} assessed
        </p>
      </div>

      {/* Search */}
      <div className="card">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-[#6b7280]" />
          <input
            type="text"
            placeholder="Search by CVE ID, comment, or assessor..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-3 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] placeholder-[#6b7280] focus:outline-none focus:border-[#4ade80]"
          />
        </div>
      </div>

      {/* Filters */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-[#e8f5e9]">Filters</h2>
          {activeFilterCount > 0 && (
            <button
              onClick={clearAllFilters}
              className="text-sm text-[#4ade80] hover:underline flex items-center gap-1"
            >
              <X className="w-4 h-4" />
              Clear all
            </button>
          )}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-4">
          {/* Status */}
          <div>
            <label className="block text-sm text-[#6b7280] mb-2">Status</label>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full px-3 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] focus:outline-none focus:border-[#4ade80]"
            >
              <option value="">All</option>
              <option value="relevant">Relevant</option>
              <option value="not_relevant">Not Relevant</option>
              <option value="accepted_risk">Accepted Risk</option>
            </select>
          </div>

          {/* Vendor Severity */}
          <div>
            <label className="block text-sm text-[#6b7280] mb-2">Vendor Severity</label>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="w-full px-3 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] focus:outline-none focus:border-[#4ade80]"
            >
              <option value="">All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="negligible">Negligible</option>
            </select>
          </div>

          {/* Min CVSS */}
          <div>
            <label className="block text-sm text-[#6b7280] mb-2">Min CVSS Score</label>
            <input
              type="number"
              min="0"
              max="10"
              step="0.1"
              value={minCvss}
              onChange={(e) => setMinCvss(e.target.value)}
              placeholder="0.0"
              className="w-full px-3 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] placeholder-[#6b7280] focus:outline-none focus:border-[#4ade80]"
            />
          </div>

          {/* Finding Active */}
          <div>
            <label className="block text-sm text-[#6b7280] mb-2">Finding Status</label>
            <select
              value={findingActiveFilter}
              onChange={(e) => setFindingActiveFilter(e.target.value)}
              className="w-full px-3 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] focus:outline-none focus:border-[#4ade80]"
            >
              <option value="">All</option>
              <option value="true">Active</option>
              <option value="false">Resolved</option>
            </select>
          </div>

          {/* Fix Available */}
          <div>
            <label className="block text-sm text-[#6b7280] mb-2">Fix Available</label>
            <select
              value={hasFixFilter}
              onChange={(e) => setHasFixFilter(e.target.value)}
              className="w-full px-3 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] focus:outline-none focus:border-[#4ade80]"
            >
              <option value="">All</option>
              <option value="true">Available</option>
              <option value="false">No Fix</option>
            </select>
          </div>
        </div>
      </div>

      {/* Table Card */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-[#e8f5e9]">
            Assessment History
            {total > 0 && <span className="text-[#a5d6a7] font-normal ml-2 text-sm">({total})</span>}
          </h2>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#2d3f36]">
                <SortHeader field="cveId">CVE ID</SortHeader>
                <SortHeader field="status">Status</SortHeader>
                <SortHeader field="cvss3Score">CVSS</SortHeader>
                <SortHeader field="severity">Vendor</SortHeader>
                <SortHeader field="affectedServers">Affected</SortHeader>
                <th className="table-header text-left py-3 px-4">Active</th>
                <th className="table-header text-left py-3 px-4">Fix</th>
                <th className="table-header text-left py-3 px-4">Comment</th>
                <SortHeader field="assessedAt">Assessed</SortHeader>
                <th className="table-header text-left py-3 px-4">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={10} className="py-8 text-center text-[#a5d6a7]">
                    Loading assessments...
                  </td>
                </tr>
              ) : assessments.length === 0 ? (
                <tr>
                  <td colSpan={10} className="py-8 text-center text-[#6b7280]">
                    No assessments match your criteria.
                  </td>
                </tr>
              ) : (
                assessments.map((assessment) => (
                  <tr key={assessment.id} className="table-row">
                    <td className="py-3 px-4">
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${assessment.cveId}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-mono text-[#4ade80] hover:underline flex items-center gap-1"
                      >
                        {assessment.cveId}
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    </td>
                    <td className="py-3 px-4">
                      <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium border ${statusClasses[assessment.status]}`}>
                        {statusIcons[assessment.status]}
                        {statusLabels[assessment.status]}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <CVSSBadge score={assessment.cvss3Score ?? null} cveId={assessment.cveId} />
                    </td>
                    <td className="py-3 px-4">
                      <VendorSeverityBadge severity={assessment.severity || ''} sourceLink={assessment.sourceLink} />
                    </td>
                    <td className="py-3 px-4 text-[#a5d6a7]">
                      {assessment.affectedServers ?? 0} server{(assessment.affectedServers ?? 0) !== 1 ? 's' : ''}
                    </td>
                    {/* Finding Active */}
                    <td className="py-3 px-4">
                      {assessment.findingActive ? (
                        <span className="inline-flex items-center gap-1 text-xs font-medium text-red-400">
                          <Activity className="w-3.5 h-3.5" />
                          Active
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs font-medium text-green-400">
                          <CheckCircle className="w-3.5 h-3.5" />
                          Resolved
                        </span>
                      )}
                    </td>
                    {/* Fix Available */}
                    <td className="py-3 px-4">
                      {assessment.hasFixAvailable ? (
                        <span className="inline-flex items-center gap-1 text-xs font-medium text-[#4ade80]">
                          <Wrench className="w-3.5 h-3.5" />
                          Available
                        </span>
                      ) : (
                        <span className="text-xs text-[#6b7280]">No fix</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <div className="max-w-xs">
                        <p className="text-sm text-[#a5d6a7] truncate" title={assessment.comment}>
                          {assessment.comment || '-'}
                        </p>
                        {assessment.ticketUrl && (
                          <a
                            href={assessment.ticketUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-xs text-[#4ade80] hover:underline flex items-center gap-1 mt-1"
                          >
                            View Ticket <ExternalLink className="w-3 h-3" />
                          </a>
                        )}
                      </div>
                    </td>
                    <td className="py-3 px-4 text-sm text-[#6b7280]">
                      <div>
                        {new Date(assessment.assessedAt).toLocaleDateString()}
                      </div>
                      <div className="text-xs">
                        by {assessment.assessedBy || 'Unknown'}
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => openEditModal(assessment)}
                          className="p-1.5 rounded hover:bg-[#2d3f36] text-[#a5d6a7] hover:text-[#4ade80] transition-colors"
                          title="Edit Assessment"
                        >
                          <Edit2 className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => openResetModal(assessment)}
                          className="p-1.5 rounded hover:bg-[#2d3f36] text-[#a5d6a7] hover:text-red-400 transition-colors"
                          title="Reset Assessment"
                        >
                          <RotateCcw className="w-4 h-4" />
                        </button>
                      </div>
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
              Showing {((currentPage - 1) * ITEMS_PER_PAGE) + 1} to {Math.min(currentPage * ITEMS_PER_PAGE, total)} of {total} assessments
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

      {/* Edit Modal */}
      {showEditModal && editingAssessment && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
          <div className="bg-[#111916] border border-[#2d3f36] rounded-xl p-6 w-full max-w-2xl mx-4 max-h-[90vh] overflow-y-auto">
            <h2 className="text-xl font-bold text-[#e8f5e9] mb-2">
              Edit Assessment: {editingAssessment.cveId}
            </h2>
            <p className="text-sm text-[#a5d6a7] mb-4">
              Update the assessment status and justification.
            </p>

            {error && (
              <div className="mb-4 p-3 bg-red-600/10 border border-red-600/50 rounded-lg text-red-400">
                {error}
              </div>
            )}

            <div className="space-y-4">
              {/* Status Selection */}
              <div>
                <label className="block text-sm text-[#a5d6a7] mb-2">Status</label>
                <div className="flex gap-2">
                  {(['relevant', 'not_relevant', 'accepted_risk'] as AssessmentStatus[]).map((status) => (
                    <button
                      key={status}
                      onClick={() => {
                        setEditStatus(status);
                        setSelectedReason('');
                        setEditComment('');
                      }}
                      className={`px-4 py-2 rounded-lg border transition-colors ${
                        editStatus === status
                          ? statusClasses[status]
                          : 'bg-[#1a2420] border-[#2d3f36] text-[#a5d6a7] hover:border-[#4ade80]/30'
                      }`}
                    >
                      {statusLabels[status]}
                    </button>
                  ))}
                </div>
              </div>

              {/* Relevant: Comment + Ticket URL */}
              {editStatus === 'relevant' && (
                <>
                  <div>
                    <label className="block text-sm text-[#a5d6a7] mb-2">Reason / Notes</label>
                    <textarea
                      value={editComment}
                      onChange={(e) => setEditComment(e.target.value)}
                      className="input w-full h-24 resize-none"
                      placeholder="Describe why this is relevant and what action is needed..."
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-[#a5d6a7] mb-2">Ticket URL (optional)</label>
                    <input
                      type="url"
                      value={editTicketUrl}
                      onChange={(e) => setEditTicketUrl(e.target.value)}
                      className="input w-full"
                      placeholder="https://jira.example.com/browse/SEC-123"
                    />
                  </div>
                </>
              )}

              {/* Not Relevant / Accept Risk: Reason templates or custom */}
              {(editStatus === 'not_relevant' || editStatus === 'accepted_risk') && (
                <>
                  {filteredTemplates.length > 0 && (
                    <div>
                      <label className="block text-sm text-[#a5d6a7] mb-2">Select a reason</label>
                      <div className="space-y-2 max-h-48 overflow-y-auto">
                        {filteredTemplates.map((template) => (
                          <label
                            key={template.id}
                            className={`flex items-center gap-3 px-4 py-3 rounded-lg cursor-pointer border transition-colors ${
                              selectedReason === template.reason
                                ? 'bg-[#4ade80]/20 border-[#4ade80]/50'
                                : 'bg-[#1a2420] border-[#2d3f36] hover:border-[#4ade80]/30'
                            }`}
                          >
                            <input
                              type="radio"
                              name="reason"
                              value={template.reason}
                              checked={selectedReason === template.reason}
                              onChange={(e) => {
                                setSelectedReason(e.target.value);
                                setEditComment('');
                              }}
                              className="text-[#4ade80]"
                            />
                            <span className="text-[#e8f5e9]">{template.reason}</span>
                          </label>
                        ))}
                      </div>
                    </div>
                  )}
                  <div>
                    <label className="block text-sm text-[#a5d6a7] mb-2">Or enter custom reason</label>
                    <textarea
                      value={editComment}
                      onChange={(e) => {
                        setEditComment(e.target.value);
                        setSelectedReason('');
                      }}
                      className="input w-full h-20 resize-none"
                      placeholder="Enter a custom reason..."
                    />
                  </div>
                </>
              )}
            </div>

            {/* Modal Actions */}
            <div className="flex justify-end gap-3 mt-6">
              <button
                onClick={() => setShowEditModal(false)}
                className="btn bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36]"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveEdit}
                disabled={saving || (editStatus === 'relevant' && !editComment) || (editStatus !== 'relevant' && !selectedReason && !editComment)}
                className="btn bg-[#4ade80] text-[#0a0f0d] font-semibold hover:bg-[#22c55e] disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {saving ? 'Saving...' : 'Save Changes'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Reset Confirmation Modal */}
      {showResetModal && resettingAssessment && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
          <div className="bg-[#111916] border border-[#2d3f36] rounded-xl p-6 w-full max-w-md mx-4">
            <h2 className="text-xl font-bold text-[#e8f5e9] mb-2">Reset Assessment</h2>
            <p className="text-[#a5d6a7] mb-4">
              Are you sure you want to reset the assessment for{' '}
              <span className="font-mono text-[#4ade80]">{resettingAssessment.cveId}</span>?
            </p>
            <p className="text-sm text-[#6b7280] mb-6">
              This will remove the assessment and the CVE will appear in the triage queue again (if it matches the current filter criteria).
            </p>

            {/* Modal Actions */}
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setShowResetModal(false)}
                className="btn bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36]"
              >
                Cancel
              </button>
              <button
                onClick={handleReset}
                disabled={saving}
                className="btn bg-red-600/20 text-red-400 border border-red-600/50 hover:bg-red-600/30 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {saving ? 'Resetting...' : 'Reset Assessment'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
