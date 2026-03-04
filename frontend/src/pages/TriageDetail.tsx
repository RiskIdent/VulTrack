import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { 
  ArrowLeft, ExternalLink, AlertTriangle, XCircle, CheckCircle, 
  ChevronLeft, ChevronRight, Server, Package
} from 'lucide-react';
import { CVSSBadge, VendorSeverityBadge, FixStateBadge } from '../components/SeverityBadge';
import { getTriageQueue, getFindings, getFinding, createAssessment, getReasonTemplates } from '../api/client';
import { useAuth } from '../context/AuthContext';
import type { Finding, AssessmentStatus, ReasonTemplate } from '../types';

const MAX_DESCRIPTION_LENGTH = 300;

// Expandable description component
function ExpandableDescription({ text }: { text: string | undefined }) {
  const [expanded, setExpanded] = useState(false);
  
  if (!text) return <span className="text-[#6b7280]">No description available</span>;
  
  const needsTruncation = text.length > MAX_DESCRIPTION_LENGTH;
  const displayText = expanded || !needsTruncation 
    ? text 
    : text.slice(0, MAX_DESCRIPTION_LENGTH) + '...';
  
  return (
    <div>
      <p className="text-[#e8f5e9] whitespace-pre-wrap break-words">{displayText}</p>
      {needsTruncation && (
        <button
          onClick={() => setExpanded(!expanded)}
          className="text-[#4ade80] hover:text-[#22c55e] text-sm mt-2 font-medium"
        >
          {expanded ? 'Show less' : 'Show more'}
        </button>
      )}
    </div>
  );
}

export default function TriageDetail() {
  const { cveId } = useParams<{ cveId: string }>();
  const navigate = useNavigate();
  const { user } = useAuth();
  
  const [queue, setQueue] = useState<Finding[]>([]);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [affectedFindings, setAffectedFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  // Reason templates from backend
  const [notRelevantReasons, setNotRelevantReasons] = useState<ReasonTemplate[]>([]);
  const [acceptRiskReasons, setAcceptRiskReasons] = useState<ReasonTemplate[]>([]);
  
  // Enriched finding details (exploit info, full description)
  const [enrichedFinding, setEnrichedFinding] = useState<Finding | null>(null);

  // Modal state
  const [showModal, setShowModal] = useState(false);
  const [modalType, setModalType] = useState<AssessmentStatus>('relevant');
  const [comment, setComment] = useState('');
  const [ticketUrl, setTicketUrl] = useState('');
  const [selectedReason, setSelectedReason] = useState('');

  // Load queue and find current CVE
  useEffect(() => {
    async function fetchData() {
      setLoading(true);
      try {
        const [queueData, notRelevantData, acceptRiskData] = await Promise.all([
          getTriageQueue({ limit: 1000 }),
          getReasonTemplates('not_relevant'),
          getReasonTemplates('accepted_risk'),
        ]);
        
        const findings = queueData.findings || [];
        setQueue(findings);
        setNotRelevantReasons(notRelevantData.templates || []);
        setAcceptRiskReasons(acceptRiskData.templates || []);
        
        // Find index of current CVE
        const idx = findings.findIndex(f => f.cveId === cveId);
        if (idx >= 0) {
          setCurrentIndex(idx);
        } else if (findings.length > 0) {
          // CVE not in queue, go to first
          navigate(`/triage/${findings[0].cveId}`, { replace: true });
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load queue');
      } finally {
        setLoading(false);
      }
    }
    fetchData();
  }, [cveId, navigate]);

  // Load all affected servers/packages for current CVE
  useEffect(() => {
    async function fetchAffected() {
      if (!cveId) return;
      try {
        const data = await getFindings({ cveId, limit: 100 });
        setAffectedFindings(data.findings || []);
      } catch (err) {
        console.error('Failed to load affected findings:', err);
      }
    }
    fetchAffected();
  }, [cveId]);

  const currentFinding = queue[currentIndex];

  // Load enriched finding details (exploit info, description) for current CVE
  useEffect(() => {
    async function fetchEnriched() {
      if (!currentFinding?.id) {
        setEnrichedFinding(null);
        return;
      }
      try {
        const data = await getFinding(currentFinding.id);
        setEnrichedFinding(data);
      } catch (err) {
        console.error('Failed to load enriched finding details:', err);
        setEnrichedFinding(null);
      }
    }
    fetchEnriched();
  }, [currentFinding?.id]);

  const goToNext = useCallback(() => {
    if (currentIndex < queue.length - 1) {
      const nextCve = queue[currentIndex + 1];
      navigate(`/triage/${nextCve.cveId}`);
    } else {
      // All done
      navigate('/triage');
    }
  }, [currentIndex, queue, navigate]);

  const goToPrev = useCallback(() => {
    if (currentIndex > 0) {
      const prevCve = queue[currentIndex - 1];
      navigate(`/triage/${prevCve.cveId}`);
    }
  }, [currentIndex, queue, navigate]);

  const openModal = (type: AssessmentStatus) => {
    setModalType(type);
    setComment('');
    setTicketUrl('');
    setSelectedReason('');
    setShowModal(true);
  };

  const handleSubmit = async () => {
    if (!cveId) return;
    
    setSubmitting(true);
    try {
      const finalComment = selectedReason || comment;
      await createAssessment({
        cveId,
        status: modalType,
        comment: finalComment,
        ticketUrl: modalType === 'relevant' ? ticketUrl : undefined,
        assessedBy: user?.name || user?.email || 'anonymous',
      });
      
      // Remove from queue and go to next
      const newQueue = queue.filter(f => f.cveId !== cveId);
      setQueue(newQueue);
      setShowModal(false);
      
      if (newQueue.length > 0) {
        const nextIdx = Math.min(currentIndex, newQueue.length - 1);
        navigate(`/triage/${newQueue[nextIdx].cveId}`);
      } else {
        navigate('/triage');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save assessment');
    } finally {
      setSubmitting(false);
    }
  };

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (showModal) return; // Don't handle shortcuts when modal is open
      
      switch (e.key.toLowerCase()) {
        case 'r':
          openModal('relevant');
          break;
        case 'n':
          openModal('not_relevant');
          break;
        case 'a':
          openModal('accepted_risk');
          break;
        case 'arrowleft':
          goToPrev();
          break;
        case 'arrowright':
          goToNext();
          break;
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [showModal, goToNext, goToPrev]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-[#a5d6a7]">Loading...</div>
      </div>
    );
  }

  if (!currentFinding) {
    return (
      <div className="space-y-4">
        <Link to="/triage" className="inline-flex items-center gap-2 text-[#4ade80] hover:underline">
          <ArrowLeft className="w-4 h-4" />
          Back to queue
        </Link>
        <div className="card text-center py-12">
          <CheckCircle className="w-12 h-12 text-green-400 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-[#e8f5e9]">All caught up!</h3>
          <p className="text-[#a5d6a7] mt-1">No more CVEs to assess.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header with navigation */}
      <div className="flex items-center justify-between">
        <Link to="/triage" className="inline-flex items-center gap-2 text-[#4ade80] hover:underline">
          <ArrowLeft className="w-4 h-4" />
          Back to queue
        </Link>
        
        <div className="flex items-center gap-4">
          <span className="text-[#6b7280]">
            {currentIndex + 1} of {queue.length}
          </span>
          <div className="flex gap-2">
            <button
              onClick={goToPrev}
              disabled={currentIndex === 0}
              className="p-2 rounded bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36] disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <ChevronLeft className="w-5 h-5" />
            </button>
            <button
              onClick={goToNext}
              disabled={currentIndex === queue.length - 1}
              className="p-2 rounded bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36] disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <ChevronRight className="w-5 h-5" />
            </button>
          </div>
        </div>
      </div>

      {error && (
        <div className="card border-red-600/50 bg-red-600/5">
          <p className="text-red-400">{error}</p>
        </div>
      )}

      {/* Main CVE Card */}
      <div className="card">
        <div className="flex items-start justify-between gap-6">
          <div className="flex-1">
            {/* CVE Header */}
            <div className="flex items-center gap-4 mb-4">
              <h1 className="text-3xl font-bold text-[#4ade80] font-mono">
                {currentFinding.cveId}
              </h1>
              <CVSSBadge score={currentFinding.nvdCvss3Score ?? currentFinding.cvss3Score} cveId={currentFinding.cveId} />
              <VendorSeverityBadge severity={currentFinding.severity} sourceLink={currentFinding.sourceLink} />
              <FixStateBadge fixState={currentFinding.fixState} />
            </div>

            {/* Summary */}
            <div className="mb-6">
              <h3 className="text-sm font-semibold text-[#a5d6a7] mb-2">Description</h3>
              <ExpandableDescription text={enrichedFinding?.description || currentFinding.nvdDescription || currentFinding.summary} />
            </div>

            {/* Exploit Info */}
            {enrichedFinding?.hasExploit && (
              <div className="mb-6 p-4 rounded-lg bg-red-600/5 border border-red-600/30">
                <div className="flex items-center gap-3 mb-3">
                  <AlertTriangle className="w-5 h-5 text-red-400" />
                  <h3 className="text-sm font-semibold text-red-400">
                    {enrichedFinding.exploitCount} Known Exploit{enrichedFinding.exploitCount !== 1 ? 's' : ''}
                    {enrichedFinding.verifiedExploit && (
                      <span className="text-[#fbbf24] ml-2">(verified)</span>
                    )}
                  </h3>
                </div>
                {(enrichedFinding.exploitIds?.length ?? 0) > 0 && (
                  <div className="flex flex-wrap gap-2">
                    {enrichedFinding.exploitIds?.map((edbId) => (
                      <a
                        key={edbId}
                        href={`https://www.exploit-db.com/exploits/${edbId}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[#1a2420] rounded text-sm font-mono text-red-400 hover:bg-red-600/20 border border-red-600/30"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                        EDB-{edbId}
                      </a>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* External Links */}
            <div className="flex gap-4 mb-6">
              <a
                href={`https://nvd.nist.gov/vuln/detail/${currentFinding.cveId}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 px-4 py-2 bg-[#1a2420] rounded-lg text-[#4ade80] hover:bg-[#2d3f36]"
              >
                <ExternalLink className="w-4 h-4" />
                View on NVD
              </a>
              {currentFinding.sourceLink && (
                <a
                  href={currentFinding.sourceLink}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 px-4 py-2 bg-[#1a2420] rounded-lg text-[#4ade80] hover:bg-[#2d3f36]"
                >
                  <ExternalLink className="w-4 h-4" />
                  Vendor Advisory
                </a>
              )}
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-col gap-3 min-w-[180px]">
            <button
              onClick={() => openModal('relevant')}
              className="btn flex items-center justify-center gap-2 bg-red-600/20 text-red-400 border border-red-600/50 hover:bg-red-600/30 py-3"
            >
              <AlertTriangle className="w-5 h-5" />
              Relevant (R)
            </button>
            <button
              onClick={() => openModal('not_relevant')}
              className="btn flex items-center justify-center gap-2 bg-green-600/20 text-green-400 border border-green-600/50 hover:bg-green-600/30 py-3"
            >
              <XCircle className="w-5 h-5" />
              Not Relevant (N)
            </button>
            <button
              onClick={() => openModal('accepted_risk')}
              className="btn flex items-center justify-center gap-2 bg-yellow-600/20 text-yellow-400 border border-yellow-600/50 hover:bg-yellow-600/30 py-3"
            >
              <CheckCircle className="w-5 h-5" />
              Accept Risk (A)
            </button>
          </div>
        </div>
      </div>

      {/* Affected Servers & Packages */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Affected Servers */}
        <div className="card">
          <h2 className="text-lg font-semibold text-[#e8f5e9] mb-4 flex items-center gap-2">
            <Server className="w-5 h-5" />
            Affected Servers ({[...new Set(affectedFindings.map(f => f.serverName))].length})
          </h2>
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {[...new Set(affectedFindings.map(f => f.serverName))].map(server => (
              <div key={server} className="px-3 py-2 bg-[#1a2420] rounded text-[#a5d6a7]">
                {server}
              </div>
            ))}
          </div>
        </div>

        {/* Affected Packages */}
        <div className="card">
          <h2 className="text-lg font-semibold text-[#e8f5e9] mb-4 flex items-center gap-2">
            <Package className="w-5 h-5" />
            Affected Packages ({[...new Set(affectedFindings.map(f => f.packageName))].length})
          </h2>
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {[...new Set(affectedFindings.map(f => `${f.packageName}|${f.packageVersion}|${f.fixState}|${f.fixedIn}`))].map(pkg => {
              const [name, version, fixState, fixedIn] = pkg.split('|');
              return (
                <div key={pkg} className="px-3 py-2 bg-[#1a2420] rounded font-mono text-sm flex items-center justify-between gap-2">
                  <div>
                    <span className="text-[#a5d6a7]">{name}</span>
                    {version && <span className="text-[#6b7280] ml-2">@ {version}</span>}
                    {fixedIn && <span className="text-[#4ade80] ml-2">→ {fixedIn}</span>}
                  </div>
                  <FixStateBadge fixState={fixState} />
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Keyboard shortcuts hint */}
      <div className="text-center text-sm text-[#6b7280]">
        Keyboard shortcuts: <kbd className="px-2 py-1 bg-[#1a2420] rounded">R</kbd> Relevant, 
        <kbd className="px-2 py-1 bg-[#1a2420] rounded ml-2">N</kbd> Not Relevant, 
        <kbd className="px-2 py-1 bg-[#1a2420] rounded ml-2">A</kbd> Accept Risk, 
        <kbd className="px-2 py-1 bg-[#1a2420] rounded ml-2">←</kbd><kbd className="px-2 py-1 bg-[#1a2420] rounded">→</kbd> Navigate
      </div>

      {/* Assessment Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
          <div className="bg-[#111916] border border-[#2d3f36] rounded-xl p-6 w-full max-w-2xl mx-4">
            <h2 className="text-xl font-bold text-[#e8f5e9] mb-4">
              {modalType === 'relevant' && 'Mark as Relevant'}
              {modalType === 'not_relevant' && 'Mark as Not Relevant'}
              {modalType === 'accepted_risk' && 'Accept Risk'}
            </h2>

            {/* Relevant: Comment + Ticket URL */}
            {modalType === 'relevant' && (
              <div className="space-y-4">
                <div>
                  <label className="block text-sm text-[#a5d6a7] mb-2">Reason / Notes</label>
                  <textarea
                    value={comment}
                    onChange={(e) => setComment(e.target.value)}
                    className="input w-full h-24 resize-none"
                    placeholder="Describe why this is relevant and what action is needed..."
                  />
                </div>
                <div>
                  <label className="block text-sm text-[#a5d6a7] mb-2">Ticket URL (optional)</label>
                  <input
                    type="url"
                    value={ticketUrl}
                    onChange={(e) => setTicketUrl(e.target.value)}
                    className="input w-full"
                    placeholder="https://jira.example.com/browse/SEC-123"
                  />
                </div>
              </div>
            )}

            {/* Not Relevant / Accept Risk: Reason templates or custom */}
            {(modalType === 'not_relevant' || modalType === 'accepted_risk') && (
              <div className="space-y-4">
                <div>
                  <label className="block text-sm text-[#a5d6a7] mb-2">Select a reason</label>
                  <div className="space-y-2">
                    {(modalType === 'not_relevant' ? notRelevantReasons : acceptRiskReasons).map((template) => (
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
                            setComment('');
                          }}
                          className="text-[#4ade80]"
                        />
                        <span className="text-[#e8f5e9]">{template.reason}</span>
                      </label>
                    ))}
                  </div>
                </div>
                <div>
                  <label className="block text-sm text-[#a5d6a7] mb-2">Or enter custom reason</label>
                  <textarea
                    value={comment}
                    onChange={(e) => {
                      setComment(e.target.value);
                      setSelectedReason('');
                    }}
                    className="input w-full h-20 resize-none"
                    placeholder="Enter a custom reason..."
                  />
                </div>
              </div>
            )}

            {/* Modal Actions */}
            <div className="flex justify-end gap-3 mt-6">
              <button
                onClick={() => setShowModal(false)}
                className="btn bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36]"
              >
                Cancel
              </button>
              <button
                onClick={handleSubmit}
                disabled={submitting || (modalType === 'relevant' && !comment) || (modalType !== 'relevant' && !selectedReason && !comment)}
                className="btn bg-[#4ade80] text-[#0a0f0d] font-semibold hover:bg-[#22c55e] disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {submitting ? 'Saving...' : 'Confirm'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
