import { useCallback, useEffect, useState } from 'react';
import { Sparkles, AlertTriangle, XCircle, CheckCircle, Clock, RefreshCw } from 'lucide-react';
import { ApiError, getAIAssessment, requestAIAssessment } from '../api/client';
import type { AIAssessment } from '../types';

const recommendedStatusLabels: Record<string, string> = {
  relevant: 'Relevant',
  not_relevant: 'Not Relevant',
  accepted_risk: 'Accepted Risk',
};

const recommendedStatusClasses: Record<string, string> = {
  relevant: 'bg-red-600/20 text-red-400 border-red-600/50',
  not_relevant: 'bg-green-600/20 text-green-400 border-green-600/50',
  accepted_risk: 'bg-yellow-600/20 text-yellow-400 border-yellow-600/50',
};

const confidenceClasses: Record<string, string> = {
  low: 'bg-[#1a2420] text-[#6b7280] border-[#2d3f36]',
  medium: 'bg-blue-600/20 text-blue-400 border-blue-600/50',
  high: 'bg-green-600/20 text-green-400 border-green-600/50',
};

// Badge for the model's recommended assessment status.
export function RecommendedStatusBadge({ status }: { status: string }) {
  if (!status) return null;
  const icon =
    status === 'relevant' ? <AlertTriangle className="w-3.5 h-3.5" /> :
    status === 'not_relevant' ? <XCircle className="w-3.5 h-3.5" /> :
    <CheckCircle className="w-3.5 h-3.5" />;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium border ${recommendedStatusClasses[status] || ''}`}>
      {icon}
      {recommendedStatusLabels[status] || status}
    </span>
  );
}

// Badge for the model's confidence level.
export function ConfidenceBadge({ confidence }: { confidence: string }) {
  if (!confidence) return null;
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${confidenceClasses[confidence] || ''}`}>
      {confidence.charAt(0).toUpperCase() + confidence.slice(1)} confidence
    </span>
  );
}

// Presentational body for a completed AI assessment. Reused by the triage card
// and the AI Assessments page modal.
export function AIAssessmentContent({ assessment }: { assessment: AIAssessment }) {
  const totalTokens = (assessment.inputTokens || 0) + (assessment.outputTokens || 0);
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <RecommendedStatusBadge status={assessment.recommendedStatus} />
        <ConfidenceBadge confidence={assessment.confidence} />
      </div>
      <div>
        <h4 className="text-sm font-semibold text-[#a5d6a7] mb-1">Attack vector</h4>
        <p className="text-[#e8f5e9] whitespace-pre-wrap break-words">{assessment.attackVector || '-'}</p>
      </div>
      <div>
        <h4 className="text-sm font-semibold text-[#a5d6a7] mb-1">Prerequisites</h4>
        <p className="text-[#e8f5e9] whitespace-pre-wrap break-words">{assessment.prerequisites || '-'}</p>
      </div>
      <div>
        <h4 className="text-sm font-semibold text-[#a5d6a7] mb-1">Recommendation</h4>
        <p className="text-[#e8f5e9] whitespace-pre-wrap break-words">{assessment.recommendationReasoning || '-'}</p>
      </div>
      <p className="text-xs text-[#6b7280]">
        Model: {assessment.model || 'unknown'}
        {assessment.updatedAt && ` · ${new Date(assessment.updatedAt).toLocaleString()}`}
        {totalTokens > 0 && ` · ${totalTokens.toLocaleString()} tokens`}
      </p>
      <p className="text-xs text-[#6b7280] italic">
        This is an AI-generated recommendation. A human analyst makes the final decision.
      </p>
    </div>
  );
}

// Self-contained card that loads, polls, and (re-)requests the AI assessment
// for a single CVE. Used on the triage detail page.
export function AIAssessmentCard({ cveId }: { cveId: string }) {
  const [assessment, setAssessment] = useState<AIAssessment | null>(null);
  const [loading, setLoading] = useState(true);
  const [requesting, setRequesting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await getAIAssessment(cveId);
      setAssessment(data);
      setError(null);
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        // 404 is the expected "no assessment yet" case — not an error.
        setAssessment(null);
        setError(null);
      } else {
        setError(err instanceof Error ? err.message : 'Failed to load AI assessment');
      }
    } finally {
      setLoading(false);
    }
  }, [cveId]);

  useEffect(() => {
    setLoading(true);
    setError(null);
    setAssessment(null);
    load();
  }, [load]);

  // Poll while the assessment is still being produced. Uses an interval (not a
  // one-shot timeout) so polling continues even when the row stays in the same
  // state between fetches (e.g. pending for a while before a worker claims it).
  useEffect(() => {
    const status = assessment?.status;
    if (status !== 'pending' && status !== 'processing') return;
    const id = setInterval(load, 4000);
    return () => clearInterval(id);
  }, [assessment?.status, load]);

  async function handleRequest(force: boolean) {
    setRequesting(true);
    setError(null);
    try {
      await requestAIAssessment(cveId, force);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to request AI assessment');
    } finally {
      setRequesting(false);
    }
  }

  const status = assessment?.status;

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-[#e8f5e9] flex items-center gap-2">
          <Sparkles className="w-5 h-5 text-[#4ade80]" />
          AI assessment
        </h2>
        {(status === 'completed' || status === 'failed') && (
          <button
            onClick={() => handleRequest(true)}
            disabled={requesting}
            className="btn bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36] flex items-center gap-2 disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${requesting ? 'animate-spin' : ''}`} />
            Request new assessment
          </button>
        )}
      </div>

      {error && (
        <div className="mb-4 p-3 bg-red-600/10 border border-red-600/50 rounded-lg text-red-400">{error}</div>
      )}

      {loading ? (
        <p className="text-[#a5d6a7]">Loading…</p>
      ) : status === 'completed' && assessment ? (
        <AIAssessmentContent assessment={assessment} />
      ) : status === 'pending' || status === 'processing' ? (
        <div className="flex items-center gap-2 text-[#a5d6a7]">
          <Clock className="w-4 h-4 animate-pulse" />
          Assessment in progress…
        </div>
      ) : status === 'failed' ? (
        <div className="text-[#a5d6a7]">
          <p className="text-red-400 mb-1">The AI assessment failed.</p>
          {assessment?.error && <p className="text-xs text-[#6b7280] break-words">{assessment.error}</p>}
        </div>
      ) : (
        <div className="flex items-center justify-between gap-4">
          <p className="text-[#6b7280]">No AI assessment yet.</p>
          <button
            onClick={() => handleRequest(false)}
            disabled={requesting}
            className="btn btn-primary flex items-center gap-2 disabled:opacity-50"
          >
            <Sparkles className="w-4 h-4" />
            {requesting ? 'Requesting…' : 'Request AI assessment'}
          </button>
        </div>
      )}
    </div>
  );
}
