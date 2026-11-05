import { useCallback, useEffect, useState } from 'react';
import { Route, RefreshCw, Save, Link as LinkIcon } from 'lucide-react';
import { Link } from 'react-router-dom';
import { getCVEPreconditions, getPreconditionStatus, runPreconditionAnalysis, updatePreconditionConfig } from '../api/client';
import type { PreconditionAnalysis, PreconditionCondition, PreconditionStatus } from '../types';

const MODEL_NAMES: Record<string, string> = {
  'claude-sonnet-5-5': 'Claude Sonnet 5.5',
  'claude-opus-5-5': 'Claude Opus 5.5',
  'claude-haiku-5-5': 'Claude Haiku 5.5',
};

const CONDITION_LABELS: Record<string, string> = {
  network_listener: 'Listening socket',
  package_in_use: 'Package in use',
  service_active: 'Service running',
  unprivileged_userns: 'Unprivileged user namespaces',
  unprivileged_bpf: 'Unprivileged BPF',
  kernel_code: 'Kernel code compiled in',
  local_user: 'Local user',
  physical_access: 'Physical access',
  user_interaction: 'User interaction',
  config_dependent: 'Configuration',
};

const CHECKABLE = new Set(['network_listener', 'package_in_use', 'service_active', 'unprivileged_userns', 'unprivileged_bpf']);

function usd(v: number) {
  return `$${v.toFixed(v < 1 ? 3 : 2)}`;
}

function conditionText(c: PreconditionCondition) {
  const subject = [c.package, c.unit, c.path].filter(Boolean).join(' ');
  const scope = c.type === 'network_listener' && c.scope === 'non_loopback' ? ' (non-loopback)' : '';
  return `${CONDITION_LABELS[c.type] || c.type}${subject ? `: ${subject}` : ''}${scope}`;
}

// PreconditionCard shows the AI precondition analysis of a CVE: the attack
// paths and their conditions. Rule AI-PRE checks them per server.
export function PreconditionCard({ cveId }: { cveId: string }) {
  const [analysis, setAnalysis] = useState<PreconditionAnalysis | null | undefined>(undefined);

  useEffect(() => {
    let cancelled = false;
    getCVEPreconditions(cveId)
      .then((r) => !cancelled && setAnalysis(r.analysis))
      .catch(() => !cancelled && setAnalysis(null));
    return () => {
      cancelled = true;
    };
  }, [cveId]);

  if (!analysis) return null;
  const r = analysis.result;
  return (
    <div className="card">
      <div className="flex items-center justify-between gap-3 mb-3">
        <div className="flex items-center gap-2">
          <Route className="w-5 h-5 text-sky-300" />
          <h3 className="text-lg font-semibold text-[#e8f5e9]">Attack preconditions</h3>
        </div>
        <span className="text-xs text-[#6b7280]">
          {MODEL_NAMES[analysis.model] || analysis.model}
          {analysis.analysedAt ? ` · ${new Date(analysis.analysedAt).toLocaleDateString()}` : ''}
          {!analysis.current && analysis.status === 'ok' ? ' · outdated, will be redone' : ''}
        </span>
      </div>
      {analysis.refusedBy && analysis.status === 'ok' && (
        <p className="text-xs text-yellow-400 mb-2">
          {MODEL_NAMES[analysis.refusedBy] || analysis.refusedBy} declined this CVE; analysed by the fallback model.
        </p>
      )}
      {analysis.status === 'pending' && <p className="text-sm text-[#a5d6a7]">Analysis requested, waiting for the batch result.</p>}
      {analysis.status === 'error' && <p className="text-sm text-red-400">Analysis failed: {analysis.error}</p>}
      {r && (
        <div className="space-y-3">
          {!r.determinable && (
            <p className="text-sm text-yellow-400">The model could not determine the preconditions; no server is dismissed on this basis.</p>
          )}
          <p className="text-xs text-[#6b7280]">
            Any one path suffices for an attack; within a path every condition is needed. A server is dismissed (rule AI-PRE) only when
            each path has a necessary, high-confidence condition that is definitely false there.
          </p>
          {r.paths.map((p, i) => (
            <div key={i} className="rounded-lg border border-[#2d3f36] bg-[#1a2420] p-3">
              <div className="text-xs font-semibold text-[#a5d6a7] mb-2">Path {i + 1}</div>
              <ul className="space-y-1.5">
                {p.requires.map((c, j) => (
                  <li key={j} className="text-sm">
                    <span className="text-[#e8f5e9]">{conditionText(c)}</span>
                    <span className="ml-2 text-xs text-[#6b7280]">
                      {c.necessary ? 'necessary' : 'not strictly necessary'} · {c.confidence} confidence
                      {CHECKABLE.has(c.type) ? ' · checked per server' : ' · not checkable'}
                    </span>
                    {c.reason && <div className="text-xs text-[#a5d6a7]">{c.reason}</div>}
                  </li>
                ))}
              </ul>
            </div>
          ))}
          {r.reasoning && (
            <div>
              <h4 className="text-sm font-semibold text-[#a5d6a7] mb-1">Reasoning</h4>
              <p className="text-sm text-[#e8f5e9] whitespace-pre-line">{r.reasoning}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// PreconditionSettings is the Admin section of the AI precondition analysis.
export function PreconditionSettings() {
  const [status, setStatus] = useState<PreconditionStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [budget, setBudget] = useState('');
  const [daily, setDaily] = useState('');
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    try {
      const s = await getPreconditionStatus();
      setStatus(s);
      setBudget(String(s.config.budgetUsd));
      setDaily(String(s.config.dailyMax));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load');
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const save = async (data: Parameters<typeof updatePreconditionConfig>[0], msg: string) => {
    setSaving(true);
    setError(null);
    try {
      setStatus(await updatePreconditionConfig(data));
      setNotice(msg);
      setTimeout(() => setNotice(null), 4000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save');
    } finally {
      setSaving(false);
    }
  };

  const saveLimits = () => {
    const b = parseFloat(budget);
    const d = parseInt(daily, 10);
    if (isNaN(b) || b < 0 || isNaN(d) || d < 0) {
      setError('Budget and daily limit must be zero or positive numbers');
      return;
    }
    save({ budgetUsd: b, dailyMax: d }, 'Limits saved.');
  };

  const run = async () => {
    try {
      await runPreconditionAnalysis();
      setNotice('Run started.');
      setTimeout(load, 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start');
    }
  };

  if (!status) return <div className="text-[#a5d6a7]">{error || 'Loading...'}</div>;
  const c = status.config;
  const pct = c.budgetUsd > 0 ? Math.min(100, (status.spentMonth / c.budgetUsd) * 100) : 100;

  return (
    <div className="space-y-6">
      {error && <div className="p-3 rounded-lg border border-red-600/50 bg-red-600/5 text-red-400">{error}</div>}
      {notice && <div className="p-3 rounded-lg border border-[#4ade80]/40 bg-[#4ade80]/10 text-[#4ade80]">{notice}</div>}

      <div className="card">
        <div className="flex items-start justify-between gap-4 mb-4">
          <div className="flex items-center gap-3">
            <Route className="w-6 h-6 text-sky-300" />
            <div>
              <h2 className="text-lg font-semibold text-[#e8f5e9] flex items-center gap-2">
                AI Preconditions
                <span className={`px-2 py-0.5 rounded text-xs font-medium border ${c.enabled
                  ? 'bg-[#4ade80]/20 text-[#4ade80] border-[#4ade80]/40' : 'bg-gray-600/20 text-gray-400 border-gray-600/40'}`}>
                  {c.enabled ? 'enabled' : 'off'}
                </span>
              </h2>
              <p className="text-sm text-[#6b7280]">
                <span className="text-sky-300">Prepares decisions.</span> For CVEs in the triage queue that no rule has decided, a model lists the
                attack paths and their conditions. VulTrack checks those conditions on every server; rule{' '}
                <span className="font-mono">AI-PRE</span> dismisses a server only when every path is definitely blocked there. Its mode is set
                under <Link to="/admin?tab=auto&section=rules" className="underline">Rules &amp; Guards</Link>.
              </p>
            </div>
          </div>
          <button onClick={run} disabled={!status.configured || status.running} className="btn flex items-center gap-2 bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36] shrink-0"
            title="Collect finished batches and start new analyses now (also runs every 15 minutes)">
            <RefreshCw className={`w-4 h-4 ${status.running ? 'animate-spin' : ''}`} /> Run now
          </button>
        </div>

        {!status.configured && (
          <p className="text-sm text-yellow-400 mb-4">ANTHROPIC_API_KEY is not set; the analysis cannot run.</p>
        )}

        <div className="space-y-4">
          <label className={`flex items-start gap-3 cursor-pointer p-3 rounded-lg border ${c.enabled ? 'border-[#4ade80] bg-[#4ade80]/10' : 'border-[#2d3f36] bg-[#1a2420]'}`}>
            <input type="checkbox" checked={c.enabled} disabled={saving || !status.configured}
              onChange={(e) => save({ enabled: e.target.checked }, e.target.checked ? 'AI precondition analysis enabled.' : 'AI precondition analysis disabled.')}
              className="w-4 h-4 mt-1" />
            <div>
              <div className="font-semibold text-[#e8f5e9]">Enable AI precondition analysis</div>
              <div className="text-xs text-[#a5d6a7]">
                Sends CVEs of the triage queue to the model below, within the monthly budget and daily limit. Off: no API calls, no cost;
                existing analyses are kept. Whether the results dismiss servers is decided by the mode of rule AI-PRE.
              </div>
            </div>
          </label>
          <div className="flex flex-wrap items-center gap-6">
            <label className="flex items-center gap-3">
              <span className="text-sm text-[#a5d6a7]">Model</span>
              <select className="input py-1" value={c.model} disabled={saving} onChange={(e) => save({ model: e.target.value }, 'Model saved. Existing analyses are redone with it.')}>
                {status.models.map((m) => (
                  <option key={m} value={m}>{MODEL_NAMES[m] || m}</option>
                ))}
              </select>
            </label>
            <label className="flex items-center gap-3">
              <span className="text-sm text-[#a5d6a7]" title="Analyses CVEs the main model declines (refusal). Without it they stay open for a human.">If declined</span>
              <select className="input py-1" value={c.fallbackModel} disabled={saving}
                onChange={(e) => save({ fallbackModel: e.target.value }, e.target.value ? 'Fallback model saved.' : 'Fallback switched off.')}>
                <option value="">leave open</option>
                {status.fallbackModels.filter((m) => m !== c.model).map((m) => (
                  <option key={m} value={m}>retry with {MODEL_NAMES[m] || m}</option>
                ))}
              </select>
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input type="checkbox" checked={c.useBatch} disabled={saving} onChange={(e) => save({ useBatch: e.target.checked }, 'Saved.')} className="w-4 h-4" />
              <span className="text-sm text-[#e8f5e9]">Batch processing</span>
              <span className="text-xs text-[#6b7280]">half the cost, results within hours</span>
            </label>
          </div>
          <div className="flex flex-wrap items-end gap-4">
            <label>
              <div className="text-sm text-[#a5d6a7] mb-1">Monthly budget (USD)</div>
              <input type="number" min="0" step="1" value={budget} onChange={(e) => setBudget(e.target.value)} className="input w-32" />
            </label>
            <label>
              <div className="text-sm text-[#a5d6a7] mb-1">Analyses per day</div>
              <input type="number" min="0" step="10" value={daily} onChange={(e) => setDaily(e.target.value)} className="input w-32" />
            </label>
            <button onClick={saveLimits} disabled={saving} className="btn btn-primary flex items-center gap-2">
              <Save className="w-4 h-4" /> Save limits
            </button>
          </div>
        </div>
      </div>

      <div className="card">
        <h3 className="text-lg font-semibold text-[#e8f5e9] mb-3">Usage</h3>
        <div className="mb-4">
          <div className="flex justify-between text-sm mb-1">
            <span className="text-[#a5d6a7]">This month: {usd(status.spentMonth)} of {usd(c.budgetUsd)}</span>
            <span className="text-[#6b7280]">≈ {usd(status.avgCost)} per analysis</span>
          </div>
          <div className="h-2 rounded bg-[#1a2420] overflow-hidden">
            <div className={`h-full ${pct >= 100 ? 'bg-red-500' : pct >= 80 ? 'bg-yellow-400' : 'bg-[#4ade80]'}`} style={{ width: `${pct}%` }} />
          </div>
          {pct >= 100 && <p className="text-xs text-red-400 mt-1">Budget reached: no new analyses until next month or a higher budget.</p>}
        </div>
        <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
          <Tile label="Analyses" value={status.analyses.ok} />
          <Tile label="Determinable" value={status.analyses.determinable} />
          <Tile label="Waiting for batch" value={status.analyses.pending} />
          <Tile label="Failed" value={status.analyses.errors} />
          <Tile label={`Declined (${status.analyses.byFallback} by fallback)`} value={status.analyses.refused} />
          <Tile label="Spent in total" text={usd(status.spentTotal)} />
        </div>
        {status.refusals.length > 0 && (
          <div className="mt-4">
            <h4 className="text-sm font-semibold text-[#a5d6a7] mb-2">Declined and still open</h4>
            <table className="w-full">
              <tbody>
                {status.refusals.map((r) => (
                  <tr key={r.cveId} className="table-row">
                    <td className="py-1.5 px-2 font-mono text-sm">
                      <Link to={`/triage/${encodeURIComponent(r.cveId)}`} className="text-[#e8f5e9] hover:underline">{r.cveId}</Link>
                    </td>
                    <td className="py-1.5 px-2 text-sm text-[#a5d6a7]">{MODEL_NAMES[r.model] || r.model}{r.fallback ? ' (fallback)' : ''}</td>
                    <td className="py-1.5 px-2 text-xs text-[#6b7280] max-w-xl truncate" title={r.error}>{r.error}</td>
                    <td className="py-1.5 px-2 text-xs text-[#6b7280] whitespace-nowrap">{new Date(r.at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {status.lastError && <p className="text-xs text-red-400 mt-3">Last error: {status.lastError}</p>}
        <p className="text-xs text-[#6b7280] mt-3 flex items-center gap-1">
          <LinkIcon className="w-3 h-3" /> The analysis of a CVE is shown on its triage page.
        </p>
      </div>
    </div>
  );
}

function Tile({ label, value, text }: { label: string; value?: number; text?: string }) {
  return (
    <div className="bg-[#1a2420] rounded-lg p-3">
      <div className="text-xl font-bold text-[#e8f5e9]">{text ?? (value ?? 0).toLocaleString()}</div>
      <div className="text-xs text-[#6b7280]">{label}</div>
    </div>
  );
}
