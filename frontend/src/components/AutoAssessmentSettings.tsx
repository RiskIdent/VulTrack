import { useEffect, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { Bot, RefreshCw, ShieldAlert, Save, ExternalLink } from 'lucide-react';
import { ConfirmModal } from './ConfirmModal';
import {
  getAutoAssessmentStats,
  updateAutoAssessmentConfig,
  reevaluateAutoAssessment,
} from '../api/client';
import type { AutoAssessmentConfig, AutoAssessmentStats, AutoMode, AutoRuleStats } from '../types';

const MODES: { id: AutoMode; label: string; text: string }[] = [
  { id: 'off', label: 'Off', text: 'No automated decisions. The triage queue works exactly as without this feature.' },
  { id: 'shadow', label: 'Shadow', text: 'Decisions are computed and shown everywhere, but none take effect. Use this to review the rules.' },
  { id: 'active', label: 'Active', text: 'Decisions of rules set to "active" remove servers from the triage queue. Other rules stay in shadow mode.' },
];

const modeBadge: Record<AutoMode, string> = {
  off: 'bg-gray-600/20 text-gray-400 border-gray-600/40',
  shadow: 'bg-purple-600/20 text-purple-300 border-purple-600/40',
  active: 'bg-[#4ade80]/20 text-[#4ade80] border-[#4ade80]/40',
};

export function ModeBadge({ mode }: { mode: AutoMode }) {
  return <span className={`px-2 py-0.5 rounded text-xs font-medium border ${modeBadge[mode]}`}>{mode}</span>;
}

// agreement renders "x of y" with a percentage, or a dash without data.
function agreement(r?: AutoRuleStats) {
  if (!r) return <span className="text-[#6b7280]">–</span>;
  const judged = r.humanAgree + r.humanDisagree;
  if (judged === 0) return <span className="text-[#6b7280]" title="No human assessment on the same servers yet">no data</span>;
  const pct = Math.round((r.humanAgree / judged) * 100);
  const cls = r.humanDisagree === 0 ? 'text-[#4ade80]' : pct >= 95 ? 'text-yellow-400' : 'text-red-400';
  return (
    <span className={cls} title={`${r.humanAgree} agree, ${r.humanDisagree} disagree (a human assessed the server as relevant or accepted risk)`}>
      {pct}% ({r.humanAgree}/{judged})
    </span>
  );
}

// Admin tab: configure and review the automated assessment.
export default function AutoAssessmentSettings() {
  const [config, setConfig] = useState<AutoAssessmentConfig | null>(null);
  const [stats, setStats] = useState<AutoAssessmentStats | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [guardExploit, setGuardExploit] = useState(true);
  const [guardEpssPct, setGuardEpssPct] = useState('10');
  const [confirm, setConfirm] = useState<{ title: string; message: string; run: () => void } | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await getAutoAssessmentStats();
      setConfig(data.config);
      setStats(data.stats);
      setGuardExploit(data.config.guardExploit);
      setGuardEpssPct(String(Math.round(data.config.guardEpss * 1000) / 10));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load automated assessment');
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const flash = (msg: string) => {
    setNotice(msg);
    setTimeout(() => setNotice(null), 4000);
  };

  const save = async (data: Parameters<typeof updateAutoAssessmentConfig>[0], msg: string) => {
    setSaving(true);
    setError(null);
    try {
      const updated = await updateAutoAssessmentConfig(data);
      setConfig(updated);
      flash(msg + ' All servers are being re-evaluated in the background.');
      setTimeout(load, 2500);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save');
    } finally {
      setSaving(false);
    }
  };

  const ruleModes = () => Object.fromEntries((config?.rules || []).map((r) => [r.id, r.mode])) as Record<string, AutoMode>;

  const setGlobalMode = (mode: AutoMode) => {
    if (!config || mode === config.mode) return;
    const run = () => save({ mode }, `Mode set to ${mode}.`);
    if (mode === 'active') {
      const active = config.rules.filter((r) => r.mode === 'active').map((r) => r.id);
      setConfirm({
        title: 'Activate automated assessment?',
        message: active.length
          ? `Decisions of ${active.join(', ')} will take effect immediately and remove servers from the triage queue.`
          : 'No rule is set to "active" yet, so nothing changes until you activate a rule.',
        run,
      });
    } else {
      run();
    }
  };

  const setRuleMode = (ruleId: string, mode: AutoMode) => {
    const run = () => save({ ruleModes: { ...ruleModes(), [ruleId]: mode } }, `${ruleId} set to ${mode}.`);
    if (mode === 'active') {
      const r = stats?.rules?.find((x) => x.ruleId === ruleId);
      const lines = [`${ruleId} decisions will remove servers from the triage queue${config?.mode === 'active' ? '' : ' once the global mode is active'}.`];
      if (r) {
        lines.push(`Currently ${r.decisions} decisions, ${r.blocked} blocked by guards.`);
        if (r.humanDisagree > 0) {
          lines.push(`Warning: on ${r.humanDisagree} server(s) a human assessed the CVE as relevant or accepted risk. Review them on the Auto Decisions page first.`);
        } else if (r.humanAgree === 0) {
          lines.push('No human assessment on the same servers yet to compare with.');
        }
      }
      setConfirm({ title: `Activate ${ruleId}?`, message: lines.join(' '), run });
    } else {
      run();
    }
  };

  const saveGuards = () => {
    const pct = parseFloat(guardEpssPct);
    if (isNaN(pct) || pct < 0 || pct > 100) {
      setError('EPSS threshold must be between 0 and 100 %');
      return;
    }
    save({ guardExploit, guardEpss: pct / 100 }, 'Guards saved.');
  };

  const reevaluate = async () => {
    try {
      await reevaluateAutoAssessment();
      flash('Re-evaluation of all servers started.');
      setTimeout(load, 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start re-evaluation');
    }
  };

  if (!config) {
    return <div className="text-[#a5d6a7]">{error || 'Loading...'}</div>;
  }
  const ruleStats = (id: string) => stats?.rules?.find((r) => r.ruleId === id);

  return (
    <div className="space-y-6">
      {error && <div className="p-3 rounded-lg border border-red-600/50 bg-red-600/5 text-red-400">{error}</div>}
      {notice && <div className="p-3 rounded-lg border border-[#4ade80]/40 bg-[#4ade80]/10 text-[#4ade80]">{notice}</div>}

      {/* Global mode */}
      <div className="card">
        <div className="flex items-start justify-between gap-4 mb-4">
          <div className="flex items-center gap-3">
            <Bot className="w-6 h-6 text-[#4ade80]" />
            <div>
              <h2 className="text-lg font-semibold text-[#e8f5e9]">Automated Assessment</h2>
              <p className="text-sm text-[#6b7280]">
                Deterministic rules dismiss findings that cannot affect a server. Automation only ever sets
                &nbsp;<em>not relevant</em>; everything else stays open for a human, and a human decision always wins.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <Link to="/auto-decisions" className="btn flex items-center gap-2 bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36]">
              <ExternalLink className="w-4 h-4" /> Review decisions
            </Link>
            <button onClick={reevaluate} disabled={config.mode === 'off'} className="btn btn-primary flex items-center gap-2"
              title="Re-evaluate every server now (also happens after each scan and data sync)">
              <RefreshCw className="w-4 h-4" /> Re-evaluate
            </button>
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {MODES.map((m) => (
            <button
              key={m.id}
              disabled={saving}
              onClick={() => setGlobalMode(m.id)}
              className={`text-left p-4 rounded-lg border transition-colors ${
                config.mode === m.id ? 'border-[#4ade80] bg-[#4ade80]/10' : 'border-[#2d3f36] bg-[#1a2420] hover:border-[#4ade80]/40'
              }`}
            >
              <div className="flex items-center gap-2 mb-1">
                <span className={`w-3 h-3 rounded-full border ${config.mode === m.id ? 'bg-[#4ade80] border-[#4ade80]' : 'border-[#6b7280]'}`} />
                <span className="font-semibold text-[#e8f5e9]">{m.label}</span>
              </div>
              <p className="text-xs text-[#a5d6a7]">{m.text}</p>
            </button>
          ))}
        </div>
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4">
            <Stat label="Decisions stored" value={stats.total.decisions} />
            <Stat label="In effect" value={stats.total.applied} />
            <Stat label="Blocked by guards" value={stats.total.blocked} />
            <Stat label="Open server/CVE pairs" value={stats.openPairs} hint={`of ${stats.totalPairs.toLocaleString()} with active findings`} />
          </div>
        )}
      </div>

      {/* Rules */}
      <div className="card">
        <h3 className="text-lg font-semibold text-[#e8f5e9] mb-1">Rules</h3>
        <p className="text-sm text-[#6b7280] mb-4">
          A server/CVE pair is dismissed only when every active finding of the CVE on that server is dismissed by a rule.
          Run a rule in shadow mode and compare it with human assessments before activating it.
        </p>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#2d3f36]">
                <th className="table-header text-left py-3 px-3">Rule</th>
                <th className="table-header text-left py-3 px-3">Mode</th>
                <th className="table-header text-right py-3 px-3">Decisions</th>
                <th className="table-header text-right py-3 px-3">In effect</th>
                <th className="table-header text-right py-3 px-3">Blocked</th>
                <th className="table-header text-right py-3 px-3" title="Agreement with human assessments of the same servers">Human agreement</th>
              </tr>
            </thead>
            <tbody>
              {config.rules.map((r) => {
                const st = ruleStats(r.id);
                return (
                  <tr key={r.id} className="table-row align-top">
                    <td className="py-3 px-3 max-w-xl">
                      <div className="font-mono text-[#e8f5e9]">{r.id} <span className="text-xs text-[#6b7280]">v{r.version}</span></div>
                      <div className="text-xs text-[#a5d6a7] mt-1">{r.description}</div>
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      <select
                        className="input py-1"
                        value={r.mode}
                        disabled={saving}
                        onChange={(e) => setRuleMode(r.id, e.target.value as AutoMode)}
                      >
                        <option value="off">off</option>
                        <option value="shadow">shadow</option>
                        <option value="active">active</option>
                      </select>
                      {r.effectiveMode !== r.mode && (
                        <div className="text-xs text-[#6b7280] mt-1">effective: <ModeBadge mode={r.effectiveMode} /></div>
                      )}
                    </td>
                    <td className="py-3 px-3 text-right text-[#e8f5e9]">
                      <Link to={`/auto-decisions?ruleId=${r.id}`} className="hover:underline">{st?.decisions ?? 0}</Link>
                    </td>
                    <td className="py-3 px-3 text-right text-[#e8f5e9]">{st?.applied ?? 0}</td>
                    <td className="py-3 px-3 text-right text-[#e8f5e9]">{st?.blocked ?? 0}</td>
                    <td className="py-3 px-3 text-right text-sm">{agreement(st)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Guards */}
      <div className="card">
        <div className="flex items-center gap-3 mb-1">
          <ShieldAlert className="w-5 h-5 text-red-400" />
          <h3 className="text-lg font-semibold text-[#e8f5e9]">Guards</h3>
        </div>
        <p className="text-sm text-[#6b7280] mb-4">
          A guard blocks automated dismissal of a CVE, whatever the rules say. A human can still assess it as not relevant.
        </p>
        <div className="space-y-3">
          <label className="flex items-start gap-3">
            <input type="checkbox" checked disabled className="w-4 h-4 mt-1" />
            <div>
              <div className="text-[#e8f5e9]">G-KEV — listed in CISA KEV <span className="text-xs text-[#6b7280]">(always on)</span></div>
              <div className="text-xs text-[#6b7280]">Exploited in the wild. A CVE that enters the catalog reopens every automated dismissal at the next sync.</div>
            </div>
          </label>
          <label className="flex items-start gap-3 cursor-pointer">
            <input type="checkbox" checked={guardExploit} onChange={(e) => setGuardExploit(e.target.checked)} className="w-4 h-4 mt-1" />
            <div>
              <div className="text-[#e8f5e9]">G-EXPLOIT — verified public exploit</div>
              <div className="text-xs text-[#6b7280]">A verified exploit for the CVE is listed in ExploitDB.</div>
            </div>
          </label>
          <div className="flex items-start gap-3">
            <input
              type="number" min="0" max="100" step="1"
              value={guardEpssPct}
              onChange={(e) => setGuardEpssPct(e.target.value)}
              className="input w-24"
            />
            <div>
              <div className="text-[#e8f5e9]">G-EPSS — EPSS threshold in %</div>
              <div className="text-xs text-[#6b7280]">Block dismissal when the probability of exploitation in the next 30 days is at least this high. 0 switches the guard off.</div>
            </div>
          </div>
          {stats && Object.keys(stats.guards).length > 0 && (
            <div className="text-xs text-[#a5d6a7]">
              Currently blocking: {Object.entries(stats.guards).map(([g, n]) => `${g} ${n}`).join(' · ')}
            </div>
          )}
          <button onClick={saveGuards} disabled={saving} className="btn btn-primary flex items-center gap-2">
            <Save className="w-4 h-4" /> Save guards
          </button>
        </div>
      </div>

      <ConfirmModal
        isOpen={confirm !== null}
        title={confirm?.title || ''}
        message={confirm?.message || ''}
        confirmLabel="Activate"
        variant="warning"
        onConfirm={() => {
          confirm?.run();
          setConfirm(null);
        }}
        onCancel={() => setConfirm(null)}
      />
    </div>
  );
}

function Stat({ label, value, hint }: { label: string; value: number; hint?: string }) {
  return (
    <div className="bg-[#1a2420] rounded-lg p-3">
      <div className="text-xl font-bold text-[#e8f5e9]">{value.toLocaleString()}</div>
      <div className="text-xs text-[#6b7280]">{label}{hint ? ` ${hint}` : ''}</div>
    </div>
  );
}
