import { useEffect, useState, useCallback, type ReactNode } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Bot, RefreshCw, ShieldAlert, Save, ExternalLink, Sparkles, Cpu } from 'lucide-react';
import { ConfirmModal } from './ConfirmModal';
import {
  getAutoAssessmentStats,
  updateAutoAssessmentConfig,
  reevaluateAutoAssessment,
  getKernelIntelStatus,
  triggerKernelIntelSync,
} from '../api/client';
import type { AutoAssessmentConfig, AutoAssessmentStats, AutoMode, AutoRuleStats, KernelIntelStatus } from '../types';

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
              <h2 className="text-lg font-semibold text-[#e8f5e9]">Rules &amp; Guards</h2>
              <p className="text-sm text-[#6b7280]">
                <span className="text-sky-300">Decides automatically.</span> Deterministic rules dismiss findings that cannot
                affect a server and remove them from the triage queue. Automation only ever sets <em>not relevant</em>;
                everything else stays open for a human, and a human decision always wins.
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

      <KernelDataCard
        settleMinutes={config.factSettleMinutes}
        unusedDays={config.unusedDays}
        onSaveUnused={(d) => save({ unusedDays: d }, 'Observation period saved.')}
        kmodMode={config.rules.find((r) => r.id === 'R-KMOD')?.effectiveMode ?? 'off'}
        saving={saving}
        onSaveSettle={(m) => save({ factSettleMinutes: m }, 'Settle time saved.')}
        onError={setError}
      />

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

// KernelDataCard shows the data R-KMOD relies on (CVE records listing the
// affected source files, mapped kernel builds) and the settle time for
// decisions based on runtime facts.
function KernelDataCard({ settleMinutes, unusedDays, kmodMode, saving, onSaveSettle, onSaveUnused, onError }: {
  settleMinutes: number;
  unusedDays: number;
  onSaveUnused: (days: number) => void;
  kmodMode: AutoMode;
  saving: boolean;
  onSaveSettle: (minutes: number) => void;
  onError: (msg: string) => void;
}) {
  const [status, setStatus] = useState<KernelIntelStatus | null>(null);
  const [settle, setSettle] = useState(String(settleMinutes));
  const [unused, setUnused] = useState(String(unusedDays));

  useEffect(() => setSettle(String(settleMinutes)), [settleMinutes]);
  useEffect(() => setUnused(String(unusedDays)), [unusedDays]);

  const saveUnused = () => {
    const n = parseInt(unused, 10);
    if (isNaN(n) || n < 7 || n > 90) {
      onError('Observation period must be between 7 and 90 days');
      return;
    }
    onSaveUnused(n);
  };

  const load = useCallback(async () => {
    try {
      setStatus(await getKernelIntelStatus());
    } catch (err) {
      onError(err instanceof Error ? err.message : 'Failed to load kernel data status');
    }
  }, [onError]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!status?.running) return;
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [status?.running, load]);

  const sync = async () => {
    try {
      await triggerKernelIntelSync();
      setTimeout(load, 1000);
    } catch (err) {
      onError(err instanceof Error ? err.message : 'Failed to start sync');
    }
  };

  const saveSettle = () => {
    const n = parseInt(settle, 10);
    if (isNaN(n) || n < 0 || n > 10080) {
      onError('Settle time must be between 0 and 10080 minutes');
      return;
    }
    onSaveSettle(n);
  };

  return (
    <div className="card">
      <div className="flex items-start justify-between gap-4 mb-1">
        <div className="flex items-center gap-3">
          <Cpu className="w-5 h-5 text-sky-300" />
          <h3 className="text-lg font-semibold text-[#e8f5e9]">Runtime facts &amp; kernel data</h3>
        </div>
        <button onClick={sync} disabled={kmodMode === 'off' || status?.running} className="btn flex items-center gap-2 bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36]"
          title={kmodMode === 'off' ? 'R-KMOD is off' : 'Fetch missing CVE records and kernel builds now (also runs hourly)'}>
          <RefreshCw className={`w-4 h-4 ${status?.running ? 'animate-spin' : ''}`} /> {status?.running ? 'Syncing…' : 'Sync now'}
        </button>
      </div>
      <p className="text-sm text-[#6b7280] mb-4">
        R-KMOD needs the source files each kernel CVE affects (from the CVE record at cveawg.mitre.org) and, per kernel build the
        servers run, how each file is built (from Ubuntu's kernel headers and module packages on launchpad.net). Both are fetched
        in the background while R-KMOD is not off.
      </p>

      <div className="flex items-start gap-3 mb-5">
        <input type="number" min="0" max="10080" step="10" value={settle} onChange={(e) => setSettle(e.target.value)} className="input w-24" />
        <div className="flex-1">
          <div className="text-[#e8f5e9]">Settle time in minutes</div>
          <div className="text-xs text-[#6b7280]">
            A rule based on runtime facts (loaded modules …) creates a new decision only once the server's facts have been
            unchanged this long. Existing decisions are revoked at once when the facts no longer support them. 0 = no wait.
          </div>
        </div>
        <button onClick={saveSettle} disabled={saving} className="btn btn-primary flex items-center gap-2">
          <Save className="w-4 h-4" /> Save
        </button>
      </div>

      <div className="flex items-start gap-3 mb-5">
        <input type="number" min="7" max="90" step="1" value={unused} onChange={(e) => setUnused(e.target.value)} className="input w-24" />
        <div className="flex-1">
          <div className="text-[#e8f5e9]">R-UNUSED observation period in days</div>
          <div className="text-xs text-[#6b7280]">
            R-UNUSED dismisses a package only after every agent report of this period said which packages were in use, without a gap
            of more than six hours, and none of them used it. The period counts from the start of the observation, not from the
            finding. 14 days or more catches weekly jobs.
          </div>
        </div>
        <button onClick={saveUnused} disabled={saving} className="btn btn-primary flex items-center gap-2">
          <Save className="w-4 h-4" /> Save
        </button>
      </div>

      {status && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
            <Stat label="CVE records with source files" value={status.cves.withData} />
            <Stat label="without source files" value={status.cves.noFiles} hint="(not assigned by the kernel CNA)" />
            <Stat label="Not fetched yet" value={status.cves.pending} />
            <Stat label="Fetch errors" value={status.cves.errors} />
          </div>
          {status.builds.length === 0 ? (
            <p className="text-sm text-[#6b7280]">No kernel build mapped yet. Builds are mapped for servers whose agent reports kernel facts.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-[#2d3f36]">
                    <th className="table-header text-left py-2 px-3">Kernel</th>
                    <th className="table-header text-left py-2 px-3">Build</th>
                    <th className="table-header text-left py-2 px-3">Status</th>
                    <th className="table-header text-right py-2 px-3">Source files</th>
                    <th className="table-header text-left py-2 px-3" title="Module paths checked against linux-modules / linux-modules-extra">Modules verified</th>
                    <th className="table-header text-right py-2 px-3">Servers</th>
                    <th className="table-header text-left py-2 px-3">Mapped</th>
                  </tr>
                </thead>
                <tbody>
                  {status.builds.map((b) => (
                    <tr key={`${b.release}/${b.version}/${b.arch}`} className="table-row">
                      <td className="py-2 px-3 font-mono text-sm text-[#e8f5e9]">{b.release} <span className="text-[#6b7280]">{b.arch}</span></td>
                      <td className="py-2 px-3 font-mono text-sm text-[#a5d6a7]">{b.version}</td>
                      <td className="py-2 px-3 text-sm">
                        {b.status === 'ok' ? <span className="text-[#4ade80]">ok</span> : <span className="text-red-400" title={b.error}>error</span>}
                        {b.error && <div className="text-xs text-red-400/80 max-w-md truncate" title={b.error}>{b.error}</div>}
                      </td>
                      <td className="py-2 px-3 text-right text-sm text-[#e8f5e9]">{b.sourceFiles.toLocaleString()}</td>
                      <td className="py-2 px-3 text-sm">{b.modulesVerified ? <span className="text-[#4ade80]">yes</span> : <span className="text-yellow-400">no</span>}</td>
                      <td className="py-2 px-3 text-right text-sm text-[#e8f5e9]">{b.servers}</td>
                      <td className="py-2 px-3 text-sm text-[#6b7280]">{new Date(b.builtAt).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}

type AutomationSection = 'rules' | 'ai';
const SECTION_STORAGE_KEY = 'vultrack.admin.automationSection';

// AssessmentAutomationTab is the Admin tab for everything that assesses
// findings without a human: rule-based decisions and the AI advisor. The two
// are shown as separate sections because they do different things — rules
// decide, the AI only recommends.
export function AssessmentAutomationTab({ aiSettings }: { aiSettings: ReactNode }) {
  const [params] = useSearchParams();
  const [section, setSection] = useState<AutomationSection>(() => {
    const fromUrl = params.get('section');
    if (fromUrl === 'rules' || fromUrl === 'ai') return fromUrl;
    if (params.get('tab') === 'ai') return 'ai';
    try {
      const stored = window.localStorage.getItem(SECTION_STORAGE_KEY);
      if (stored === 'rules' || stored === 'ai') return stored;
    } catch {
      // storage unavailable
    }
    return 'rules';
  });
  const choose = (s: AutomationSection) => {
    setSection(s);
    try {
      window.localStorage.setItem(SECTION_STORAGE_KEY, s);
    } catch {
      // storage unavailable
    }
  };

  const sections: { id: AutomationSection; icon: typeof Bot; title: string }[] = [
    { id: 'rules', icon: Bot, title: 'Rules & Guards' },
    { id: 'ai', icon: Sparkles, title: 'AI Advisor' },
  ];

  return (
    <div className="space-y-6">
      {/* Sub-navigation: a segmented control, visibly subordinate to the Admin tabs */}
      <div role="tablist" aria-label="Assessment automation" className="inline-flex rounded-lg border border-[#2d3f36] bg-[#111916] p-1">
        {sections.map((s) => {
          const Icon = s.icon;
          const active = section === s.id;
          return (
            <button
              key={s.id}
              role="tab"
              aria-selected={active}
              onClick={() => choose(s.id)}
              className={`flex items-center gap-2 px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
                active ? 'bg-[#4ade80]/15 text-[#4ade80]' : 'text-[#6b7280] hover:text-[#a5d6a7]'
              }`}
            >
              <Icon className="w-4 h-4" />
              {s.title}
            </button>
          );
        })}
      </div>
      {section === 'rules' ? <AutoAssessmentSettings /> : aiSettings}
    </div>
  );
}

