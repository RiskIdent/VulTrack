import { useEffect, useState, useCallback } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { X, Settings } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { getAutoAssessmentStats, getAutoDecisions } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { ModeBadge } from '../components/AutoAssessmentSettings';
import { DecisionStateBadge, EvidenceTable, DecisionTimeline, ServerDecisionActions, StatusPill } from '../components/AutoDecision';
import { Pagination } from '../components/TableControls';
import type { AutoAssessmentConfig, AutoAssessmentStats, AutoDecision } from '../types';

const PAGE_SIZE = 50;

// Review page for automated decisions: what was decided, why, whether it is in
// effect, and how it compares with human assessments.
export default function AutoDecisions() {
  const { user } = useAuth();
  const [params, setParams] = useSearchParams();
  const ruleId = params.get('ruleId') || '';
  const state = params.get('state') || '';
  const guard = params.get('guard') || '';
  const [search, setSearch] = useState(params.get('search') || '');

  const [stats, setStats] = useState<AutoAssessmentStats | null>(null);
  const [config, setConfig] = useState<AutoAssessmentConfig | null>(null);
  const [decisions, setDecisions] = useState<AutoDecision[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<AutoDecision | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  const setParam = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
    setPage(1);
  };

  // Debounced search into the URL.
  useEffect(() => {
    const t = setTimeout(() => {
      if ((params.get('search') || '') !== search.trim()) setParam('search', search.trim());
    }, 300);
    return () => clearTimeout(t);
  }, [search]); // eslint-disable-line react-hooks/exhaustive-deps

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [s, d] = await Promise.all([
        getAutoAssessmentStats(),
        getAutoDecisions({ ruleId, state, guard, search: params.get('search') || '', limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE }),
      ]);
      setStats(s.stats);
      setConfig(s.config);
      setDecisions(d.decisions);
      setTotal(d.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load decisions');
    } finally {
      setLoading(false);
    }
  }, [ruleId, state, guard, params, page]);

  useEffect(() => {
    load();
  }, [load, refreshKey]);

  const t = stats?.total;
  const judged = t ? t.humanAgree + t.humanAccepted + t.humanDisagree : 0;

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[#e8f5e9] flex items-center gap-3">
            Auto Decisions {config && <ModeBadge mode={config.mode} />}
          </h1>
          <p className="text-[#a5d6a7] mt-1">
            Findings dismissed automatically by deterministic rules, per server and CVE, with the reason for every decision
          </p>
        </div>
        {user?.isAdmin !== false && (
          <Link to="/admin?tab=auto&section=rules" className="btn flex items-center gap-2 bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36]">
            <Settings className="w-4 h-4" /> Configure
          </Link>
        )}
      </div>

      {error && <div className="card border-red-600/50 bg-red-600/5 text-red-400">{error}</div>}

      {stats && t && (
        <div className="grid grid-cols-2 lg:grid-cols-6 gap-4">
          <Card label="Decisions" value={t.decisions} onClick={() => setParam('state', '')} active={!state} />
          <Card label="In effect" value={t.applied} onClick={() => setParam('state', 'applied')} active={state === 'applied'} />
          <Card label="Shadow" value={t.shadow} onClick={() => setParam('state', 'shadow')} active={state === 'shadow'} />
          <Card label="Blocked by guard" value={t.blocked} onClick={() => setParam('state', 'blocked')} active={state === 'blocked'} />
          <Card label="Overridden by human" value={t.overridden} onClick={() => setParam('state', 'overridden')} active={state === 'overridden'} />
          <div className="card">
            <div className={`text-2xl font-bold ${t.humanDisagree ? 'text-yellow-400' : 'text-[#4ade80]'}`}>
              {judged ? `${Math.round(((judged - t.humanDisagree) / judged) * 100)}%` : '–'}
            </div>
            <div className="text-sm text-[#6b7280]"
              title={`Decisions where a human assessed the same server: ${t.humanAgree} not relevant, ${t.humanAccepted} accepted risk (no contradiction), ${t.humanDisagree} relevant (contradiction)`}>
              Human agreement {judged ? `(${judged - t.humanDisagree}/${judged})` : ''}
            </div>
          </div>
        </div>
      )}

      {stats && (
        <div className="card">
          <h2 className="text-lg font-semibold text-[#e8f5e9] mb-4">Activity, last 30 days</h2>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={stats.activity}>
                <CartesianGrid strokeDasharray="3 3" stroke="#2d3f36" />
                <XAxis dataKey="date" stroke="#6b7280" tick={{ fontSize: 11 }}
                  tickFormatter={(v) => new Date(v).toLocaleDateString('en', { month: 'short', day: 'numeric' })} />
                <YAxis stroke="#6b7280" allowDecimals={false} />
                <Tooltip contentStyle={{ backgroundColor: '#111916', border: '1px solid #2d3f36', borderRadius: '8px', color: '#e8f5e9' }}
                  itemStyle={{ color: '#a5d6a7' }} labelStyle={{ color: '#e8f5e9' }} />
                <Legend />
                <Bar dataKey="created" name="Decided" fill="#38bdf8" />
                <Bar dataKey="revoked" name="Revoked" fill="#f97316" />
                <Bar dataKey="overrides" name="Human per-server decisions" fill="#a5d6a7" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      <div className="card">
        <div className="flex flex-wrap items-end gap-4 mb-4">
          <div>
            <label className="block text-sm text-[#a5d6a7] mb-1">Rule</label>
            <select className="input" value={ruleId} onChange={(e) => setParam('ruleId', e.target.value)}>
              <option value="">All rules</option>
              {config?.rules.map((r) => <option key={r.id} value={r.id}>{r.id}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-sm text-[#a5d6a7] mb-1">State</label>
            <select className="input" value={state} onChange={(e) => setParam('state', e.target.value)}>
              <option value="">All</option>
              <option value="applied">In effect</option>
              <option value="shadow">Shadow</option>
              <option value="blocked">Blocked by guard</option>
              <option value="overridden">Overridden by human</option>
              <option value="rejected">Automation off for server</option>
            </select>
          </div>
          <div>
            <label className="block text-sm text-[#a5d6a7] mb-1">Guard</label>
            <select className="input" value={guard} onChange={(e) => setParam('guard', e.target.value)}>
              <option value="">Any</option>
              <option value="G-KEV">G-KEV</option>
              <option value="G-EXPLOIT">G-EXPLOIT</option>
              <option value="G-EPSS">G-EPSS</option>
            </select>
          </div>
          <div className="flex-1 min-w-[14rem]">
            <label className="block text-sm text-[#a5d6a7] mb-1">Search</label>
            <input className="input w-full" placeholder="CVE ID or server" value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
          <div className="text-sm text-[#6b7280] pb-2">{total.toLocaleString()} decisions</div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#2d3f36]">
                <th className="table-header text-left py-3 px-3">CVE</th>
                <th className="table-header text-left py-3 px-3">Server</th>
                <th className="table-header text-left py-3 px-3">Rules</th>
                <th className="table-header text-left py-3 px-3">State</th>
                <th className="table-header text-left py-3 px-3">Human</th>
                <th className="table-header text-left py-3 px-3">Reason</th>
                <th className="table-header text-left py-3 px-3">Updated</th>
              </tr>
            </thead>
            <tbody className={loading ? 'opacity-50' : ''}>
              {decisions.map((d) => (
                <tr key={`${d.serverId}|${d.cveId}`} className="table-row cursor-pointer hover:bg-[#1a2420]" onClick={() => setSelected(d)}>
                  <td className="py-2 px-3 font-mono text-[#4ade80] whitespace-nowrap">{d.cveId}</td>
                  <td className="py-2 px-3 text-[#e8f5e9] whitespace-nowrap">{d.serverName}</td>
                  <td className="py-2 px-3 font-mono text-xs text-[#a5d6a7] whitespace-nowrap">{d.ruleIds.join(', ')}</td>
                  <td className="py-2 px-3"><DecisionStateBadge state={d.state} /></td>
                  <td className="py-2 px-3">{d.humanStatus ? <StatusPill status={d.humanStatus} /> : <span className="text-xs text-[#6b7280]">–</span>}</td>
                  <td className="py-2 px-3 text-xs text-[#a5d6a7] max-w-md truncate" title={d.reason}>{d.reason}</td>
                  <td className="py-2 px-3 text-xs text-[#6b7280] whitespace-nowrap">{new Date(d.updatedAt).toLocaleString()}</td>
                </tr>
              ))}
              {!loading && decisions.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-10 text-center text-[#6b7280]">
                    {config?.mode === 'off' ? 'Automated assessment is off.' : 'No decisions match the filters.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <Pagination page={page} pageSize={PAGE_SIZE} total={total} noun="decisions" onPage={setPage} />
      </div>

      {selected && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" onClick={() => setSelected(null)}>
          <div className="bg-[#0d1512] border border-[#2d3f36] rounded-lg max-w-3xl w-full max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <div className="sticky top-0 bg-[#0d1512] border-b border-[#2d3f36] p-5 flex items-center justify-between">
              <div>
                <h2 className="text-xl font-bold text-[#e8f5e9] font-mono">{selected.cveId}</h2>
                <div className="text-sm text-[#a5d6a7]">on {selected.serverName}</div>
              </div>
              <button onClick={() => setSelected(null)} className="text-[#6b7280] hover:text-[#e8f5e9]"><X className="w-6 h-6" /></button>
            </div>
            <div className="p-5 space-y-6">
              <div className="flex flex-wrap items-center gap-2">
                <DecisionStateBadge state={selected.state} />
                <span className="text-sm text-[#a5d6a7]">Verdict: not relevant · decided {new Date(selected.decidedAt).toLocaleString()}</span>
                {selected.humanStatus && <span className="text-sm text-[#a5d6a7]">· human: <StatusPill status={selected.humanStatus} /></span>}
              </div>
              <section>
                <h3 className="text-sm font-semibold text-[#e8f5e9] mb-2">Why</h3>
                <EvidenceTable evidence={selected.evidence} />
              </section>
              <section>
                <h3 className="text-sm font-semibold text-[#e8f5e9] mb-2">Decide for this server</h3>
                <ServerDecisionActions
                  serverId={selected.serverId}
                  cveId={selected.cveId}
                  onChanged={() => { setRefreshKey((k) => k + 1); setSelected(null); }}
                />
                <p className="text-xs text-[#6b7280] mt-2">
                  A per-server decision always wins over automation. To assess the CVE for all servers, open it from the{' '}
                  <Link className="text-[#4ade80] hover:underline" to="/triage">triage queue</Link> or see all its{' '}
                  <Link className="text-[#4ade80] hover:underline" to={`/findings?search=${encodeURIComponent(selected.cveId)}`}>findings</Link>.
                </p>
              </section>
              <section>
                <h3 className="text-sm font-semibold text-[#e8f5e9] mb-2">History</h3>
                <DecisionTimeline serverId={selected.serverId} cveId={selected.cveId} refreshKey={refreshKey} />
              </section>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Card({ label, value, onClick, active }: { label: string; value: number; onClick: () => void; active: boolean }) {
  return (
    <button onClick={onClick} className={`card text-left transition-colors ${active ? 'border-[#4ade80]/60' : 'hover:border-[#4ade80]/30'}`}>
      <div className="text-2xl font-bold text-[#e8f5e9]">{value.toLocaleString()}</div>
      <div className="text-sm text-[#6b7280]">{label}</div>
    </button>
  );
}
