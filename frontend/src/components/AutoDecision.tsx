import { Fragment, useEffect, useState } from 'react';
import { Bot, User, History } from 'lucide-react';
import { getDecisionEvents, setServerAssessment, deleteServerAssessment } from '../api/client';
import { useAuth } from '../context/AuthContext';
import type { DecisionBadge, DecisionEvent, DecisionState, ServerOverrideStatus, ServerStatus, DecisionEvidence } from '../types';

// Building blocks for automated decisions, shared by the Auto Decisions page,
// the findings list and the triage detail page.

const stateStyle: Record<DecisionState, { label: string; cls: string; title: string }> = {
  applied: { label: 'auto: not relevant', cls: 'bg-sky-600/20 text-sky-300 border-sky-600/40', title: 'Automated decision in effect: the server is not in the triage queue for this CVE.' },
  shadow: { label: 'auto (shadow)', cls: 'bg-purple-600/20 text-purple-300 border-purple-600/40', title: 'Computed but not in effect (shadow mode).' },
  blocked: { label: 'auto: blocked', cls: 'bg-red-600/20 text-red-300 border-red-600/40', title: 'A rule would dismiss it, but a guard (CISA KEV, verified exploit, EPSS) blocks the dismissal.' },
  rejected: { label: 'auto: off for server', cls: 'bg-gray-600/20 text-gray-300 border-gray-600/40', title: 'A human switched automation off for this server.' },
  overridden: { label: 'auto: overridden', cls: 'bg-gray-600/20 text-gray-300 border-gray-600/40', title: 'A human decided for this server, or the CVE assessment is binding for all servers.' },
};

export function DecisionStateBadge({ state }: { state: DecisionState }) {
  const s = stateStyle[state];
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium border whitespace-nowrap ${s.cls}`} title={s.title}>
      <Bot className="w-3 h-3" />{s.label}
    </span>
  );
}

// AutoDecisionBadge is the compact form shown next to a finding.
export function AutoDecisionBadge({ decision }: { decision?: DecisionBadge }) {
  if (!decision) return null;
  const s = stateStyle[decision.state];
  const title = `${s.title} Rules: ${decision.ruleIds.join(', ')}${decision.guards?.length ? `. Guards: ${decision.guards.join(', ')}` : ''}`;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium border whitespace-nowrap ${s.cls}`} title={title}>
      <Bot className="w-3 h-3" />{decision.ruleIds.join(', ')}{decision.state !== 'applied' && <span className="opacity-75">· {decision.state}</span>}
    </span>
  );
}

const statusLabel: Record<string, string> = {
  open: 'Open', not_relevant: 'Not relevant', relevant: 'Relevant', accepted_risk: 'Accepted risk', pending: 'Pending', manual: 'Manual',
};
const statusCls: Record<string, string> = {
  open: 'bg-yellow-600/20 text-yellow-300 border-yellow-600/40',
  pending: 'bg-yellow-600/20 text-yellow-300 border-yellow-600/40',
  not_relevant: 'bg-green-600/20 text-green-300 border-green-600/40',
  relevant: 'bg-red-600/20 text-red-300 border-red-600/40',
  accepted_risk: 'bg-orange-600/20 text-orange-300 border-orange-600/40',
  manual: 'bg-gray-600/20 text-gray-300 border-gray-600/40',
};
export function StatusPill({ status }: { status: string }) {
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium border whitespace-nowrap ${statusCls[status] || statusCls.open}`}>
      {statusLabel[status] || status}
    </span>
  );
}

const sourceLabel: Record<ServerStatus['source'], string> = {
  override: 'decided for this server',
  binding: 'binding CVE assessment',
  auto: 'automated decision',
  assessment: 'CVE assessment',
  none: 'not yet assessed',
};
export function sourceText(s: ServerStatus['source']) {
  return sourceLabel[s];
}

// EvidenceTable lists which rule dismissed which package.
export function EvidenceTable({ evidence }: { evidence?: DecisionEvidence }) {
  if (!evidence?.packages?.length) return null;
  return (
    <div className="space-y-2">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[#2d3f36] text-left text-xs text-[#6b7280] uppercase">
            <th className="py-1 pr-3">Package</th><th className="py-1 pr-3">Rule</th><th className="py-1">Why</th>
          </tr>
        </thead>
        <tbody>
          {evidence.packages.map((p) => (
            <tr key={p.package} className="border-b border-[#1a2420]">
              <td className="py-1 pr-3 font-mono text-[#e8f5e9]">{p.package} <span className="text-xs text-[#6b7280]">{p.version}</span></td>
              <td className="py-1 pr-3 font-mono text-[#a5d6a7] whitespace-nowrap">{p.rule} v{p.ruleVersion}</td>
              <td className="py-1 text-[#a5d6a7]">{p.detail}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {evidence.guards?.map((g) => (
        <div key={g.id} className="text-sm text-red-300">Blocked by {g.id}: {g.detail}</div>
      ))}
    </div>
  );
}

const eventLabel: Record<DecisionEvent['event'], string> = {
  auto_created: 'Automated decision made',
  auto_changed: 'Automated decision changed',
  auto_revoked: 'Automated decision revoked',
  override_set: 'Decided for this server',
  override_removed: 'Per-server decision removed',
};

// DecisionTimeline shows the audit trail of one server and CVE.
export function DecisionTimeline({ serverId, cveId, refreshKey }: { serverId: number; cveId: string; refreshKey?: number }) {
  const [events, setEvents] = useState<DecisionEvent[] | null>(null);
  useEffect(() => {
    getDecisionEvents({ serverId, cveId, limit: 50 })
      .then((d) => setEvents(d.events))
      .catch(() => setEvents([]));
  }, [serverId, cveId, refreshKey]);

  if (events === null) return <div className="text-sm text-[#6b7280]">Loading history...</div>;
  if (events.length === 0) return <div className="text-sm text-[#6b7280]">No decisions recorded yet.</div>;
  return (
    <ol className="space-y-2">
      {events.map((e) => {
        // Who acted follows from the event type, not from whether a name was recorded.
        const human = e.event.startsWith('override');
        return (
        <li key={e.id} className="flex gap-3 text-sm">
          <span className="mt-0.5">{human ? <User className="w-4 h-4 text-[#a5d6a7]" /> : <Bot className="w-4 h-4 text-sky-300" />}</span>
          <div>
            <div className="text-[#e8f5e9]">
              {eventLabel[e.event]}
              {e.event === 'override_set' && e.verdict && <>: <StatusPill status={e.verdict} /></>}
              {e.ruleIds?.length ? <span className="font-mono text-xs text-[#a5d6a7] ml-2">{e.ruleIds.join(', ')}</span> : null}
              {e.guards?.length ? <span className="text-xs text-red-300 ml-2">blocked by {e.guards.join(', ')}</span> : null}
            </div>
            <div className="text-xs text-[#6b7280]">
              {new Date(e.createdAt).toLocaleString()} · {human ? (e.actor || 'unknown user') : 'automation'}
            </div>
            {e.reason && <div className="text-xs text-[#a5d6a7] mt-0.5">{e.reason}</div>}
          </div>
        </li>
        );
      })}
    </ol>
  );
}

// ServerDecisionActions lets a human decide a CVE for one server, or remove
// that decision again.
export function ServerDecisionActions({ serverId, cveId, current, onChanged }: {
  serverId: number;
  cveId: string;
  current?: ServerOverrideStatus;
  onChanged: () => void;
}) {
  const { user } = useAuth();
  // Same fallback as CVE assessments when authentication is disabled.
  const actor = user?.name || user?.email || 'anonymous';
  const [status, setStatus] = useState<ServerOverrideStatus>(current || 'not_relevant');
  const [comment, setComment] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async (f: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await f();
      setComment('');
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <select className="input py-1" value={status} onChange={(e) => setStatus(e.target.value as ServerOverrideStatus)}>
          <option value="not_relevant">Not relevant on this server</option>
          <option value="relevant">Relevant on this server</option>
          <option value="accepted_risk">Accept risk on this server</option>
          <option value="manual">No automation for this server (decide manually)</option>
        </select>
        <input
          className="input py-1 flex-1 min-w-[12rem]"
          placeholder="Reason (recommended)"
          value={comment}
          onChange={(e) => setComment(e.target.value)}
        />
        <button
          className="btn btn-primary py-1"
          disabled={busy}
          onClick={() => run(() => setServerAssessment(serverId, cveId, { status, comment, assessedBy: actor }))}
        >
          Save for this server
        </button>
        {current && (
          <button
            className="btn py-1 bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36]"
            disabled={busy}
            onClick={() => run(() => deleteServerAssessment(serverId, cveId, actor))}
            title="The server follows automation and the CVE assessment again"
          >
            Remove server decision
          </button>
        )}
      </div>
      {error && <div className="text-sm text-red-400">{error}</div>}
    </div>
  );
}

// HistoryToggle is a small button that reveals the decision timeline.
export function HistoryToggle({ serverId, cveId, refreshKey }: { serverId: number; cveId: string; refreshKey?: number }) {
  const [open, setOpen] = useState(false);
  return (
    <div>
      <button className="inline-flex items-center gap-1 text-xs text-[#a5d6a7] hover:text-[#4ade80]" onClick={() => setOpen((o) => !o)}>
        <History className="w-3.5 h-3.5" /> {open ? 'Hide history' : 'History'}
      </button>
      {open && <div className="mt-2"><DecisionTimeline serverId={serverId} cveId={cveId} refreshKey={refreshKey} /></div>}
    </div>
  );
}

// CVEServerStatusCard lists every affected server of a CVE with its effective
// status, where it comes from, the automated decision and per-server actions.
export function CVEServerStatusCard({ cveId, servers, onChanged }: {
  cveId: string;
  servers: ServerStatus[] | null;
  onChanged: () => void;
}) {
  const [expanded, setExpanded] = useState<number | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  if (servers === null) {
    return <div className="card text-[#a5d6a7]">Loading servers...</div>;
  }
  const counts = servers.reduce<Record<string, number>>((acc, s) => {
    acc[s.status] = (acc[s.status] || 0) + 1;
    return acc;
  }, {});
  const auto = servers.filter((s) => s.source === 'auto').length;

  return (
    <div className="card">
      <div className="flex flex-wrap items-baseline justify-between gap-2 mb-3">
        <h2 className="text-lg font-semibold text-[#e8f5e9]">Affected Servers ({servers.length})</h2>
        <div className="flex flex-wrap gap-2 text-xs">
          {Object.entries(counts).map(([st, n]) => (
            <span key={st} className="flex items-center gap-1"><StatusPill status={st} /> {n}</span>
          ))}
          {auto > 0 && <span className="text-sky-300">{auto} dismissed automatically</span>}
        </div>
      </div>
      <div className="overflow-x-auto max-h-[28rem] overflow-y-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-[#2d3f36]">
              <th className="table-header text-left py-2 px-3">Server</th>
              <th className="table-header text-left py-2 px-3">Packages</th>
              <th className="table-header text-left py-2 px-3">Status</th>
              <th className="table-header text-left py-2 px-3">Automation</th>
              <th className="table-header py-2 px-3"></th>
            </tr>
          </thead>
          <tbody>
            {servers.map((s) => (
              <Fragment key={s.serverId}>
                <tr className="table-row align-top">
                  <td className="py-2 px-3 text-[#e8f5e9] whitespace-nowrap">{s.serverName}</td>
                  <td className="py-2 px-3 font-mono text-xs text-[#a5d6a7]">{s.packages.join(', ')}</td>
                  <td className="py-2 px-3">
                    <StatusPill status={s.status} />
                    <div className="text-xs text-[#6b7280] mt-1">{sourceText(s.source)}</div>
                    {s.override?.comment && <div className="text-xs text-[#a5d6a7] mt-1" title={s.override.assessedBy}>“{s.override.comment}”</div>}
                  </td>
                  <td className="py-2 px-3">
                    {s.decision ? (
                      <div className="space-y-1">
                        <DecisionStateBadge state={s.decision.state} />
                        <div className="font-mono text-xs text-[#a5d6a7]">{s.decision.ruleIds.join(', ')}</div>
                      </div>
                    ) : (
                      <span className="text-xs text-[#6b7280]">no rule applies</span>
                    )}
                  </td>
                  <td className="py-2 px-3 text-right">
                    <button className="text-xs text-[#4ade80] hover:underline whitespace-nowrap"
                      onClick={() => setExpanded(expanded === s.serverId ? null : s.serverId)}>
                      {expanded === s.serverId ? 'Close' : 'Details / decide'}
                    </button>
                  </td>
                </tr>
                {expanded === s.serverId && (
                  <tr className="bg-[#0a0f0d]">
                    <td colSpan={5} className="p-4 space-y-4">
                      {s.decision && (
                        <div>
                          <div className="text-xs text-[#6b7280] uppercase tracking-wide mb-1">Automated decision</div>
                          <EvidenceTable evidence={s.decision.evidence} />
                        </div>
                      )}
                      <div>
                        <div className="text-xs text-[#6b7280] uppercase tracking-wide mb-1">Decide for this server only</div>
                        <ServerDecisionActions
                          serverId={s.serverId}
                          cveId={cveId}
                          current={s.override?.status}
                          onChanged={() => { setRefreshKey((k) => k + 1); onChanged(); }}
                        />
                      </div>
                      <div>
                        <div className="text-xs text-[#6b7280] uppercase tracking-wide mb-1">History</div>
                        <DecisionTimeline serverId={s.serverId} cveId={cveId} refreshKey={refreshKey} />
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
