import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { AlertTriangle } from 'lucide-react';
import { getStaleServers } from '../api/client';
import type { Server } from '../types';

// formatAge renders seconds as "12 min", "5 h" or "3 days".
export function formatAge(seconds: number): string {
  if (seconds < 3600) return `${Math.max(1, Math.round(seconds / 60))} min`;
  if (seconds < 48 * 3600) return `${Math.round(seconds / 3600)} h`;
  return `${Math.floor(seconds / 86400)} days`;
}

// ServerStatusBadge marks disabled servers and servers without a recent agent report.
export function ServerStatusBadge({ server }: { server: Pick<Server, 'stale' | 'disabledAt'> }) {
  if (server.disabledAt) {
    return <span className="px-1.5 py-0.5 rounded text-[10px] font-medium border bg-gray-600/20 text-gray-400 border-gray-600/40">disabled</span>;
  }
  if (server.stale) {
    return <span className="px-1.5 py-0.5 rounded text-[10px] font-medium border bg-red-600/20 text-red-400 border-red-600/40">no report</span>;
  }
  return null;
}

// LastReport shows how long ago the agent last reported, highlighted when stale.
export function LastReport({ server }: { server: Server }) {
  const title = server.lastReportAt ? new Date(server.lastReportAt).toLocaleString() : 'never';
  const cls = server.disabledAt ? 'text-[#6b7280]' : server.stale ? 'text-red-400 font-medium' : 'text-[#a5d6a7]';
  return <span className={cls} title={`Last agent report: ${title}`}>{formatAge(server.reportAgeSeconds)} ago</span>;
}

// StaleServersWarning lists enabled servers without a recent agent report.
// It renders nothing when there are none or the warnings are off.
export function StaleServersWarning() {
  const [data, setData] = useState<{ servers: Server[]; thresholdHours: number } | null>(null);
  useEffect(() => {
    let cancelled = false;
    getStaleServers().then((d) => !cancelled && setData(d)).catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, []);
  if (!data || data.servers.length === 0) return null;
  const shown = data.servers.slice(0, 5);
  return (
    <div className="card border-red-600/50 bg-red-600/5">
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 mt-0.5 shrink-0" />
          <div>
            <h3 className="font-semibold text-red-400">
              {data.servers.length} server{data.servers.length === 1 ? '' : 's'} without agent report for more than {data.thresholdHours} h
            </h3>
            <p className="text-sm text-[#a5d6a7] mt-1">
              Their findings may be out of date. Servers switched off on purpose can be marked as disabled under Admin → Servers.
            </p>
            <ul className="mt-2 text-sm space-y-0.5">
              {shown.map((s) => (
                <li key={s.id}>
                  <Link to={`/servers/${s.id}`} className="text-[#e8f5e9] hover:underline">{s.name}</Link>
                  <span className="text-[#6b7280]"> · last report {formatAge(s.reportAgeSeconds)} ago</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
        <Link to="/servers?status=stale" className="btn shrink-0 bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36]">
          Show all
        </Link>
      </div>
    </div>
  );
}

// ServerReportBanner warns on a server's page when it is disabled or silent.
export function ServerReportBanner({ server, thresholdHours }: { server: Server; thresholdHours?: number }) {
  if (server.disabledAt) {
    return (
      <div className="p-3 rounded-lg border border-gray-600/40 bg-gray-600/10 text-sm text-gray-300">
        This server is marked as disabled{server.disabledBy ? ` by ${server.disabledBy}` : ''} since{' '}
        {new Date(server.disabledAt).toLocaleDateString()}: no warnings, and its findings are not in the triage queue.
        {!server.stale && server.reportAgeSeconds < 3600 && ' It has reported again recently.'}
      </div>
    );
  }
  if (!server.stale) return null;
  return (
    <div className="p-3 rounded-lg border border-red-600/50 bg-red-600/5 text-sm text-red-400 flex items-center gap-2">
      <AlertTriangle className="w-4 h-4 shrink-0" />
      No agent report for {formatAge(server.reportAgeSeconds)}{thresholdHours ? ` (threshold ${thresholdHours} h)` : ''}. The findings may be out
      of date.
    </div>
  );
}
