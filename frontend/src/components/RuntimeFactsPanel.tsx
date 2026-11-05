import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { AlertTriangle, Cpu, Network, Package, Settings2, RotateCw } from 'lucide-react';
import { getServerRuntime } from '../api/client';
import type { ServerRuntime, FactCategoryState } from '../types';

// Runtime facts of one server, as reported by its agent: what is running,
// listening and loaded. Shown on the server detail page.

interface Listener {
  protocol: string;
  address: string;
  port: number;
  process?: string;
  exe?: string;
  package?: string;
  unit?: string;
  hostNetns?: boolean;
}
interface PackageInUse { package: string; processes: string[]; staleProcesses?: string[] }
interface ServiceFact { unit: string; activeState?: string; subState?: string; unitFileState?: string; package?: string }
interface KernelFacts {
  release?: string;
  modulesDisabled?: boolean;
  loadedModules?: { name: string; path?: string }[];
  blacklistedModules?: { name: string; installCommand?: string }[];
  sysctls?: Record<string, string>;
  installedKernels?: string[];
  rebootRequired?: boolean;
  rebootRequiredPackages?: string[];
}

const CATEGORY_LABEL: Record<string, string> = {
  kernel: 'Kernel',
  listeners: 'Listening ports',
  packagesInUse: 'Packages in use',
  services: 'Services',
  virtualization: 'Virtualization',
  packageInfo: 'Package entry points and dependencies',
};

// isLoopback tells whether a bind address is reachable only from the host.
export function isLoopback(address: string) {
  return address === '::1' || address.startsWith('127.') || address.startsWith('::ffff:127.');
}

function since(c?: FactCategoryState) {
  if (!c) return null;
  return (
    <span className="text-xs text-[#6b7280]" title={`Last reported ${new Date(c.reportedAt).toLocaleString()}`}>
      unchanged since {new Date(c.stableSince).toLocaleString()}
      {c.truncated && <span className="ml-2 text-yellow-400">· list cut at the agent's size limit</span>}
    </span>
  );
}

function Section({ icon, title, cat, children, count }: {
  icon: ReactNode; title: string; cat?: FactCategoryState; children: ReactNode; count?: number;
}) {
  return (
    <div className="card">
      <div className="flex flex-wrap items-baseline justify-between gap-2 mb-3">
        <h3 className="text-lg font-semibold text-[#e8f5e9] flex items-center gap-2">
          {icon}{title}{count !== undefined && <span className="text-sm text-[#6b7280] font-normal">({count})</span>}
        </h3>
        {since(cat)}
      </div>
      {children}
    </div>
  );
}

function Filter({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <input
      className="input py-1 mb-3 w-full max-w-sm"
      placeholder={placeholder}
      value={value}
      onChange={(e) => onChange(e.target.value)}
    />
  );
}

export default function RuntimeFactsPanel({ serverId }: { serverId: number }) {
  const [rt, setRt] = useState<ServerRuntime | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pkgFilter, setPkgFilter] = useState('');
  const [svcFilter, setSvcFilter] = useState('');
  const [modFilter, setModFilter] = useState('');
  const [onlyRunning, setOnlyRunning] = useState(true);

  useEffect(() => {
    getServerRuntime(serverId).then(setRt).catch((e) => setError(e instanceof Error ? e.message : 'Failed to load runtime facts'));
  }, [serverId]);

  const cat = useMemo(() => {
    const m: Record<string, FactCategoryState> = {};
    rt?.categories.forEach((c) => { m[c.category] = c; });
    return m;
  }, [rt]);

  if (error) return <div className="card border-red-600/50 bg-red-600/5 text-red-400">{error}</div>;
  if (!rt) return <div className="card text-[#a5d6a7]">Loading runtime facts...</div>;

  if (rt.categories.length === 0) {
    return (
      <div className="card text-[#a5d6a7] space-y-2">
        <p>This server's agent does not report runtime facts yet.</p>
        <p className="text-sm text-[#6b7280]">
          Agents that support them send loaded kernel modules, listening ports, packages in use and services with every
          report. Rules that need these facts treat the server as unknown and never dismiss anything on it.
        </p>
      </div>
    );
  }

  const kernel = cat.kernel?.data as KernelFacts | undefined;
  const listeners = (cat.listeners?.data as Listener[] | undefined) ?? [];
  const inUse = (cat.packagesInUse?.data as PackageInUse[] | undefined) ?? [];
  const services = (cat.services?.data as ServiceFact[] | undefined) ?? [];
  const virt = cat.virtualization?.data as string | undefined;
  const pkgInfo = cat.packageInfo?.data as { package: string; entryPoints?: string[]; depends?: string[] }[] | undefined;
  const errors = (rt.errors as { collector: string; error: string }[] | null) ?? [];
  const stale = inUse.filter((p) => p.staleProcesses?.length);
  const exposed = listeners.filter((l) => !isLoopback(l.address));

  const pf = pkgFilter.toLowerCase();
  const sf = svcFilter.toLowerCase();
  const mf = modFilter.toLowerCase();

  return (
    <div className="space-y-6">
      {/* Overview */}
      <div className="card">
        <div className="flex flex-wrap gap-x-8 gap-y-2 text-sm">
          <div><span className="text-[#6b7280]">Collected </span><span className="text-[#e8f5e9]">{rt.collectedAt ? new Date(rt.collectedAt).toLocaleString() : '–'}</span></div>
          <div><span className="text-[#6b7280]">Virtualization </span><span className="text-[#e8f5e9]">{virt ?? 'unknown'}</span></div>
          <div><span className="text-[#6b7280]">Listening on non-loopback </span><span className="text-[#e8f5e9]">{cat.listeners ? exposed.length : 'unknown'}</span></div>
          <div><span className="text-[#6b7280]">Processes needing a restart </span><span className={stale.length ? 'text-yellow-400' : 'text-[#e8f5e9]'}>{cat.packagesInUse ? stale.length : 'unknown'}</span></div>
          <div title="Since when every report has said which packages are in use, without a gap of more than six hours. R-UNUSED needs a long, gap-free observation.">
            <span className="text-[#6b7280]">Package usage observed </span>
            <span className="text-[#e8f5e9]">
              {rt.packageUsage?.observedSince
                ? `${rt.packageUsage.observedDays.toLocaleString()} days (since ${new Date(rt.packageUsage.observedSince).toLocaleDateString()})`
                : 'no'}
            </span>
          </div>
          {pkgInfo && (
            <div><span className="text-[#6b7280]">Packages with entry points </span><span className="text-[#e8f5e9]">{pkgInfo.filter((p) => p.entryPoints?.length).length} of {pkgInfo.length}</span></div>
          )}
          {kernel?.rebootRequired !== undefined && (
            <div><span className="text-[#6b7280]">Reboot required </span><span className={kernel.rebootRequired ? 'text-yellow-400' : 'text-[#e8f5e9]'}>{kernel.rebootRequired ? 'yes' : 'no'}</span></div>
          )}
        </div>
        {rt.unknown.length > 0 && (
          <p className="text-xs text-[#6b7280] mt-3">
            Not reported (unknown, rules never rely on them): {rt.unknown.map((c) => CATEGORY_LABEL[c] || c).join(', ')}
          </p>
        )}
        {errors.length > 0 && (
          <div className="mt-3 p-3 rounded-lg border border-yellow-600/50 bg-yellow-600/10 text-sm text-yellow-300 flex gap-2">
            <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
            <div>
              The agent could not collect everything:
              <ul className="list-disc list-inside">
                {errors.map((e, i) => <li key={i}><span className="font-mono">{e.collector}</span>: {e.error}</li>)}
              </ul>
            </div>
          </div>
        )}
      </div>

      {/* Listening ports */}
      {cat.listeners && (
        <Section icon={<Network className="w-5 h-5 text-[#4ade80]" />} title="Listening ports" cat={cat.listeners} count={listeners.length}>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#2d3f36]">
                  {['Address', 'Port', 'Protocol', 'Process', 'Package', 'Unit'].map((h) => (
                    <th key={h} className="table-header text-left py-2 px-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {listeners.map((l, i) => (
                  <tr key={i} className="table-row">
                    <td className="py-1.5 px-3 font-mono whitespace-nowrap">
                      <span className={isLoopback(l.address) ? 'text-[#6b7280]' : 'text-[#e8f5e9]'}>{l.address}</span>
                      {!isLoopback(l.address) && <span className="ml-2 text-xs px-1.5 py-0.5 rounded bg-orange-600/20 text-orange-300">reachable</span>}
                      {l.hostNetns === false && <span className="ml-2 text-xs text-[#6b7280]">container</span>}
                    </td>
                    <td className="py-1.5 px-3 font-mono text-[#e8f5e9]">{l.port}</td>
                    <td className="py-1.5 px-3 text-[#a5d6a7]">{l.protocol}</td>
                    <td className="py-1.5 px-3 text-[#a5d6a7]" title={l.exe}>{l.process || '–'}</td>
                    <td className="py-1.5 px-3 font-mono text-xs text-[#a5d6a7]">{l.package || '–'}</td>
                    <td className="py-1.5 px-3 font-mono text-xs text-[#6b7280]">{l.unit || '–'}</td>
                  </tr>
                ))}
                {listeners.length === 0 && (
                  <tr><td colSpan={6} className="py-4 text-center text-[#6b7280]">Nothing is listening.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </Section>
      )}

      {/* Packages in use */}
      {cat.packagesInUse && (
        <Section icon={<Package className="w-5 h-5 text-[#4ade80]" />} title="Packages in use by running processes" cat={cat.packagesInUse} count={inUse.length}>
          {stale.length > 0 && (
            <p className="text-sm text-yellow-300 mb-3 flex items-center gap-2">
              <RotateCw className="w-4 h-4" />
              {stale.length} package(s) were upgraded while processes kept running the old version; those processes need a restart.
            </p>
          )}
          <Filter value={pkgFilter} onChange={setPkgFilter} placeholder="Filter by package or process" />
          <div className="overflow-x-auto max-h-[28rem] overflow-y-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#2d3f36]">
                  <th className="table-header text-left py-2 px-3">Package</th>
                  <th className="table-header text-left py-2 px-3">Processes</th>
                  <th className="table-header text-left py-2 px-3">Running the replaced version</th>
                </tr>
              </thead>
              <tbody>
                {inUse
                  .filter((p) => !pf || p.package.toLowerCase().includes(pf) || p.processes.some((x) => x.toLowerCase().includes(pf)))
                  .map((p) => (
                    <tr key={p.package} className="table-row">
                      <td className="py-1.5 px-3 font-mono text-[#e8f5e9]">{p.package}</td>
                      <td className="py-1.5 px-3 text-[#a5d6a7]">{p.processes.join(', ')}</td>
                      <td className="py-1.5 px-3 text-yellow-300">{p.staleProcesses?.join(', ') || ''}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </Section>
      )}

      {/* Kernel */}
      {cat.kernel && kernel && (
        <Section icon={<Cpu className="w-5 h-5 text-[#4ade80]" />} title="Kernel" cat={cat.kernel}>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm mb-4">
            <div><div className="text-xs text-[#6b7280] uppercase">Running kernel</div><div className="font-mono text-[#e8f5e9]">{kernel.release}</div></div>
            <div>
              <div className="text-xs text-[#6b7280] uppercase">Module loading</div>
              <div className="text-[#e8f5e9]">{kernel.modulesDisabled ? 'disabled (kernel.modules_disabled = 1)' : 'allowed'}</div>
            </div>
            <div>
              <div className="text-xs text-[#6b7280] uppercase">Module index</div>
              <div className="text-[#e8f5e9]">
                {rt.moduleIndex?.known
                  ? `${rt.moduleIndex.available.toLocaleString()} available, ${rt.moduleIndex.builtin.toLocaleString()} built in`
                  : 'not received yet'}
              </div>
            </div>
            {kernel.installedKernels && (
              <div><div className="text-xs text-[#6b7280] uppercase">Installed kernels</div><div className="font-mono text-xs text-[#a5d6a7]">{kernel.installedKernels.join(', ')}</div></div>
            )}
            {kernel.rebootRequired && (
              <div className="md:col-span-2">
                <div className="text-xs text-[#6b7280] uppercase">Reboot required by</div>
                <div className="font-mono text-xs text-yellow-300">{kernel.rebootRequiredPackages?.join(', ') || 'yes'}</div>
              </div>
            )}
          </div>
          {kernel.sysctls && Object.keys(kernel.sysctls).length > 0 && (
            <div className="mb-4">
              <div className="text-xs text-[#6b7280] uppercase mb-1">Security-relevant kernel settings</div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-x-6">
                {Object.entries(kernel.sysctls).sort().map(([k, v]) => (
                  <div key={k} className="flex justify-between font-mono text-xs py-0.5 border-b border-[#1a2420]">
                    <span className="text-[#a5d6a7]">{k}</span><span className="text-[#e8f5e9]">{v}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {kernel.blacklistedModules && kernel.blacklistedModules.length > 0 && (
            <div className="mb-4 text-sm">
              <div className="text-xs text-[#6b7280] uppercase mb-1">Blocked modules</div>
              <div className="font-mono text-xs text-[#a5d6a7]">
                {kernel.blacklistedModules.map((m) => m.installCommand ? `${m.name} (install ${m.installCommand})` : m.name).join(', ')}
              </div>
            </div>
          )}
          {kernel.loadedModules && (
            <div>
              <div className="text-xs text-[#6b7280] uppercase mb-1">Loaded modules ({kernel.loadedModules.length})</div>
              <Filter value={modFilter} onChange={setModFilter} placeholder="Filter modules" />
              <div className="font-mono text-xs text-[#a5d6a7] max-h-48 overflow-y-auto leading-6">
                {kernel.loadedModules
                  .filter((m) => !mf || m.name.toLowerCase().includes(mf) || (m.path || '').toLowerCase().includes(mf))
                  .map((m) => <span key={m.name} className="inline-block mr-3" title={m.path}>{m.name}</span>)}
              </div>
            </div>
          )}
        </Section>
      )}

      {/* Services */}
      {cat.services && (
        <Section icon={<Settings2 className="w-5 h-5 text-[#4ade80]" />} title="Services" cat={cat.services} count={services.length}>
          <div className="flex flex-wrap items-center gap-4">
            <Filter value={svcFilter} onChange={setSvcFilter} placeholder="Filter by unit or package" />
            <label className="flex items-center gap-2 text-sm text-[#a5d6a7] mb-3 cursor-pointer">
              <input type="checkbox" checked={onlyRunning} onChange={(e) => setOnlyRunning(e.target.checked)} className="w-4 h-4" />
              Active only
            </label>
          </div>
          <div className="overflow-x-auto max-h-[28rem] overflow-y-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#2d3f36]">
                  {['Unit', 'State', 'Enabled', 'Package'].map((h) => <th key={h} className="table-header text-left py-2 px-3">{h}</th>)}
                </tr>
              </thead>
              <tbody>
                {services
                  .filter((s) => !onlyRunning || s.activeState === 'active')
                  .filter((s) => !sf || s.unit.toLowerCase().includes(sf) || (s.package || '').toLowerCase().includes(sf))
                  .map((s) => (
                    <tr key={s.unit} className="table-row">
                      <td className="py-1.5 px-3 font-mono text-[#e8f5e9]">{s.unit}</td>
                      <td className="py-1.5 px-3 text-[#a5d6a7]">{s.activeState}{s.subState ? ` (${s.subState})` : ''}</td>
                      <td className="py-1.5 px-3 text-[#a5d6a7]">{s.unitFileState || '–'}</td>
                      <td className="py-1.5 px-3 font-mono text-xs text-[#a5d6a7]">{s.package || '–'}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </Section>
      )}
    </div>
  );
}
