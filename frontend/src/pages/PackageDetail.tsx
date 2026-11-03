import { useEffect, useState, useCallback } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowLeft, Shield, X } from 'lucide-react';
import { getPackageInstallations } from '../api/client';
import { useUrlFilters, SortableHeader, FilterInput, Pagination } from '../components/TableControls';
import type { InstalledPackage } from '../types';

type SortField = 'serverName' | 'version' | 'arch' | 'os' | 'firstSeenAt' | 'lastSeenAt';
type SortDirection = 'asc' | 'desc';

const ITEMS_PER_PAGE = 50;
const FILTER_KEYS = ['server', 'version', 'arch', 'os'] as const;
type FilterKey = typeof FILTER_KEYS[number];

const COLUMNS: { field: SortField; label: string; filter?: FilterKey; placeholder?: string }[] = [
  { field: 'serverName', label: 'Server', filter: 'server', placeholder: 'server' },
  { field: 'version', label: 'Version', filter: 'version', placeholder: 'e.g. 3.0.13' },
  { field: 'arch', label: 'Arch', filter: 'arch', placeholder: 'amd64' },
  { field: 'os', label: 'OS', filter: 'os', placeholder: 'e.g. 24.04' },
  { field: 'firstSeenAt', label: 'First Seen' },
  { field: 'lastSeenAt', label: 'Last Seen' },
];

// One package: the servers it is installed on, in which version.
export default function PackageDetail() {
  const { name = '' } = useParams<{ name: string }>();
  const { inputs, setInputs, setInput, filters, filterKey, hasFilters } = useUrlFilters(FILTER_KEYS);

  const [installations, setInstallations] = useState<InstalledPackage[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [sortField, setSortField] = useState<SortField>('serverName');
  const [sortDirection, setSortDirection] = useState<SortDirection>('asc');
  const [currentPage, setCurrentPage] = useState(1);

  useEffect(() => {
    setCurrentPage(1);
  }, [filterKey, name]);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getPackageInstallations(name, {
        ...filters,
        sortBy: sortField,
        sortOrder: sortDirection,
        limit: ITEMS_PER_PAGE,
        offset: (currentPage - 1) * ITEMS_PER_PAGE,
      });
      setInstallations(data.installations || []);
      setTotal(data.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load package');
    } finally {
      setLoading(false);
    }
  }, [name, filterKey, sortField, sortDirection, currentPage]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDirection(field === 'firstSeenAt' || field === 'lastSeenAt' ? 'desc' : 'asc');
    }
    setCurrentPage(1);
  };

  const sourcePackage = installations.find((i) => i.sourcePackage)?.sourcePackage;

  return (
    <div className="space-y-6">
      <Link to="/packages" className="inline-flex items-center gap-1 text-sm text-[#a5d6a7] hover:text-[#4ade80]">
        <ArrowLeft className="w-4 h-4" />
        APT Packages
      </Link>

      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[#e8f5e9] font-mono">{name}</h1>
          <p className="text-[#a5d6a7] mt-1">
            {sourcePackage && sourcePackage !== name && (
              <>Source package <span className="font-mono">{sourcePackage}</span> · </>
            )}
            Servers this package is installed on
          </p>
        </div>
        <div className="flex items-center gap-2">
          {hasFilters && (
            <button
              onClick={() => setInputs({})}
              className="flex items-center gap-1 px-3 py-2 rounded-lg bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36] text-sm"
            >
              <X className="w-4 h-4" />
              Clear filters
            </button>
          )}
          <Link
            to={`/findings?search=${encodeURIComponent(name)}`}
            className="flex items-center gap-1 px-3 py-2 rounded-lg bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36] text-sm whitespace-nowrap"
          >
            <Shield className="w-4 h-4" />
            Show findings
          </Link>
        </div>
      </div>

      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-[#e8f5e9]">
            Servers ({total.toLocaleString()})
          </h2>
          <span className="text-xs text-[#6b7280]">Filters match any part of the value, ignoring case</span>
        </div>

        {error && (
          <div className="mb-4 p-3 rounded-lg border border-red-600/50 bg-red-600/5 text-red-400">{error}</div>
        )}

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#2d3f36]">
                {COLUMNS.map((col) => (
                  <SortableHeader
                    key={col.field}
                    label={col.label}
                    active={sortField === col.field}
                    direction={sortDirection}
                    onClick={() => handleSort(col.field)}
                  />
                ))}
              </tr>
              <tr className="border-b border-[#2d3f36]">
                {COLUMNS.map((col) => (
                  <th key={col.field} className="py-2 px-2 font-normal">
                    {col.filter && (
                      <FilterInput
                        label={col.label}
                        placeholder={col.placeholder}
                        value={inputs[col.filter] ?? ''}
                        onChange={(value) => setInput(col.filter as FilterKey, value)}
                      />
                    )}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className={loading ? 'opacity-50' : ''}>
              {installations.map((inst) => (
                <tr key={inst.id} className="table-row hover:bg-[#1a2420]">
                  <td className="py-2 px-4 text-sm whitespace-nowrap">
                    <Link to={`/servers/${inst.serverId}`} className="text-[#4ade80] hover:underline">
                      {inst.serverName}
                    </Link>
                  </td>
                  <td
                    className="py-2 px-4 font-mono text-xs text-[#a5d6a7] whitespace-nowrap"
                    title={inst.previousVersion ? `Previously ${inst.previousVersion}` : undefined}
                  >
                    {inst.version}
                  </td>
                  <td className="py-2 px-4 font-mono text-xs text-[#6b7280]">{inst.arch || '-'}</td>
                  <td className="py-2 px-4 text-xs text-[#a5d6a7] whitespace-nowrap">{inst.os || '-'}</td>
                  <td className="py-2 px-4 text-xs text-[#6b7280] whitespace-nowrap">
                    {new Date(inst.firstSeenAt).toLocaleDateString()}
                  </td>
                  <td className="py-2 px-4 text-xs text-[#6b7280] whitespace-nowrap">
                    {new Date(inst.lastSeenAt).toLocaleString()}
                  </td>
                </tr>
              ))}
              {!loading && installations.length === 0 && (
                <tr>
                  <td colSpan={COLUMNS.length} className="py-8 text-center text-[#6b7280]">
                    {hasFilters ? 'No servers match your filters' : 'This package is not installed on any server'}
                  </td>
                </tr>
              )}
              {loading && installations.length === 0 && (
                <tr>
                  <td colSpan={COLUMNS.length} className="py-8 text-center text-[#a5d6a7]">Loading...</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <Pagination page={currentPage} pageSize={ITEMS_PER_PAGE} total={total} noun="servers" onPage={setCurrentPage} />
      </div>
    </div>
  );
}
