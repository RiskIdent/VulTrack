import { useEffect, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { X } from 'lucide-react';
import { getPackageSummaries } from '../api/client';
import { useUrlFilters, SortableHeader, FilterInput, Pagination } from '../components/TableControls';
import type { PackageSummary } from '../types';

type SortField = 'name' | 'sourcePackage' | 'versionCount' | 'serverCount' | 'lastSeenAt';
type SortDirection = 'asc' | 'desc';

const ITEMS_PER_PAGE = 50;
const FILTER_KEYS = ['name', 'sourcePackage', 'version'] as const;
type FilterKey = typeof FILTER_KEYS[number];

// Columns in display order. `filter` names the query parameter its filter
// input sets.
const COLUMNS: { field: SortField; label: string; filter?: FilterKey; placeholder?: string }[] = [
  { field: 'name', label: 'Package', filter: 'name', placeholder: 'e.g. openssl' },
  { field: 'sourcePackage', label: 'Source Package', filter: 'sourcePackage', placeholder: 'source' },
  { field: 'versionCount', label: 'Versions', filter: 'version', placeholder: 'e.g. 3.0.13' },
  { field: 'serverCount', label: 'Servers' },
  { field: 'lastSeenAt', label: 'Last Seen' },
];

// Show up to this many versions inline; more collapse into a count.
const MAX_INLINE_VERSIONS = 2;

export default function Packages() {
  const { inputs, setInputs, setInput, filters, filterKey, hasFilters } = useUrlFilters(FILTER_KEYS);

  const [packages, setPackages] = useState<PackageSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [sortField, setSortField] = useState<SortField>('name');
  const [sortDirection, setSortDirection] = useState<SortDirection>('asc');
  const [currentPage, setCurrentPage] = useState(1);

  // Back to the first page whenever the filters change.
  useEffect(() => {
    setCurrentPage(1);
  }, [filterKey]);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getPackageSummaries({
        ...filters,
        sortBy: sortField,
        sortOrder: sortDirection,
        limit: ITEMS_PER_PAGE,
        offset: (currentPage - 1) * ITEMS_PER_PAGE,
      });
      setPackages(data.packages || []);
      setTotal(data.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load packages');
    } finally {
      setLoading(false);
    }
  }, [filterKey, sortField, sortDirection, currentPage]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDirection(field === 'name' || field === 'sourcePackage' ? 'asc' : 'desc');
    }
    setCurrentPage(1);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[#e8f5e9]">APT Packages</h1>
          <p className="text-[#a5d6a7] mt-1">Packages currently installed on your servers, as last reported by their agents</p>
        </div>
        {hasFilters && (
          <button
            onClick={() => setInputs({})}
            className="flex items-center gap-1 px-3 py-2 rounded-lg bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36] text-sm"
          >
            <X className="w-4 h-4" />
            Clear filters
          </button>
        )}
      </div>

      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-[#e8f5e9]">
            Packages ({total.toLocaleString()})
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
              {packages.map((pkg) => (
                <tr key={pkg.name} className="table-row hover:bg-[#1a2420]">
                  <td className="py-2 px-4 font-mono text-sm">
                    <Link
                      to={`/packages/${encodeURIComponent(pkg.name)}`}
                      className="text-[#4ade80] hover:underline"
                    >
                      {pkg.name}
                    </Link>
                    {pkg.archs.length > 0 && (
                      <span className="ml-2 text-xs text-[#6b7280]">{pkg.archs.join(', ')}</span>
                    )}
                  </td>
                  <td className="py-2 px-4 font-mono text-xs text-[#a5d6a7]">
                    {pkg.sourcePackages.join(', ') || '-'}
                  </td>
                  <td className="py-2 px-4 font-mono text-xs text-[#a5d6a7]" title={pkg.versions.join('\n')}>
                    {pkg.versions.length <= MAX_INLINE_VERSIONS ? (
                      <div className="flex flex-col">
                        {pkg.versions.map((v) => <span key={v} className="whitespace-nowrap">{v}</span>)}
                      </div>
                    ) : (
                      <span className="px-2 py-0.5 rounded bg-amber-600/20 text-amber-400 whitespace-nowrap">
                        {pkg.versions.length} versions
                      </span>
                    )}
                  </td>
                  <td className="py-2 px-4 text-sm text-[#e8f5e9]">{pkg.serverCount}</td>
                  <td className="py-2 px-4 text-xs text-[#6b7280] whitespace-nowrap">
                    {new Date(pkg.lastSeenAt).toLocaleString()}
                  </td>
                </tr>
              ))}
              {!loading && packages.length === 0 && (
                <tr>
                  <td colSpan={COLUMNS.length} className="py-8 text-center text-[#6b7280]">
                    {hasFilters ? 'No packages match your filters' : 'No packages reported yet'}
                  </td>
                </tr>
              )}
              {loading && packages.length === 0 && (
                <tr>
                  <td colSpan={COLUMNS.length} className="py-8 text-center text-[#a5d6a7]">Loading packages...</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <Pagination page={currentPage} pageSize={ITEMS_PER_PAGE} total={total} noun="packages" onPage={setCurrentPage} />
      </div>
    </div>
  );
}
