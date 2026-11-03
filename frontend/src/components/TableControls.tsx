import { useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { ChevronUp, ChevronDown, ChevronLeft, ChevronRight } from 'lucide-react';

// Building blocks for server-side filtered, sorted and paged tables
// (APT Packages list and package detail).

type Filters<K extends string> = Partial<Record<K, string>>;

function toParams<K extends string>(keys: readonly K[], filters: Filters<K>): URLSearchParams {
  const params = new URLSearchParams();
  for (const key of keys) {
    const value = filters[key]?.trim();
    if (value) params.set(key, value);
  }
  return params;
}

function readFilters<K extends string>(keys: readonly K[], params: URLSearchParams): Filters<K> {
  const filters: Filters<K> = {};
  for (const key of keys) {
    const value = params.get(key);
    if (value) filters[key] = value;
  }
  return filters;
}

/**
 * Column filters kept in the URL, so a filtered view can be bookmarked or
 * shared. `inputs` follows every keystroke; `filters` (and `filterKey`, a
 * stable string for effect dependencies) update after a short typing pause.
 */
export function useUrlFilters<K extends string>(keys: readonly K[]) {
  const [searchParams, setSearchParams] = useSearchParams();
  const [inputs, setInputs] = useState<Filters<K>>(() => readFilters(keys, searchParams));
  const filters = readFilters(keys, searchParams);
  const filterKey = toParams(keys, filters).toString();

  const debounceRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => {
    debounceRef.current = setTimeout(() => {
      const next = toParams(keys, inputs);
      if (next.toString() !== filterKey) {
        setSearchParams(next, { replace: true });
      }
    }, 300);
    return () => clearTimeout(debounceRef.current);
  }, [inputs]); // eslint-disable-line react-hooks/exhaustive-deps

  const setInput = (key: K, value: string) => setInputs((prev) => ({ ...prev, [key]: value }));
  const hasFilters = keys.some((k) => inputs[k]);

  return { inputs, setInputs, setInput, filters, filterKey, hasFilters };
}

export function SortableHeader({
  label, active, direction, onClick,
}: { label: string; active: boolean; direction: 'asc' | 'desc'; onClick: () => void }) {
  return (
    <th
      className="table-header text-left py-3 px-4 cursor-pointer hover:bg-[#1a2420] select-none whitespace-nowrap"
      onClick={onClick}
    >
      <div className="flex items-center gap-1">
        {label}
        {active && (direction === 'asc' ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />)}
      </div>
    </th>
  );
}

export function FilterInput({
  label, placeholder, value, onChange,
}: { label: string; placeholder?: string; value: string; onChange: (value: string) => void }) {
  return (
    <input
      type="text"
      aria-label={`Filter by ${label}`}
      placeholder={placeholder}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="w-full min-w-[6rem] px-2 py-1 bg-[#0a0f0d] border border-[#2d3f36] rounded text-sm text-[#e8f5e9] placeholder-[#4b5563] focus:outline-none focus:border-[#4ade80]"
    />
  );
}

export function Pagination({
  page, pageSize, total, noun, onPage,
}: { page: number; pageSize: number; total: number; noun: string; onPage: (page: number) => void }) {
  const totalPages = Math.ceil(total / pageSize);
  if (totalPages <= 1) return null;
  const button = 'rounded bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36] disabled:opacity-50 disabled:cursor-not-allowed';
  return (
    <div className="flex items-center justify-between mt-4 pt-4 border-t border-[#2d3f36]">
      <div className="text-sm text-[#6b7280]">
        Showing {((page - 1) * pageSize) + 1} to {Math.min(page * pageSize, total)} of {total.toLocaleString()} {noun}
      </div>
      <div className="flex items-center gap-2">
        <button onClick={() => onPage(1)} disabled={page === 1} className={`px-3 py-1 ${button}`}>First</button>
        <button onClick={() => onPage(Math.max(1, page - 1))} disabled={page === 1} className={`p-1 ${button}`}>
          <ChevronLeft className="w-5 h-5" />
        </button>
        <span className="px-3 py-1 text-[#e8f5e9]">Page {page} of {totalPages}</span>
        <button onClick={() => onPage(Math.min(totalPages, page + 1))} disabled={page === totalPages} className={`p-1 ${button}`}>
          <ChevronRight className="w-5 h-5" />
        </button>
        <button onClick={() => onPage(totalPages)} disabled={page === totalPages} className={`px-3 py-1 ${button}`}>Last</button>
      </div>
    </div>
  );
}
