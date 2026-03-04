import { useEffect, useState, useMemo } from 'react';
import {
  Plus, Trash2, Play, Power, PowerOff, Clock, Mail, Search,
  Server as ServerIcon, FolderTree, AlertTriangle, Check, X,
  PieChart, TrendingUp, Table, List
} from 'lucide-react';
import {
  getServers, getServerGroups,
  getReportSchedules, createReportSchedule, deleteReportSchedule,
  toggleReportSchedule, runReportScheduleNow,
} from '../api/client';
import { ConfirmModal } from '../components/ConfirmModal';
import type { Server as ServerType, ServerGroup, ReportSchedule } from '../types';

const DAYS_OF_WEEK = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
const WEEK_ORDINALS = ['1st', '2nd', '3rd', '4th', '5th'];

function formatSchedule(s: ReportSchedule): string {
  const time = `${String(s.timeHour).padStart(2, '0')}:${String(s.timeMinute).padStart(2, '0')}`;
  const every = s.intervalValue > 1 ? `Every ${s.intervalValue} ` : 'Every ';

  switch (s.scheduleType) {
    case 'weekly': {
      const day = DAYS_OF_WEEK[s.dayOfWeek ?? 1];
      const unit = s.intervalValue > 1 ? 'weeks' : 'week';
      return `${every}${unit}, ${day} at ${time}`;
    }
    case 'monthly_dom': {
      const dom = s.dayOfMonth ?? 1;
      const unit = s.intervalValue > 1 ? 'months' : 'month';
      return `${every}${unit}, day ${dom} at ${time}`;
    }
    case 'monthly_dow': {
      const ord = WEEK_ORDINALS[(s.weekOfMonth ?? 1) - 1] || `${s.weekOfMonth}th`;
      const day = DAYS_OF_WEEK[s.dayOfWeek ?? 1];
      const unit = s.intervalValue > 1 ? 'months' : 'month';
      return `${every}${unit}, ${ord} ${day} at ${time}`;
    }
    default:
      return 'Unknown schedule';
  }
}

function formatPeriod(s: ReportSchedule): string {
  switch (s.periodType) {
    case 'last_month': return 'Last month';
    case 'last_week': return 'Last week';
    case 'last_n_days': return `Last ${s.periodDays ?? 30} days`;
    default: return s.periodType;
  }
}

function formatDate(dateStr: string | null | undefined): string {
  if (!dateStr) return '—';
  return new Date(dateStr).toLocaleString('de-DE', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

export default function PlannedReports() {
  // Data
  const [schedules, setSchedules] = useState<ReportSchedule[]>([]);
  const [servers, setServers] = useState<ServerType[]>([]);
  const [groups, setGroups] = useState<ServerGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Form state
  const [name, setName] = useState('');
  const [scheduleType, setScheduleType] = useState<'weekly' | 'monthly_dom' | 'monthly_dow'>('weekly');
  const [intervalValue, setIntervalValue] = useState(1);
  const [dayOfWeek, setDayOfWeek] = useState(1);
  const [weekOfMonth, setWeekOfMonth] = useState(1);
  const [dayOfMonth, setDayOfMonth] = useState(1);
  const [timeHour, setTimeHour] = useState(8);
  const [timeMinute, setTimeMinute] = useState(0);
  const [timezone, setTimezone] = useState('Europe/Berlin');

  const [selectedServerIds, setSelectedServerIds] = useState<number[]>([]);
  const [selectedGroupIds, setSelectedGroupIds] = useState<number[]>([]);
  const [serverSearchQuery, setServerSearchQuery] = useState('');
  const [groupSearchQuery, setGroupSearchQuery] = useState('');

  const [periodType, setPeriodType] = useState<'last_month' | 'last_week' | 'last_n_days'>('last_month');
  const [periodDays, setPeriodDays] = useState(30);

  const [includeSeverityChart, setIncludeSeverityChart] = useState(true);
  const [includeTrendChart, setIncludeTrendChart] = useState(true);
  const [includeTopCves, setIncludeTopCves] = useState(true);
  const [includeFullCveList, setIncludeFullCveList] = useState(false);

  const [recipientInput, setRecipientInput] = useState('');
  const [recipients, setRecipients] = useState<string[]>([]);

  const [submitting, setSubmitting] = useState(false);

  // Detail modal
  const [detailSchedule, setDetailSchedule] = useState<ReportSchedule | null>(null);

  // Confirm delete modal
  const [deleteTarget, setDeleteTarget] = useState<ReportSchedule | null>(null);

  // Fetch data
  useEffect(() => {
    async function fetchData() {
      try {
        const [schedulesData, serversData, groupsData] = await Promise.all([
          getReportSchedules(),
          getServers(),
          getServerGroups(),
        ]);
        setSchedules(schedulesData.schedules || []);
        setServers(serversData.servers || []);
        setGroups(groupsData.groups || []);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load data');
      } finally {
        setLoading(false);
      }
    }
    fetchData();
  }, []);

  // Filtered lists
  const filteredServers = useMemo(() => {
    if (!serverSearchQuery) return servers;
    const q = serverSearchQuery.toLowerCase();
    return servers.filter(s => s.name.toLowerCase().includes(q));
  }, [servers, serverSearchQuery]);

  const filteredGroups = useMemo(() => {
    if (!groupSearchQuery) return groups;
    const q = groupSearchQuery.toLowerCase();
    return groups.filter(g => g.name.toLowerCase().includes(q));
  }, [groups, groupSearchQuery]);

  // Schedule preview
  const schedulePreview = useMemo(() => {
    const preview: ReportSchedule = {
      id: 0, name, scheduleType, intervalValue,
      dayOfWeek, weekOfMonth, dayOfMonth,
      timeHour, timeMinute, timezone,
      serverIds: selectedServerIds, groupIds: selectedGroupIds,
      periodType, periodDays,
      includeSeverityChart, includeTrendChart, includeTopCves, includeFullCveList,
      recipients, enabled: true, createdAt: '', updatedAt: '',
    };
    return formatSchedule(preview);
  }, [scheduleType, intervalValue, dayOfWeek, weekOfMonth, dayOfMonth, timeHour, timeMinute]);

  const addRecipient = () => {
    const email = recipientInput.trim();
    if (email && email.includes('@') && !recipients.includes(email)) {
      setRecipients([...recipients, email]);
      setRecipientInput('');
    }
  };

  const removeRecipient = (email: string) => {
    setRecipients(recipients.filter(r => r !== email));
  };

  const handleKeyDownRecipient = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      addRecipient();
    }
  };

  const resetForm = () => {
    setName('');
    setScheduleType('weekly');
    setIntervalValue(1);
    setDayOfWeek(1);
    setWeekOfMonth(1);
    setDayOfMonth(1);
    setTimeHour(8);
    setTimeMinute(0);
    setSelectedServerIds([]);
    setSelectedGroupIds([]);
    setPeriodType('last_month');
    setPeriodDays(30);
    setIncludeSeverityChart(true);
    setIncludeTrendChart(true);
    setIncludeTopCves(true);
    setIncludeFullCveList(false);
    setRecipients([]);
    setRecipientInput('');
  };

  const handleCreate = async () => {
    if (!name.trim()) { setError('Name is required'); return; }
    if (recipients.length === 0) { setError('At least one recipient is required'); return; }

    setSubmitting(true);
    setError(null);
    try {
      const data: Partial<ReportSchedule> = {
        name: name.trim(),
        scheduleType,
        intervalValue,
        dayOfWeek: scheduleType === 'monthly_dom' ? undefined : dayOfWeek,
        weekOfMonth: scheduleType === 'monthly_dow' ? weekOfMonth : undefined,
        dayOfMonth: scheduleType === 'monthly_dom' ? dayOfMonth : undefined,
        timeHour, timeMinute, timezone,
        serverIds: selectedServerIds,
        groupIds: selectedGroupIds,
        periodType,
        periodDays: periodType === 'last_n_days' ? periodDays : undefined,
        includeSeverityChart, includeTrendChart, includeTopCves, includeFullCveList,
        recipients,
        enabled: true,
      };

      const created = await createReportSchedule(data);
      setSchedules(prev => [created, ...prev]);
      resetForm();
      setSuccessMsg('Report schedule created successfully');
      setTimeout(() => setSuccessMsg(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create schedule');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteConfirm = async () => {
    if (!deleteTarget) return;
    try {
      await deleteReportSchedule(deleteTarget.id);
      setSchedules(prev => prev.filter(s => s.id !== deleteTarget.id));
      setDeleteTarget(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete');
      setDeleteTarget(null);
    }
  };

  const handleToggle = async (id: number, currentlyEnabled: boolean) => {
    try {
      const updated = await toggleReportSchedule(id, !currentlyEnabled);
      setSchedules(prev => prev.map(s => s.id === id ? updated : s));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to toggle');
    }
  };

  const handleRunNow = async (id: number) => {
    try {
      setError(null);
      await runReportScheduleNow(id);
      setSuccessMsg('Report generated and sent successfully');
      setTimeout(() => setSuccessMsg(null), 3000);
      // Refresh to get updated last_run_at
      const data = await getReportSchedules();
      setSchedules(data.schedules || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to run report');
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-[#a5d6a7]">Loading...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {error && (
        <div className="card border-red-600/50 bg-red-600/5 flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
          <p className="text-red-400">{error}</p>
        </div>
      )}
      {successMsg && (
        <div className="card border-green-600/50 bg-green-600/5 flex items-center gap-3">
          <Check className="w-5 h-5 text-green-400 flex-shrink-0" />
          <p className="text-green-400">{successMsg}</p>
        </div>
      )}

      {/* ================================================================ */}
      {/* Create New Schedule */}
      {/* ================================================================ */}
      <div className="card">
        <h2 className="text-xl font-bold text-[#e8f5e9] mb-6">Create Scheduled Report</h2>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Left Column: Name, Schedule, Period */}
          <div className="space-y-5">
            {/* Name */}
            <div>
              <label className="block text-sm font-medium text-[#a5d6a7] mb-1">Report Name</label>
              <input
                type="text"
                value={name}
                onChange={e => setName(e.target.value)}
                className="input w-full"
                placeholder="e.g. Monthly Security Report"
              />
            </div>

            {/* Schedule Type */}
            <div>
              <label className="block text-sm font-medium text-[#a5d6a7] mb-1">Schedule Type</label>
              <div className="grid grid-cols-3 gap-2">
                {([
                  ['weekly', 'Weekly'],
                  ['monthly_dom', 'Day of Month'],
                  ['monthly_dow', 'Weekday of Month'],
                ] as const).map(([val, label]) => (
                  <button
                    key={val}
                    onClick={() => setScheduleType(val)}
                    className={`px-3 py-2 rounded-lg text-sm font-medium border transition-colors ${
                      scheduleType === val
                        ? 'bg-[#4ade80]/20 border-[#4ade80]/50 text-[#4ade80]'
                        : 'bg-[#1a2420] border-[#2d3f36] text-[#a5d6a7] hover:border-[#4ade80]/30'
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>

            {/* Schedule Details */}
            <div className="grid grid-cols-2 gap-4">
              {/* Interval */}
              <div>
                <label className="block text-sm font-medium text-[#a5d6a7] mb-1">
                  Every N {scheduleType === 'weekly' ? 'weeks' : 'months'}
                </label>
                <input
                  type="number" min={1} max={12}
                  value={intervalValue}
                  onChange={e => setIntervalValue(Math.max(1, parseInt(e.target.value) || 1))}
                  className="input w-full"
                />
              </div>

              {/* Day selection */}
              {scheduleType === 'weekly' && (
                <div>
                  <label className="block text-sm font-medium text-[#a5d6a7] mb-1">Day</label>
                  <select value={dayOfWeek} onChange={e => setDayOfWeek(Number(e.target.value))} className="input w-full">
                    {DAYS_OF_WEEK.map((d, i) => <option key={i} value={i}>{d}</option>)}
                  </select>
                </div>
              )}

              {scheduleType === 'monthly_dom' && (
                <div>
                  <label className="block text-sm font-medium text-[#a5d6a7] mb-1">Day of Month</label>
                  <input
                    type="number" min={1} max={28}
                    value={dayOfMonth}
                    onChange={e => setDayOfMonth(Math.max(1, Math.min(28, parseInt(e.target.value) || 1)))}
                    className="input w-full"
                  />
                </div>
              )}

              {scheduleType === 'monthly_dow' && (
                <>
                  <div>
                    <label className="block text-sm font-medium text-[#a5d6a7] mb-1">Which</label>
                    <select value={weekOfMonth} onChange={e => setWeekOfMonth(Number(e.target.value))} className="input w-full">
                      {WEEK_ORDINALS.map((o, i) => <option key={i} value={i + 1}>{o}</option>)}
                    </select>
                  </div>
                </>
              )}
            </div>

            {scheduleType === 'monthly_dow' && (
              <div>
                <label className="block text-sm font-medium text-[#a5d6a7] mb-1">Weekday</label>
                <select value={dayOfWeek} onChange={e => setDayOfWeek(Number(e.target.value))} className="input w-full">
                  {DAYS_OF_WEEK.map((d, i) => <option key={i} value={i}>{d}</option>)}
                </select>
              </div>
            )}

            {/* Time */}
            <div className="grid grid-cols-3 gap-4">
              <div>
                <label className="block text-sm font-medium text-[#a5d6a7] mb-1">Hour</label>
                <input
                  type="number" min={0} max={23}
                  value={timeHour}
                  onChange={e => setTimeHour(Math.max(0, Math.min(23, parseInt(e.target.value) || 0)))}
                  className="input w-full"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-[#a5d6a7] mb-1">Minute</label>
                <input
                  type="number" min={0} max={59}
                  value={timeMinute}
                  onChange={e => setTimeMinute(Math.max(0, Math.min(59, parseInt(e.target.value) || 0)))}
                  className="input w-full"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-[#a5d6a7] mb-1">Timezone</label>
                <select value={timezone} onChange={e => setTimezone(e.target.value)} className="input w-full">
                  <option value="Europe/Berlin">Europe/Berlin</option>
                  <option value="Europe/London">Europe/London</option>
                  <option value="America/New_York">America/New_York</option>
                  <option value="America/Los_Angeles">America/Los_Angeles</option>
                  <option value="Asia/Tokyo">Asia/Tokyo</option>
                  <option value="UTC">UTC</option>
                </select>
              </div>
            </div>

            {/* Preview */}
            <div className="px-4 py-3 rounded-lg bg-[#4ade80]/5 border border-[#4ade80]/20">
              <div className="flex items-center gap-2 text-[#4ade80] text-sm font-medium">
                <Clock className="w-4 h-4" />
                {schedulePreview}
              </div>
            </div>

            {/* Period */}
            <div>
              <label className="block text-sm font-medium text-[#a5d6a7] mb-1">Report Period</label>
              <div className="flex gap-3">
                <select
                  value={periodType}
                  onChange={e => setPeriodType(e.target.value as typeof periodType)}
                  className="input flex-1"
                >
                  <option value="last_month">Last month</option>
                  <option value="last_week">Last week</option>
                  <option value="last_n_days">Last N days</option>
                </select>
                {periodType === 'last_n_days' && (
                  <input
                    type="number" min={1} max={365}
                    value={periodDays}
                    onChange={e => setPeriodDays(Math.max(1, parseInt(e.target.value) || 30))}
                    className="input w-24"
                    placeholder="Days"
                  />
                )}
              </div>
            </div>

            {/* Content options */}
            <div>
              <label className="block text-sm font-medium text-[#a5d6a7] mb-2">Report Content</label>
              <div className="space-y-2">
                {[
                  { label: 'Severity Distribution Chart', checked: includeSeverityChart, set: setIncludeSeverityChart },
                  { label: 'Findings Trend Chart', checked: includeTrendChart, set: setIncludeTrendChart },
                  { label: 'Top 10 CVEs', checked: includeTopCves, set: setIncludeTopCves },
                  { label: 'Complete CVE List', checked: includeFullCveList, set: setIncludeFullCveList },
                ].map(opt => (
                  <label key={opt.label} className="flex items-center gap-3 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={opt.checked}
                      onChange={e => opt.set(e.target.checked)}
                      className="rounded border-[#2d3f36] bg-[#1a2420] text-[#4ade80]"
                    />
                    <span className="text-[#e8f5e9] text-sm">{opt.label}</span>
                  </label>
                ))}
              </div>
            </div>
          </div>

          {/* Right Column: Scope + Recipients */}
          <div className="space-y-5">
            {/* Server Selection */}
            <div>
              <label className="block text-sm font-medium text-[#a5d6a7] mb-1">
                <ServerIcon className="w-4 h-4 inline mr-1" />
                Servers ({selectedServerIds.length} selected — empty = all)
              </label>
              <div className="relative mb-2">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-[#6b7280]" />
                <input
                  type="text"
                  value={serverSearchQuery}
                  onChange={e => setServerSearchQuery(e.target.value)}
                  placeholder="Search servers..."
                  className="input w-full !pl-10"
                />
              </div>
              <div className="max-h-40 overflow-y-auto space-y-1 border border-[#2d3f36] rounded-lg p-2 bg-[#0d1411]">
                {filteredServers.map(srv => (
                  <label key={srv.id} className="flex items-center gap-2 px-2 py-1.5 rounded hover:bg-[#1a2420] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={selectedServerIds.includes(srv.id)}
                      onChange={e => {
                        if (e.target.checked) setSelectedServerIds(prev => [...prev, srv.id]);
                        else setSelectedServerIds(prev => prev.filter(id => id !== srv.id));
                      }}
                      className="rounded border-[#2d3f36] bg-[#1a2420] text-[#4ade80]"
                    />
                    <span className="text-sm text-[#e8f5e9]">{srv.name}</span>
                  </label>
                ))}
                {filteredServers.length === 0 && (
                  <p className="text-[#6b7280] text-sm text-center py-2">No servers found</p>
                )}
              </div>
            </div>

            {/* Group Selection */}
            <div>
              <label className="block text-sm font-medium text-[#a5d6a7] mb-1">
                <FolderTree className="w-4 h-4 inline mr-1" />
                Server Groups ({selectedGroupIds.length} selected)
              </label>
              <div className="relative mb-2">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-[#6b7280]" />
                <input
                  type="text"
                  value={groupSearchQuery}
                  onChange={e => setGroupSearchQuery(e.target.value)}
                  placeholder="Search groups..."
                  className="input w-full !pl-10"
                />
              </div>
              <div className="max-h-32 overflow-y-auto space-y-1 border border-[#2d3f36] rounded-lg p-2 bg-[#0d1411]">
                {filteredGroups.map(grp => (
                  <label key={grp.id} className="flex items-center gap-2 px-2 py-1.5 rounded hover:bg-[#1a2420] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={selectedGroupIds.includes(grp.id)}
                      onChange={e => {
                        if (e.target.checked) setSelectedGroupIds(prev => [...prev, grp.id]);
                        else setSelectedGroupIds(prev => prev.filter(id => id !== grp.id));
                      }}
                      className="rounded border-[#2d3f36] bg-[#1a2420] text-[#4ade80]"
                    />
                    <span className="text-sm text-[#e8f5e9]">{grp.name}</span>
                  </label>
                ))}
                {filteredGroups.length === 0 && (
                  <p className="text-[#6b7280] text-sm text-center py-2">No groups found</p>
                )}
              </div>
            </div>

            {/* Recipients */}
            <div>
              <label className="block text-sm font-medium text-[#a5d6a7] mb-1">
                <Mail className="w-4 h-4 inline mr-1" />
                Recipients
              </label>
              <div className="flex gap-2 mb-2">
                <input
                  type="email"
                  value={recipientInput}
                  onChange={e => setRecipientInput(e.target.value)}
                  onKeyDown={handleKeyDownRecipient}
                  placeholder="email@example.com"
                  className="input flex-1"
                />
                <button
                  onClick={addRecipient}
                  className="btn bg-[#4ade80] text-[#0a0f0d] font-medium hover:bg-[#22c55e] px-4"
                >
                  <Plus className="w-4 h-4" />
                </button>
              </div>
              {recipients.length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {recipients.map(email => (
                    <span
                      key={email}
                      className="inline-flex items-center gap-1.5 px-3 py-1 bg-[#1a2420] border border-[#2d3f36] rounded-full text-sm text-[#e8f5e9]"
                    >
                      {email}
                      <button
                        onClick={() => removeRecipient(email)}
                        className="text-[#6b7280] hover:text-red-400"
                      >
                        ×
                      </button>
                    </span>
                  ))}
                </div>
              )}
              {recipients.length === 0 && (
                <p className="text-[#6b7280] text-xs">Add at least one recipient email address</p>
              )}
            </div>

            {/* Create Button */}
            <div className="pt-4">
              <button
                onClick={handleCreate}
                disabled={submitting || !name.trim() || recipients.length === 0}
                className="btn w-full bg-[#4ade80] text-[#0a0f0d] font-bold hover:bg-[#22c55e] disabled:opacity-50 disabled:cursor-not-allowed py-3 flex items-center justify-center gap-2"
              >
                {submitting ? (
                  <span>Creating...</span>
                ) : (
                  <>
                    <Plus className="w-5 h-5" />
                    Create Scheduled Report
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* ================================================================ */}
      {/* Schedules Table */}
      {/* ================================================================ */}
      <div className="card">
        <h2 className="text-xl font-bold text-[#e8f5e9] mb-4">
          Scheduled Reports ({schedules.length})
        </h2>

        {schedules.length === 0 ? (
          <div className="text-center py-12 text-[#6b7280]">
            <Clock className="w-12 h-12 mx-auto mb-3 opacity-50" />
            <p>No scheduled reports yet. Create one above.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#2d3f36]">
                  <th className="text-left py-3 px-4 text-xs font-semibold text-[#6b7280] uppercase">Name</th>
                  <th className="text-left py-3 px-4 text-xs font-semibold text-[#6b7280] uppercase">Schedule</th>
                  <th className="text-left py-3 px-4 text-xs font-semibold text-[#6b7280] uppercase">Period</th>
                  <th className="text-left py-3 px-4 text-xs font-semibold text-[#6b7280] uppercase">Recipients</th>
                  <th className="text-left py-3 px-4 text-xs font-semibold text-[#6b7280] uppercase">Next Run</th>
                  <th className="text-left py-3 px-4 text-xs font-semibold text-[#6b7280] uppercase">Last Run</th>
                  <th className="text-left py-3 px-4 text-xs font-semibold text-[#6b7280] uppercase">Status</th>
                  <th className="text-right py-3 px-4 text-xs font-semibold text-[#6b7280] uppercase">Actions</th>
                </tr>
              </thead>
              <tbody>
                {schedules.map(s => (
                  <tr
                    key={s.id}
                    className="border-b border-[#2d3f36]/50 hover:bg-[#1a2420]/50 cursor-pointer"
                    onClick={() => setDetailSchedule(s)}
                  >
                    <td className="py-3 px-4">
                      <div className="font-medium text-[#e8f5e9]">{s.name}</div>
                      <div className="text-xs text-[#6b7280]">
                        {s.serverIds.length > 0 || s.groupIds.length > 0
                          ? `${s.serverIds.length} servers, ${s.groupIds.length} groups`
                          : 'All servers'}
                      </div>
                    </td>
                    <td className="py-3 px-4 text-sm text-[#a5d6a7]">{formatSchedule(s)}</td>
                    <td className="py-3 px-4 text-sm text-[#a5d6a7]">{formatPeriod(s)}</td>
                    <td className="py-3 px-4">
                      <div className="flex flex-wrap gap-1">
                        {s.recipients.slice(0, 2).map(r => (
                          <span key={r} className="text-xs px-2 py-0.5 bg-[#1a2420] rounded text-[#a5d6a7]">{r}</span>
                        ))}
                        {s.recipients.length > 2 && (
                          <span className="text-xs text-[#6b7280]">+{s.recipients.length - 2}</span>
                        )}
                      </div>
                    </td>
                    <td className="py-3 px-4 text-sm text-[#a5d6a7]">{formatDate(s.nextRunAt)}</td>
                    <td className="py-3 px-4 text-sm text-[#a5d6a7]">
                      {formatDate(s.lastRunAt)}
                      {s.lastError && (
                        <div className="text-xs text-red-400 mt-1 truncate max-w-[200px]" title={s.lastError}>
                          {s.lastError}
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${
                        s.enabled
                          ? 'bg-green-600/20 text-green-400 border border-green-600/30'
                          : 'bg-[#1a2420] text-[#6b7280] border border-[#2d3f36]'
                      }`}>
                        {s.enabled ? <Power className="w-3 h-3" /> : <PowerOff className="w-3 h-3" />}
                        {s.enabled ? 'Active' : 'Paused'}
                      </span>
                    </td>
                    <td className="py-3 px-4" onClick={e => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => handleRunNow(s.id)}
                          title="Run now"
                          className="p-1.5 rounded text-[#a5d6a7] hover:bg-[#2d3f36] hover:text-[#4ade80]"
                        >
                          <Play className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleToggle(s.id, s.enabled)}
                          title={s.enabled ? 'Pause' : 'Activate'}
                          className="p-1.5 rounded text-[#a5d6a7] hover:bg-[#2d3f36] hover:text-[#4ade80]"
                        >
                          {s.enabled ? <PowerOff className="w-4 h-4" /> : <Power className="w-4 h-4" />}
                        </button>
                        <button
                          onClick={() => setDeleteTarget(s)}
                          title="Delete"
                          className="p-1.5 rounded text-[#a5d6a7] hover:bg-red-600/20 hover:text-red-400"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Detail Modal */}
      {detailSchedule && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
          <div className="bg-[#111916] border border-[#2d3f36] rounded-xl p-6 w-full max-w-2xl mx-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-start justify-between mb-6">
              <div>
                <h2 className="text-xl font-bold text-[#e8f5e9]">{detailSchedule.name}</h2>
                <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium mt-2 ${
                  detailSchedule.enabled
                    ? 'bg-green-600/20 text-green-400 border border-green-600/30'
                    : 'bg-[#1a2420] text-[#6b7280] border border-[#2d3f36]'
                }`}>
                  {detailSchedule.enabled ? <Power className="w-3 h-3" /> : <PowerOff className="w-3 h-3" />}
                  {detailSchedule.enabled ? 'Active' : 'Paused'}
                </span>
              </div>
              <button
                onClick={() => setDetailSchedule(null)}
                className="p-1 text-[#6b7280] hover:text-[#a5d6a7] rounded"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-4">
              {/* Schedule */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h4 className="text-xs font-semibold text-[#6b7280] uppercase mb-1">Schedule</h4>
                  <div className="flex items-center gap-2 text-[#4ade80] text-sm">
                    <Clock className="w-4 h-4" />
                    {formatSchedule(detailSchedule)}
                  </div>
                </div>
                <div>
                  <h4 className="text-xs font-semibold text-[#6b7280] uppercase mb-1">Timezone</h4>
                  <p className="text-sm text-[#a5d6a7]">{detailSchedule.timezone}</p>
                </div>
              </div>

              {/* Period & Scope */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h4 className="text-xs font-semibold text-[#6b7280] uppercase mb-1">Report Period</h4>
                  <p className="text-sm text-[#a5d6a7]">{formatPeriod(detailSchedule)}</p>
                </div>
                <div>
                  <h4 className="text-xs font-semibold text-[#6b7280] uppercase mb-1">Scope</h4>
                  <p className="text-sm text-[#a5d6a7]">
                    {detailSchedule.serverIds.length > 0 || detailSchedule.groupIds.length > 0
                      ? `${detailSchedule.serverIds.length} servers, ${detailSchedule.groupIds.length} groups`
                      : 'All servers'}
                  </p>
                </div>
              </div>

              {/* Content Options */}
              <div>
                <h4 className="text-xs font-semibold text-[#6b7280] uppercase mb-2">Report Content</h4>
                <div className="flex flex-wrap gap-2">
                  {detailSchedule.includeSeverityChart && (
                    <span className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 bg-[#1a2420] rounded-full text-[#a5d6a7] border border-[#2d3f36]">
                      <PieChart className="w-3 h-3" /> Severity Chart
                    </span>
                  )}
                  {detailSchedule.includeTrendChart && (
                    <span className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 bg-[#1a2420] rounded-full text-[#a5d6a7] border border-[#2d3f36]">
                      <TrendingUp className="w-3 h-3" /> Trend Chart
                    </span>
                  )}
                  {detailSchedule.includeTopCves && (
                    <span className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 bg-[#1a2420] rounded-full text-[#a5d6a7] border border-[#2d3f36]">
                      <Table className="w-3 h-3" /> Top 10 CVEs
                    </span>
                  )}
                  {detailSchedule.includeFullCveList && (
                    <span className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 bg-[#1a2420] rounded-full text-[#a5d6a7] border border-[#2d3f36]">
                      <List className="w-3 h-3" /> Complete CVE List
                    </span>
                  )}
                </div>
              </div>

              {/* Recipients */}
              <div>
                <h4 className="text-xs font-semibold text-[#6b7280] uppercase mb-2">
                  Recipients ({detailSchedule.recipients.length})
                </h4>
                <div className="flex flex-wrap gap-2">
                  {detailSchedule.recipients.map(r => (
                    <span key={r} className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 bg-[#1a2420] rounded-full text-[#e8f5e9] border border-[#2d3f36]">
                      <Mail className="w-3 h-3 text-[#6b7280]" />
                      {r}
                    </span>
                  ))}
                </div>
              </div>

              {/* Execution Status */}
              <div className="grid grid-cols-2 gap-4 pt-2 border-t border-[#2d3f36]">
                <div>
                  <h4 className="text-xs font-semibold text-[#6b7280] uppercase mb-1">Next Run</h4>
                  <p className="text-sm text-[#a5d6a7]">{formatDate(detailSchedule.nextRunAt)}</p>
                </div>
                <div>
                  <h4 className="text-xs font-semibold text-[#6b7280] uppercase mb-1">Last Run</h4>
                  <p className="text-sm text-[#a5d6a7]">{formatDate(detailSchedule.lastRunAt)}</p>
                </div>
              </div>

              {/* Last Error */}
              {detailSchedule.lastError && (
                <div className="p-3 rounded-lg bg-red-600/5 border border-red-600/30">
                  <h4 className="text-xs font-semibold text-red-400 uppercase mb-1 flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    Last Error
                  </h4>
                  <p className="text-sm text-red-300 whitespace-pre-wrap break-words">{detailSchedule.lastError}</p>
                </div>
              )}

              {/* Created */}
              <div className="pt-2 border-t border-[#2d3f36]">
                <p className="text-xs text-[#6b7280]">Created: {formatDate(detailSchedule.createdAt)}</p>
              </div>
            </div>

            {/* Modal Actions */}
            <div className="flex justify-end gap-3 mt-6 pt-4 border-t border-[#2d3f36]">
              <button
                onClick={() => {
                  handleToggle(detailSchedule.id, detailSchedule.enabled);
                  setDetailSchedule(prev => prev ? { ...prev, enabled: !prev.enabled } : null);
                }}
                className="btn bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36] flex items-center gap-2"
              >
                {detailSchedule.enabled ? <PowerOff className="w-4 h-4" /> : <Power className="w-4 h-4" />}
                {detailSchedule.enabled ? 'Pause' : 'Activate'}
              </button>
              <button
                onClick={() => {
                  handleRunNow(detailSchedule.id);
                  setDetailSchedule(null);
                }}
                className="btn bg-[#4ade80] text-[#0a0f0d] font-semibold hover:bg-[#22c55e] flex items-center gap-2"
              >
                <Play className="w-4 h-4" />
                Run Now
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      <ConfirmModal
        isOpen={deleteTarget !== null}
        title="Delete Scheduled Report"
        message={`Are you sure you want to delete "${deleteTarget?.name}"? This action cannot be undone.`}
        confirmLabel="Delete"
        cancelLabel="Cancel"
        variant="danger"
        onConfirm={handleDeleteConfirm}
        onCancel={() => setDeleteTarget(null)}
      />
    </div>
  );
}
