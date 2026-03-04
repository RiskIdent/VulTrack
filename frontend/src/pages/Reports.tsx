import { useEffect, useState, useMemo } from 'react';
import { FileText, Server, FolderTree, Calendar, Search, Check, PieChart, TrendingUp, Table, List, Clock } from 'lucide-react';
import { getServers, getServerGroups, generateReport } from '../api/client';
import type { Server as ServerType, ServerGroup } from '../types';
import PlannedReports from './PlannedReports';

export default function Reports() {
  const [activeTab, setActiveTab] = useState<'generate' | 'planned'>('generate');

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-[#e8f5e9]">Reports</h1>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-[#2d3f36]">
        <button
          onClick={() => setActiveTab('generate')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'generate'
              ? 'border-[#4ade80] text-[#4ade80]'
              : 'border-transparent text-[#6b7280] hover:text-[#a5d6a7]'
          }`}
        >
          <FileText className="w-4 h-4" />
          Generate Report
        </button>
        <button
          onClick={() => setActiveTab('planned')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'planned'
              ? 'border-[#4ade80] text-[#4ade80]'
              : 'border-transparent text-[#6b7280] hover:text-[#a5d6a7]'
          }`}
        >
          <Clock className="w-4 h-4" />
          Scheduled Reports
        </button>
      </div>

      {/* Tab Content */}
      {activeTab === 'generate' ? <ReportGenerator /> : <PlannedReports />}
    </div>
  );
}

function ReportGenerator() {
  // Data
  const [servers, setServers] = useState<ServerType[]>([]);
  const [groups, setGroups] = useState<ServerGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Selection
  const [selectedServerIds, setSelectedServerIds] = useState<number[]>([]);
  const [selectedGroupIds, setSelectedGroupIds] = useState<number[]>([]);
  const [serverSearchQuery, setServerSearchQuery] = useState('');
  const [groupSearchQuery, setGroupSearchQuery] = useState('');

  // Date range
  const [startDate, setStartDate] = useState(() => {
    const date = new Date();
    date.setDate(date.getDate() - 30);
    return date.toISOString().split('T')[0];
  });
  const [endDate, setEndDate] = useState(() => {
    return new Date().toISOString().split('T')[0];
  });

  // Content options
  const [includeSeverityChart, setIncludeSeverityChart] = useState(true);
  const [includeTrendChart, setIncludeTrendChart] = useState(true);
  const [includeTopCVEs, setIncludeTopCVEs] = useState(true);
  const [includeFullCVEList, setIncludeFullCVEList] = useState(false);

  // Report generation
  const [generating, setGenerating] = useState(false);
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    fetchData();
  }, []);

  async function fetchData() {
    setLoading(true);
    try {
      const [serversData, groupsData] = await Promise.all([
        getServers(),
        getServerGroups(),
      ]);
      setServers(serversData.servers || []);
      setGroups(groupsData.groups || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load data');
    } finally {
      setLoading(false);
    }
  }

  // Filtered servers
  const filteredServers = useMemo(() => {
    if (!serverSearchQuery.trim()) return servers;
    const query = serverSearchQuery.toLowerCase();
    return servers.filter(s =>
      s.name.toLowerCase().includes(query) ||
      s.osFamily?.toLowerCase().includes(query) ||
      s.ipv4Addrs?.some(ip => ip.includes(query))
    );
  }, [servers, serverSearchQuery]);

  // Filtered groups
  const filteredGroups = useMemo(() => {
    if (!groupSearchQuery.trim()) return groups;
    const query = groupSearchQuery.toLowerCase();
    return groups.filter(g =>
      g.name.toLowerCase().includes(query) ||
      g.description?.toLowerCase().includes(query)
    );
  }, [groups, groupSearchQuery]);

  function toggleServer(id: number) {
    setSelectedServerIds(prev =>
      prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
    );
  }

  function toggleGroup(id: number) {
    setSelectedGroupIds(prev =>
      prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
    );
  }

  function selectAllServers() {
    setSelectedServerIds(servers.map(s => s.id));
  }

  function clearServerSelection() {
    setSelectedServerIds([]);
  }

  function selectAllGroups() {
    setSelectedGroupIds(groups.map(g => g.id));
  }

  function clearGroupSelection() {
    setSelectedGroupIds([]);
  }

  async function handleGenerateReport() {
    setGenerating(true);
    setError(null);
    setSuccess(false);

    try {
      const blob = await generateReport({
        serverIds: selectedServerIds.length > 0 ? selectedServerIds : undefined,
        groupIds: selectedGroupIds.length > 0 ? selectedGroupIds : undefined,
        startDate,
        endDate,
        reportType: 'vulnerability_summary',
        includeSeverityChart,
        includeTrendChart,
        includeTopCVEs,
        includeFullCVEList,
      });

      // Create download link
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vultrack-report-${new Date().toISOString().split('T')[0]}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      setSuccess(true);
      setTimeout(() => setSuccess(false), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate report');
    } finally {
      setGenerating(false);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-[#a5d6a7]">Loading...</div>
      </div>
    );
  }

  const scopeDescription = selectedServerIds.length === 0 && selectedGroupIds.length === 0
    ? 'All servers'
    : `${selectedServerIds.length} servers, ${selectedGroupIds.length} groups`;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <p className="text-[#a5d6a7]">
          Generate a one-time PDF report for vulnerability analysis
        </p>
      </div>

      {/* Error/Success Messages */}
      {error && (
        <div className="p-4 bg-red-600/10 border border-red-600/50 rounded-lg text-red-400">
          {error}
        </div>
      )}
      {success && (
        <div className="p-4 bg-green-600/10 border border-green-600/50 rounded-lg text-green-400 flex items-center gap-2">
          <Check className="w-5 h-5" />
          Report generated and downloaded successfully!
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Server Selection */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-[#e8f5e9] flex items-center gap-2">
              <Server className="w-5 h-5 text-[#4ade80]" />
              Servers
            </h2>
            <div className="flex gap-2">
              <button
                onClick={selectAllServers}
                className="text-xs text-[#4ade80] hover:underline"
              >
                Select All
              </button>
              <span className="text-[#6b7280]">|</span>
              <button
                onClick={clearServerSelection}
                className="text-xs text-[#a5d6a7] hover:underline"
              >
                Clear
              </button>
            </div>
          </div>

          {/* Search */}
          <div className="relative mb-4">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#6b7280]" />
            <input
              type="text"
              placeholder="Search servers..."
              value={serverSearchQuery}
              onChange={(e) => setServerSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] placeholder-[#6b7280] focus:outline-none focus:border-[#4ade80]"
            />
          </div>

          {/* Server List */}
          <div className="max-h-64 overflow-y-auto space-y-1">
            {filteredServers.map(server => (
              <label
                key={server.id}
                className={`flex items-center gap-3 px-3 py-2 rounded-lg cursor-pointer transition-colors ${
                  selectedServerIds.includes(server.id)
                    ? 'bg-[#4ade80]/20 border border-[#4ade80]/50'
                    : 'bg-[#1a2420] border border-transparent hover:border-[#2d3f36]'
                }`}
              >
                <input
                  type="checkbox"
                  checked={selectedServerIds.includes(server.id)}
                  onChange={() => toggleServer(server.id)}
                  className="w-4 h-4 rounded text-[#4ade80] bg-[#1a2420] border-[#2d3f36] focus:ring-[#4ade80]"
                />
                <div className="flex-1 min-w-0">
                  <div className="text-[#e8f5e9] truncate">{server.name}</div>
                  <div className="text-xs text-[#6b7280]">{server.osFamily}</div>
                </div>
              </label>
            ))}
            {filteredServers.length === 0 && (
              <div className="text-center py-4 text-[#6b7280]">
                No servers found
              </div>
            )}
          </div>

          <div className="mt-3 text-sm text-[#a5d6a7]">
            {selectedServerIds.length} of {servers.length} servers selected
          </div>
        </div>

        {/* Group Selection */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-[#e8f5e9] flex items-center gap-2">
              <FolderTree className="w-5 h-5 text-[#4ade80]" />
              Server Groups
            </h2>
            <div className="flex gap-2">
              <button
                onClick={selectAllGroups}
                className="text-xs text-[#4ade80] hover:underline"
              >
                Select All
              </button>
              <span className="text-[#6b7280]">|</span>
              <button
                onClick={clearGroupSelection}
                className="text-xs text-[#a5d6a7] hover:underline"
              >
                Clear
              </button>
            </div>
          </div>

          {/* Search */}
          <div className="relative mb-4">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#6b7280]" />
            <input
              type="text"
              placeholder="Search groups..."
              value={groupSearchQuery}
              onChange={(e) => setGroupSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] placeholder-[#6b7280] focus:outline-none focus:border-[#4ade80]"
            />
          </div>

          {/* Group List */}
          <div className="max-h-64 overflow-y-auto space-y-1">
            {filteredGroups.map(group => (
              <label
                key={group.id}
                className={`flex items-center gap-3 px-3 py-2 rounded-lg cursor-pointer transition-colors ${
                  selectedGroupIds.includes(group.id)
                    ? 'bg-[#4ade80]/20 border border-[#4ade80]/50'
                    : 'bg-[#1a2420] border border-transparent hover:border-[#2d3f36]'
                }`}
              >
                <input
                  type="checkbox"
                  checked={selectedGroupIds.includes(group.id)}
                  onChange={() => toggleGroup(group.id)}
                  className="w-4 h-4 rounded text-[#4ade80] bg-[#1a2420] border-[#2d3f36] focus:ring-[#4ade80]"
                />
                <div
                  className="w-3 h-3 rounded-full"
                  style={{ backgroundColor: group.color || '#4ade80' }}
                />
                <div className="flex-1 min-w-0">
                  <div className="text-[#e8f5e9] truncate">{group.name}</div>
                  <div className="text-xs text-[#6b7280]">
                    {group.serverCount ?? 0} servers
                  </div>
                </div>
              </label>
            ))}
            {filteredGroups.length === 0 && (
              <div className="text-center py-4 text-[#6b7280]">
                No groups found
              </div>
            )}
          </div>

          <div className="mt-3 text-sm text-[#a5d6a7]">
            {selectedGroupIds.length} of {groups.length} groups selected
          </div>
        </div>
      </div>

      {/* Date Range */}
      <div className="card">
        <h2 className="text-lg font-semibold text-[#e8f5e9] mb-4 flex items-center gap-2">
          <Calendar className="w-5 h-5 text-[#4ade80]" />
          Report Period
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Start Date */}
          <div>
            <label className="block text-sm text-[#a5d6a7] mb-2">Start Date</label>
            <input
              type="date"
              value={startDate}
              onChange={(e) => setStartDate(e.target.value)}
              className="w-full px-3 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] focus:outline-none focus:border-[#4ade80]"
            />
          </div>

          {/* End Date */}
          <div>
            <label className="block text-sm text-[#a5d6a7] mb-2">End Date</label>
            <input
              type="date"
              value={endDate}
              onChange={(e) => setEndDate(e.target.value)}
              className="w-full px-3 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] focus:outline-none focus:border-[#4ade80]"
            />
          </div>

          {/* Scope Summary */}
          <div>
            <label className="block text-sm text-[#a5d6a7] mb-2">Scope</label>
            <div className="px-3 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9]">
              {scopeDescription}
            </div>
          </div>
        </div>
      </div>

      {/* Report Content Options */}
      <div className="card">
        <h2 className="text-lg font-semibold text-[#e8f5e9] mb-4 flex items-center gap-2">
          <List className="w-5 h-5 text-[#4ade80]" />
          Report Content
        </h2>

        <p className="text-sm text-[#6b7280] mb-4">
          Select which sections to include in the PDF report. The report period, scope (with resolved server names), and executive summary are always included.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Severity Distribution Chart */}
          <label
            className={`flex items-center gap-4 p-4 rounded-lg cursor-pointer transition-colors ${
              includeSeverityChart
                ? 'bg-[#4ade80]/20 border border-[#4ade80]/50'
                : 'bg-[#1a2420] border border-[#2d3f36] hover:border-[#4ade80]/30'
            }`}
          >
            <input
              type="checkbox"
              checked={includeSeverityChart}
              onChange={(e) => setIncludeSeverityChart(e.target.checked)}
              className="w-5 h-5 rounded text-[#4ade80] bg-[#1a2420] border-[#2d3f36] focus:ring-[#4ade80]"
            />
            <PieChart className="w-6 h-6 text-[#4ade80]" />
            <div>
              <div className="text-[#e8f5e9] font-medium">Severity Distribution</div>
              <div className="text-xs text-[#6b7280]">Pie chart showing breakdown by severity level</div>
            </div>
          </label>

          {/* Findings Trend Chart */}
          <label
            className={`flex items-center gap-4 p-4 rounded-lg cursor-pointer transition-colors ${
              includeTrendChart
                ? 'bg-[#4ade80]/20 border border-[#4ade80]/50'
                : 'bg-[#1a2420] border border-[#2d3f36] hover:border-[#4ade80]/30'
            }`}
          >
            <input
              type="checkbox"
              checked={includeTrendChart}
              onChange={(e) => setIncludeTrendChart(e.target.checked)}
              className="w-5 h-5 rounded text-[#4ade80] bg-[#1a2420] border-[#2d3f36] focus:ring-[#4ade80]"
            />
            <TrendingUp className="w-6 h-6 text-[#4ade80]" />
            <div>
              <div className="text-[#e8f5e9] font-medium">Findings Trend</div>
              <div className="text-xs text-[#6b7280]">Line chart showing new findings over time</div>
            </div>
          </label>

          {/* Top CVEs Table */}
          <label
            className={`flex items-center gap-4 p-4 rounded-lg cursor-pointer transition-colors ${
              includeTopCVEs
                ? 'bg-[#4ade80]/20 border border-[#4ade80]/50'
                : 'bg-[#1a2420] border border-[#2d3f36] hover:border-[#4ade80]/30'
            }`}
          >
            <input
              type="checkbox"
              checked={includeTopCVEs}
              onChange={(e) => setIncludeTopCVEs(e.target.checked)}
              className="w-5 h-5 rounded text-[#4ade80] bg-[#1a2420] border-[#2d3f36] focus:ring-[#4ade80]"
            />
            <Table className="w-6 h-6 text-[#4ade80]" />
            <div>
              <div className="text-[#e8f5e9] font-medium">Top 10 CVEs</div>
              <div className="text-xs text-[#6b7280]">Table of most widespread vulnerabilities</div>
            </div>
          </label>

          {/* Full CVE List */}
          <label
            className={`flex items-center gap-4 p-4 rounded-lg cursor-pointer transition-colors ${
              includeFullCVEList
                ? 'bg-[#4ade80]/20 border border-[#4ade80]/50'
                : 'bg-[#1a2420] border border-[#2d3f36] hover:border-[#4ade80]/30'
            }`}
          >
            <input
              type="checkbox"
              checked={includeFullCVEList}
              onChange={(e) => setIncludeFullCVEList(e.target.checked)}
              className="w-5 h-5 rounded text-[#4ade80] bg-[#1a2420] border-[#2d3f36] focus:ring-[#4ade80]"
            />
            <List className="w-6 h-6 text-[#4ade80]" />
            <div>
              <div className="text-[#e8f5e9] font-medium">Complete CVE List</div>
              <div className="text-xs text-[#6b7280]">Full list of all CVEs with summaries (may be long)</div>
            </div>
          </label>
        </div>

        {/* Generate Button */}
        <div className="mt-6 pt-4 border-t border-[#2d3f36]">
          <button
            onClick={handleGenerateReport}
            disabled={generating}
            className="btn bg-[#4ade80] text-[#0a0f0d] font-semibold hover:bg-[#22c55e] disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
          >
            {generating ? (
              <>
                <div className="w-4 h-4 border-2 border-[#0a0f0d] border-t-transparent rounded-full animate-spin" />
                Generating...
              </>
            ) : (
              <>
                <FileText className="w-4 h-4" />
                Generate PDF Report
              </>
            )}
          </button>
        </div>
      </div>

      {/* Info Card */}
      <div className="card bg-blue-600/5 border-blue-600/50">
        <h3 className="text-[#e8f5e9] font-semibold mb-2">Always Included</h3>
        <ul className="text-[#a5d6a7] text-sm space-y-1">
          <li>• <strong>Report Period:</strong> Start and end date of the analysis</li>
          <li>• <strong>Scope:</strong> List of all included servers (groups are resolved to server names)</li>
          <li>• <strong>Executive Summary:</strong> Total, active, and resolved findings with severity breakdown</li>
        </ul>
      </div>
    </div>
  );
}
