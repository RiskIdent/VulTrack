import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { 
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar, PieChart, Pie, Cell
} from 'recharts';
import { getTrendStats, getTopServers, getTopCVEs, getSeverityStats, getAssessmentsBySeverity } from '../api/client';
import { CVSSBadge, VendorSeverityBadge } from '../components/SeverityBadge';
import type { TrendDataPoint, TopServer, TopCVE, AssessmentBySeverity } from '../types';

export default function Statistics() {
  const [trend, setTrend] = useState<TrendDataPoint[]>([]);
  const [topServers, setTopServers] = useState<TopServer[]>([]);
  const [topCVEs, setTopCVEs] = useState<TopCVE[]>([]);
  const [severity, setSeverity] = useState<Record<string, number>>({});
  const [assessmentStats, setAssessmentStats] = useState<AssessmentBySeverity[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [days, setDays] = useState(30);

  useEffect(() => {
    async function fetchData() {
      try {
        const [trendData, serversData, cvesData, severityData, assessmentData] = await Promise.all([
          getTrendStats(days),
          getTopServers(10),
          getTopCVEs(10),
          getSeverityStats(),
          getAssessmentsBySeverity(),
        ]);
        setTrend(trendData.trend || []);
        setTopServers(serversData.servers || []);
        setTopCVEs(cvesData.cves || []);
        setSeverity(severityData.breakdown || {});
        setAssessmentStats(assessmentData.stats || []);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load statistics');
      } finally {
        setLoading(false);
      }
    }
    fetchData();
  }, [days]);

  const severityColors: Record<string, string> = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#ca8a04',
    low: '#16a34a',
    none: '#6b7280',
  };

  const severityData = Object.entries(severity).map(([name, value]) => ({ name, value }));

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-[#a5d6a7]">Loading statistics...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card border-red-600/50 bg-red-600/5">
        <p className="text-red-400">{error}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[#e8f5e9]">Statistics</h1>
          <p className="text-[#a5d6a7] mt-1">Trends and detailed analysis</p>
        </div>
        <div>
          <select
            className="input"
            value={days}
            onChange={(e) => setDays(parseInt(e.target.value))}
          >
            <option value="7">Last 7 days</option>
            <option value="30">Last 30 days</option>
            <option value="90">Last 90 days</option>
          </select>
        </div>
      </div>

      {/* Info Banner */}
      <div className="flex items-center gap-2 px-4 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-sm text-[#a5d6a7]">
        <span className="text-[#6b7280]">ℹ</span>
        Severity distribution and server rankings are based on vendor severity ratings, not CVSS scores.
      </div>

      {/* Trend Chart */}
      <div className="card">
        <h2 className="text-lg font-semibold text-[#e8f5e9] mb-4">Findings Trend</h2>
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={trend}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2d3f36" />
              <XAxis 
                dataKey="date" 
                stroke="#6b7280"
                tick={{ fontSize: 12 }}
                tickFormatter={(value) => new Date(value).toLocaleDateString('en', { month: 'short', day: 'numeric' })}
              />
              <YAxis stroke="#6b7280" />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: '#111916', 
                  border: '1px solid #2d3f36',
                  borderRadius: '8px',
                  color: '#e8f5e9',
                }}
                itemStyle={{ color: '#a5d6a7' }}
                labelStyle={{ color: '#e8f5e9' }}
              />
              <Line 
                type="monotone" 
                dataKey="newFindings" 
                stroke="#ea580c" 
                name="New Findings"
                strokeWidth={2}
                dot={false}
              />
              <Line 
                type="monotone" 
                dataKey="resolvedCount" 
                stroke="#22c55e" 
                name="Resolved"
                strokeWidth={2}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Distribution */}
        <div className="card">
          <h2 className="text-lg font-semibold text-[#e8f5e9] mb-4">Severity Distribution</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  outerRadius={80}
                  dataKey="value"
                  label={({ name, percent }) => `${name} (${(percent * 100).toFixed(0)}%)`}
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={severityColors[entry.name] || '#6b7280'} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#111916', 
                    border: '1px solid #2d3f36',
                    borderRadius: '8px',
                    color: '#e8f5e9',
                  }}
                  itemStyle={{ color: '#a5d6a7' }}
                  labelStyle={{ color: '#e8f5e9' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Top Servers */}
        <div className="card">
          <h2 className="text-lg font-semibold text-[#e8f5e9] mb-4">Top 10 Affected Servers</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={topServers} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#2d3f36" />
                <XAxis type="number" stroke="#6b7280" />
                <YAxis
                  type="category"
                  dataKey="name"
                  stroke="#6b7280"
                  width={Math.min(Math.max(...topServers.map(s => s.name.length), 0) * 7 + 8, 220)}
                  tick={{ fontSize: 11 }}
                />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#111916', 
                    border: '1px solid #2d3f36',
                    borderRadius: '8px',
                    color: '#e8f5e9',
                  }}
                  itemStyle={{ color: '#a5d6a7' }}
                  labelStyle={{ color: '#e8f5e9' }}
                />
                <Bar dataKey="criticalCount" stackId="a" fill="#dc2626" name="Critical" />
                <Bar dataKey="highCount" stackId="a" fill="#ea580c" name="High" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Top CVEs Table */}
      <div className="card">
        <h2 className="text-lg font-semibold text-[#e8f5e9] mb-4">Most Widespread CVEs</h2>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#2d3f36]">
                <th className="table-header text-left py-3 px-4">CVE ID</th>
                <th className="table-header text-left py-3 px-4">CVSS</th>
                <th className="table-header text-left py-3 px-4">Vendor</th>
                <th className="table-header text-left py-3 px-4">Affected Servers</th>
                <th className="table-header text-left py-3 px-4">Affected Packages</th>
              </tr>
            </thead>
            <tbody>
              {topCVEs.map((cve, index) => (
                <tr key={cve.cveId} className="table-row">
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-2">
                      <span className="text-[#6b7280] text-sm w-6">{index + 1}.</span>
                      <span className="font-mono text-[#e8f5e9]">{cve.cveId}</span>
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <CVSSBadge score={cve.cvss3Score} cveId={cve.cveId} />
                  </td>
                  <td className="py-3 px-4">
                    <VendorSeverityBadge severity={cve.severity} sourceLink={cve.sourceLink || undefined} />
                  </td>
                  <td className="py-3 px-4">
                    <Link 
                      to={`/findings?search=${encodeURIComponent(cve.cveId)}`}
                      className="text-[#4ade80] hover:underline"
                    >
                      {cve.serverCount}
                    </Link>
                  </td>
                  <td className="py-3 px-4">
                    <Link 
                      to={`/findings?search=${encodeURIComponent(cve.cveId)}`}
                      className="text-[#4ade80] hover:underline"
                    >
                      {cve.packageCount}
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Assessment Statistics by Severity */}
      <div className="card">
        <h2 className="text-lg font-semibold text-[#e8f5e9] mb-4">Assessment Status by Severity</h2>
        <p className="text-sm text-[#6b7280] mb-4">
          Shows how active findings are distributed across triage statuses for each severity level.
        </p>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#2d3f36]">
                <th className="table-header text-left py-3 px-4">Severity</th>
                <th className="table-header text-right py-3 px-4">Pending</th>
                <th className="table-header text-right py-3 px-4">Relevant</th>
                <th className="table-header text-right py-3 px-4">Not Relevant</th>
                <th className="table-header text-right py-3 px-4">Accepted Risk</th>
                <th className="table-header text-right py-3 px-4">Total</th>
              </tr>
            </thead>
            <tbody>
              {assessmentStats.map((stat) => (
                <tr key={stat.severity} className="table-row">
                  <td className="py-3 px-4">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${
                      stat.severity === 'critical' ? 'bg-red-600/20 text-red-400' :
                      stat.severity === 'high' ? 'bg-orange-600/20 text-orange-400' :
                      stat.severity === 'medium' ? 'bg-yellow-600/20 text-yellow-400' :
                      stat.severity === 'low' ? 'bg-green-600/20 text-green-400' :
                      'bg-gray-600/20 text-gray-400'
                    }`}>
                      {stat.severity.charAt(0).toUpperCase() + stat.severity.slice(1)}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right">
                    {stat.pending > 0 ? (
                      <span className="px-2 py-1 rounded text-xs font-medium bg-blue-600/20 text-blue-400">
                        {stat.pending}
                      </span>
                    ) : (
                      <span className="text-[#6b7280]">0</span>
                    )}
                  </td>
                  <td className="py-3 px-4 text-right">
                    {stat.relevant > 0 ? (
                      <span className="px-2 py-1 rounded text-xs font-medium bg-red-600/20 text-red-400">
                        {stat.relevant}
                      </span>
                    ) : (
                      <span className="text-[#6b7280]">0</span>
                    )}
                  </td>
                  <td className="py-3 px-4 text-right">
                    {stat.notRelevant > 0 ? (
                      <span className="px-2 py-1 rounded text-xs font-medium bg-green-600/20 text-green-400">
                        {stat.notRelevant}
                      </span>
                    ) : (
                      <span className="text-[#6b7280]">0</span>
                    )}
                  </td>
                  <td className="py-3 px-4 text-right">
                    {stat.acceptedRisk > 0 ? (
                      <span className="px-2 py-1 rounded text-xs font-medium bg-yellow-600/20 text-yellow-400">
                        {stat.acceptedRisk}
                      </span>
                    ) : (
                      <span className="text-[#6b7280]">0</span>
                    )}
                  </td>
                  <td className="py-3 px-4 text-right font-medium text-[#e8f5e9]">
                    {stat.total}
                  </td>
                </tr>
              ))}
              {/* Totals Row */}
              {assessmentStats.length > 0 && (
                <tr className="border-t border-[#2d3f36] bg-[#1a2420]">
                  <td className="py-3 px-4 font-medium text-[#e8f5e9]">Total</td>
                  <td className="py-3 px-4 text-right font-medium text-blue-400">
                    {assessmentStats.reduce((sum, s) => sum + s.pending, 0)}
                  </td>
                  <td className="py-3 px-4 text-right font-medium text-red-400">
                    {assessmentStats.reduce((sum, s) => sum + s.relevant, 0)}
                  </td>
                  <td className="py-3 px-4 text-right font-medium text-green-400">
                    {assessmentStats.reduce((sum, s) => sum + s.notRelevant, 0)}
                  </td>
                  <td className="py-3 px-4 text-right font-medium text-yellow-400">
                    {assessmentStats.reduce((sum, s) => sum + s.acceptedRisk, 0)}
                  </td>
                  <td className="py-3 px-4 text-right font-bold text-[#e8f5e9]">
                    {assessmentStats.reduce((sum, s) => sum + s.total, 0)}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
