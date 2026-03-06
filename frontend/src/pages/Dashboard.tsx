import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { 
  Server, 
  Shield, 
  AlertTriangle, 
  ClipboardCheck,
  TrendingUp
} from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';
import StatCard from '../components/StatCard';
import { CVSSBadge, VendorSeverityBadge } from '../components/SeverityBadge';
import { getDashboard, getTopServers, getTopCVEs } from '../api/client';
import type { DashboardStats, TopServer, TopCVE } from '../types';

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [topServers, setTopServers] = useState<TopServer[]>([]);
  const [topCVEs, setTopCVEs] = useState<TopCVE[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function fetchData() {
      try {
        const [dashboardData, serversData, cvesData] = await Promise.all([
          getDashboard(),
          getTopServers(5),
          getTopCVEs(5),
        ]);
        setStats(dashboardData);
        setTopServers(serversData.servers || []);
        setTopCVEs(cvesData.cves || []);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load dashboard');
      } finally {
        setLoading(false);
      }
    }
    fetchData();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-[#a5d6a7]">Loading dashboard...</div>
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

  const severityData = stats?.severityBreakdown 
    ? Object.entries(stats.severityBreakdown).map(([name, value]) => ({ name, value }))
    : [];

  const severityColors: Record<string, string> = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#ca8a04',
    low: '#16a34a',
    none: '#6b7280',
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-[#e8f5e9]">Dashboard</h1>
        <p className="text-[#a5d6a7] mt-1">Overview of your vulnerability landscape</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Servers"
          value={stats?.totalServers || 0}
          icon={<Server className="w-6 h-6 text-[#4ade80]" />}
        />
        <StatCard
          title="Active Findings"
          value={stats?.activeFindings || 0}
          icon={<Shield className="w-6 h-6 text-[#4ade80]" />}
        />
        <StatCard
          title="Critical"
          value={stats?.criticalFindings || 0}
          icon={<AlertTriangle className="w-6 h-6 text-red-400" />}
          variant="critical"
        />
        <StatCard
          title="Pending Assessment"
          value={stats?.pendingAssessments || 0}
          icon={<ClipboardCheck className="w-6 h-6 text-orange-400" />}
          variant="high"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Breakdown */}
        <div className="card">
          <h2 className="text-lg font-semibold text-[#e8f5e9] mb-4">Findings by Severity</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={2}
                  dataKey="value"
                  label={({ name, value }) => `${name}: ${value}`}
                  labelLine={false}
                >
                  {severityData.map((entry, index) => (
                    <Cell 
                      key={`cell-${index}`} 
                      fill={severityColors[entry.name] || '#6b7280'} 
                    />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#111916', 
                    border: '1px solid #2d3f36',
                    borderRadius: '8px',
                    color: '#e8f5e9',
                  }}
                  itemStyle={{
                    color: '#a5d6a7',
                  }}
                  labelStyle={{
                    color: '#e8f5e9',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Top Servers */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-[#e8f5e9]">Most Affected Servers</h2>
            <Link to="/servers" className="text-sm text-[#4ade80] hover:underline">
              View all
            </Link>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={topServers} layout="vertical">
                <XAxis type="number" stroke="#6b7280" />
                <YAxis
                  type="category"
                  dataKey="name"
                  stroke="#6b7280"
                  width={Math.min(Math.max(...topServers.map(s => s.name.length), 0) * 7 + 8, 220)}
                  tick={{ fontSize: 12 }}
                />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#111916', 
                    border: '1px solid #2d3f36',
                    borderRadius: '8px',
                    color: '#e8f5e9',
                  }}
                  itemStyle={{
                    color: '#a5d6a7',
                  }}
                  labelStyle={{
                    color: '#e8f5e9',
                  }}
                />
                <Bar dataKey="criticalCount" stackId="a" fill="#dc2626" name="Critical" />
                <Bar dataKey="highCount" stackId="a" fill="#ea580c" name="High" />
                <Bar dataKey="findingsCount" fill="#4ade80" name="Total" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Top CVEs Table */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-[#e8f5e9]">Top CVEs by Impact</h2>
          <Link to="/findings" className="text-sm text-[#4ade80] hover:underline">
            View all findings
          </Link>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#2d3f36]">
                <th className="table-header text-left py-3 px-4">CVE ID</th>
                <th className="table-header text-left py-3 px-4">CVSS</th>
                <th className="table-header text-left py-3 px-4">Vendor</th>
                <th className="table-header text-left py-3 px-4">Affected Servers</th>
                <th className="table-header text-left py-3 px-4">Packages</th>
              </tr>
            </thead>
            <tbody>
              {topCVEs.map((cve) => (
                <tr key={cve.cveId} className="table-row">
                  <td className="py-3 px-4">
                    <span className="font-mono text-[#e8f5e9]">{cve.cveId}</span>
                  </td>
                  <td className="py-3 px-4">
                    <CVSSBadge score={cve.cvss3Score} cveId={cve.cveId} />
                  </td>
                  <td className="py-3 px-4">
                    <VendorSeverityBadge severity={cve.severity} sourceLink={cve.sourceLink || undefined} />
                  </td>
                  <td className="py-3 px-4 text-[#a5d6a7]">{cve.serverCount}</td>
                  <td className="py-3 px-4 text-[#a5d6a7]">{cve.packageCount}</td>
                </tr>
              ))}
              {topCVEs.length === 0 && (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-[#6b7280]">
                    No CVEs found
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Link to="/triage" className="card card-hover group">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-orange-600/20 rounded-lg flex items-center justify-center group-hover:bg-orange-600/30 transition-colors">
              <ClipboardCheck className="w-6 h-6 text-orange-400" />
            </div>
            <div>
              <h3 className="font-semibold text-[#e8f5e9]">Start Triage</h3>
              <p className="text-sm text-[#a5d6a7]">{stats?.pendingAssessments || 0} findings need review</p>
            </div>
          </div>
        </Link>

        <Link to="/statistics" className="card card-hover group">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-[#4ade80]/20 rounded-lg flex items-center justify-center group-hover:bg-[#4ade80]/30 transition-colors">
              <TrendingUp className="w-6 h-6 text-[#4ade80]" />
            </div>
            <div>
              <h3 className="font-semibold text-[#e8f5e9]">View Statistics</h3>
              <p className="text-sm text-[#a5d6a7]">Trends and detailed reports</p>
            </div>
          </div>
        </Link>

        <Link to="/servers" className="card card-hover group">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-blue-600/20 rounded-lg flex items-center justify-center group-hover:bg-blue-600/30 transition-colors">
              <Server className="w-6 h-6 text-blue-400" />
            </div>
            <div>
              <h3 className="font-semibold text-[#e8f5e9]">Server Overview</h3>
              <p className="text-sm text-[#a5d6a7]">{stats?.totalServers || 0} servers monitored</p>
            </div>
          </div>
        </Link>
      </div>
    </div>
  );
}
