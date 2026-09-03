const API_BASE = (import.meta.env.VITE_API_URL || '/api/v1').replace(/\/$/, '');

// ApiError carries the HTTP status so callers can distinguish cases (e.g. a 404
// "not found" from a real failure). It extends Error, so existing callers that
// read err.message keep working unchanged.
export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

async function fetchAPI<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  });

  if (!response.ok) {
    if (response.status === 401 && typeof window !== 'undefined' && !window.location.pathname.startsWith('/login')) {
      window.location.href = '/login';
    }
    const error = await response.json().catch(() => ({ error: 'Unknown error' }));
    throw new ApiError(response.status, error.error || `HTTP error ${response.status}`);
  }

  // Handle 204 No Content responses
  if (response.status === 204) {
    return undefined as T;
  }

  return response.json();
}

// =============================================================================
// Auth
// =============================================================================

export interface AuthMeResponse {
  authEnabled: boolean;
  id?: number;
  email?: string;
  name?: string;
  isAdmin?: boolean;
  error?: string;
}

export async function getAuthMe(): Promise<AuthMeResponse> {
  const response = await fetch(`${API_BASE}/auth/me`, {
    credentials: 'include',
    headers: { Accept: 'application/json' },
  });
  const data = await response.json().catch(() => ({}));
  if (response.status === 401) {
    return { authEnabled: true };
  }
  if (!response.ok) {
    throw new Error((data as { error?: string }).error || `HTTP ${response.status}`);
  }
  return data as AuthMeResponse;
}

export function getLoginURL(): string {
  return `${API_BASE}/auth/login`;
}

export async function logout(): Promise<void> {
  const response = await fetch(`${API_BASE}/auth/logout`, {
    method: 'POST',
    credentials: 'include',
    headers: { Accept: 'application/json' },
  });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error((data as { error?: string }).error || 'Logout failed');
  }
  // Backend may return redirect; caller can navigate as needed
}

// Dashboard
export const getDashboard = () => fetchAPI<{
  totalServers: number;
  totalFindings: number;
  activeFindings: number;
  resolvedFindings: number;
  criticalFindings: number;
  highFindings: number;
  pendingAssessments: number;
  severityBreakdown: Record<string, number>;
}>('/dashboard');

// Servers
export const getServers = () => fetchAPI<{
  servers: import('../types').Server[];
  total: number;
}>('/servers');

export const getServer = (id: number) => 
  fetchAPI<import('../types').Server>(`/servers/${id}`);

export const deleteServer = (id: number) =>
  fetchAPI<{ message: string; serverId: number }>(`/admin/servers/${id}`, {
    method: 'DELETE',
  });

export const getServerFindings = (id: number, params?: { includeResolved?: boolean; limit?: number; offset?: number }) => {
  const searchParams = new URLSearchParams();
  if (params?.includeResolved) searchParams.set('includeResolved', 'true');
  if (params?.limit) searchParams.set('limit', params.limit.toString());
  if (params?.offset) searchParams.set('offset', params.offset.toString());
  
  return fetchAPI<{
    findings: import('../types').Finding[];
    total: number;
    limit: number;
    offset: number;
  }>(`/servers/${id}/findings?${searchParams}`);
};

export const getServerPackages = (id: number) =>
  fetchAPI<{
    packages: import('../types').ServerPackage[];
    activeCount: number;
  }>(`/servers/${id}/packages`);

export const triggerServerScan = (id: number) =>
  fetchAPI<{ message: string }>(`/servers/${id}/scan`, { method: 'POST' });

// Findings
export const getFindings = (params?: {
  cveId?: string;
  severity?: string;
  minCvss?: number;
  includeResolved?: boolean;
  search?: string;
  sortBy?: string;
  sortOrder?: string;
  limit?: number;
  offset?: number;
  vexStatus?: string;
}) => {
  const searchParams = new URLSearchParams();
  if (params?.cveId) searchParams.set('cveId', params.cveId);
  if (params?.severity) searchParams.set('severity', params.severity);
  if (params?.minCvss) searchParams.set('minCvss', params.minCvss.toString());
  if (params?.includeResolved) searchParams.set('includeResolved', 'true');
  if (params?.search) searchParams.set('search', params.search);
  if (params?.sortBy) searchParams.set('sortBy', params.sortBy);
  if (params?.sortOrder) searchParams.set('sortOrder', params.sortOrder);
  if (params?.limit) searchParams.set('limit', params.limit.toString());
  if (params?.offset != null) searchParams.set('offset', params.offset.toString());
  if (params?.vexStatus) searchParams.set('vexStatus', params.vexStatus);
  
  return fetchAPI<{
    findings: import('../types').Finding[];
    total: number;
    limit: number;
    offset: number;
  }>(`/findings?${searchParams}`);
};

// Findings grouped by (server, CVE). Each group bundles the package-level rows
// for the same CVE on the same server. Pagination is over groups, not packages.
export const getFindingsGrouped = (params?: {
  cveId?: string;
  severity?: string;
  minCvss?: number;
  includeResolved?: boolean;
  search?: string;
  sortBy?: string;
  sortOrder?: string;
  limit?: number;
  offset?: number;
  vexStatus?: string;
}) => {
  const searchParams = new URLSearchParams();
  searchParams.set('grouped', 'true');
  if (params?.cveId) searchParams.set('cveId', params.cveId);
  if (params?.severity) searchParams.set('severity', params.severity);
  if (params?.minCvss) searchParams.set('minCvss', params.minCvss.toString());
  if (params?.includeResolved) searchParams.set('includeResolved', 'true');
  if (params?.search) searchParams.set('search', params.search);
  if (params?.sortBy) searchParams.set('sortBy', params.sortBy);
  if (params?.sortOrder) searchParams.set('sortOrder', params.sortOrder);
  if (params?.limit) searchParams.set('limit', params.limit.toString());
  if (params?.offset != null) searchParams.set('offset', params.offset.toString());
  if (params?.vexStatus) searchParams.set('vexStatus', params.vexStatus);

  return fetchAPI<{
    groups: import('../types').GroupedFinding[];
    total: number;
    limit: number;
    offset: number;
  }>(`/findings?${searchParams}`);
};

export interface TriageFilter {
  mode: 'cvss' | 'vendor_severity';
  threshold?: number;
  severities?: string[];
  includeUnrated?: boolean;
}

export const getTriageQueue = (params?: { minCvss?: number; limit?: number; offset?: number; hideVexNotAffected?: boolean }) => {
  const searchParams = new URLSearchParams();
  if (params?.minCvss) searchParams.set('minCvss', params.minCvss.toString());
  if (params?.limit) searchParams.set('limit', params.limit.toString());
  if (params?.offset) searchParams.set('offset', params.offset.toString());
  if (params?.hideVexNotAffected === false) searchParams.set('hideVexNotAffected', 'false');
  
  return fetchAPI<{
    findings: import('../types').Finding[];
    total: number;
    limit: number;
    offset: number;
    filter: TriageFilter;
  }>(`/findings/triage?${searchParams}`);
};

export const getFinding = (id: number) => 
  fetchAPI<import('../types').Finding>(`/findings/${id}`);

// CVEs
export const getCVE = (id: string) => 
  fetchAPI<{
    cveId: string;
    findings: import('../types').Finding[];
    serverCount: number;
    assessment: import('../types').Assessment | null;
  }>(`/cves/${id}`);

export const getCVEServers = (id: string) => 
  fetchAPI<{
    cveId: string;
    findings: import('../types').Finding[];
    total: number;
  }>(`/cves/${id}/servers`);

// Assessments
export interface AssessmentFilterParams {
  search?: string;
  status?: string;
  severity?: string;
  findingActive?: string;    // "true" | "false"
  hasFixAvailable?: string;  // "true" | "false"
  minCvss?: string;
  sortBy?: string;
  sortOrder?: string;
  limit?: number;
  offset?: number;
}

export const getAssessments = (params?: AssessmentFilterParams) => {
  const query = new URLSearchParams();
  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== '' && value !== null) {
        query.set(key, String(value));
      }
    });
  }
  const qs = query.toString();
  return fetchAPI<{
    assessments: import('../types').Assessment[];
    total: number;
  }>(`/assessments${qs ? '?' + qs : ''}`);
};

export const createAssessment = (data: { cveId: string; status: string; comment?: string; ticketUrl?: string; assessedBy?: string }) =>
  fetchAPI<import('../types').Assessment>('/assessments', {
    method: 'POST',
    body: JSON.stringify(data),
  });

export const updateAssessment = (cveId: string, data: { status: string; comment?: string; ticketUrl?: string; assessedBy?: string }) =>
  fetchAPI<import('../types').Assessment>(`/assessments/${cveId}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });

export const deleteAssessment = (cveId: string) =>
  fetchAPI<void>(`/assessments/${cveId}`, { method: 'DELETE' });

// AI Assessments (advisory LLM assessments)
export const getAIAssessments = (params?: { status?: string; search?: string; limit?: number; offset?: number }) => {
  const qs = new URLSearchParams();
  if (params?.status) qs.set('status', params.status);
  if (params?.search) qs.set('search', params.search);
  if (params?.limit != null) qs.set('limit', String(params.limit));
  if (params?.offset != null) qs.set('offset', String(params.offset));
  const q = qs.toString();
  return fetchAPI<{
    assessments: import('../types').AIAssessment[];
    total: number;
    limit: number;
    offset: number;
  }>(`/ai-assessments${q ? '?' + q : ''}`);
};

export const getAIAssessment = (cveId: string) =>
  fetchAPI<import('../types').AIAssessment>(`/ai-assessments/${encodeURIComponent(cveId)}`);

// Request a (re-)assessment. force=true requests a fresh result when one exists.
export const requestAIAssessment = (cveId: string, force = false) =>
  fetchAPI<{ cveId: string; queued: boolean }>(
    `/findings/${encodeURIComponent(cveId)}/ai-assess${force ? '?force=true' : ''}`,
    { method: 'POST' },
  );

// Reason Templates
export const getReasonTemplates = (appliesTo?: string) => {
  const params = appliesTo ? `?appliesTo=${appliesTo}` : '';
  return fetchAPI<{ templates: import('../types').ReasonTemplate[] }>(`/reason-templates${params}`);
};

export const createReasonTemplate = (data: { reason: string; appliesTo: string; sortOrder: number }) =>
  fetchAPI<import('../types').ReasonTemplate>('/reason-templates', {
    method: 'POST',
    body: JSON.stringify(data),
  });

export const updateReasonTemplate = (id: number, data: { reason: string; appliesTo: string; isActive: boolean; sortOrder: number }) =>
  fetchAPI<import('../types').ReasonTemplate>(`/reason-templates/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });

export const deleteReasonTemplate = (id: number) =>
  fetchAPI<void>(`/reason-templates/${id}`, { method: 'DELETE' });

// Statistics
export const getSeverityStats = () => 
  fetchAPI<{ breakdown: Record<string, number> }>('/stats/severity');

export const getTrendStats = (days = 30) => 
  fetchAPI<{
    trend: import('../types').TrendDataPoint[];
    days: number;
  }>(`/stats/trend?days=${days}`);

export const getTopServers = (limit = 10) => 
  fetchAPI<{ servers: import('../types').TopServer[] }>(`/stats/top-servers?limit=${limit}`);

export const getTopCVEs = (limit = 10) => 
  fetchAPI<{ cves: import('../types').TopCVE[] }>(`/stats/top-cves?limit=${limit}`);

export const getAssessmentsBySeverity = () =>
  fetchAPI<{ stats: import('../types').AssessmentBySeverity[] }>('/stats/assessments-by-severity');

// Reports
export interface GenerateReportParams {
  serverIds?: number[];
  groupIds?: number[];
  startDate: string;
  endDate: string;
  reportType?: string;
  includeSeverityChart?: boolean;
  includeTrendChart?: boolean;
  includeTopCVEs?: boolean;
  includeFullCVEList?: boolean;
}

export const generateReport = async (params: GenerateReportParams): Promise<Blob> => {
  const response = await fetch(`${API_BASE}/reports/generate`, {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(params),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ message: 'Failed to generate report' }));
    throw new Error(errorData.message || 'Failed to generate report');
  }

  return response.blob();
};

// Report Schedules
export const getReportSchedules = () =>
  fetchAPI<{ schedules: import('../types').ReportSchedule[] }>('/report-schedules');

export const getReportSchedule = (id: number) =>
  fetchAPI<import('../types').ReportSchedule>(`/report-schedules/${id}`);

export const createReportSchedule = (data: Partial<import('../types').ReportSchedule>) =>
  fetchAPI<import('../types').ReportSchedule>('/report-schedules', {
    method: 'POST',
    body: JSON.stringify(data),
  });

export const updateReportSchedule = (id: number, data: Partial<import('../types').ReportSchedule>) =>
  fetchAPI<import('../types').ReportSchedule>(`/report-schedules/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });

export const deleteReportSchedule = (id: number) =>
  fetchAPI<void>(`/report-schedules/${id}`, { method: 'DELETE' });

export const toggleReportSchedule = (id: number, enabled: boolean) =>
  fetchAPI<import('../types').ReportSchedule>(`/report-schedules/${id}/toggle`, {
    method: 'POST',
    body: JSON.stringify({ enabled }),
  });

export const runReportScheduleNow = (id: number) =>
  fetchAPI<{ message: string }>(`/report-schedules/${id}/run-now`, { method: 'POST' });

// Admin - Settings
export const getSettings = () =>
  fetchAPI<{ settings: import('../types').Setting[]; aiApiKeyConfigured?: boolean }>('/admin/settings');

export const updateSettings = (settings: Record<string, string>) =>
  fetchAPI<{ message: string }>('/admin/settings', {
    method: 'PUT',
    body: JSON.stringify(settings),
  });

// Admin - Users (OIDC; admin only)
export interface AdminUser {
  id: number;
  email: string;
  name: string;
  isAdmin: boolean;
  lastLoginAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export const getAdminUsers = () =>
  fetchAPI<{ users: AdminUser[] }>('/admin/users');

export const updateUserAdmin = (id: number, isAdmin: boolean) =>
  fetchAPI<AdminUser>(`/admin/users/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({ isAdmin }),
  });

// Admin - Server Groups
export const getServerGroups = () =>
  fetchAPI<{ groups: import('../types').ServerGroup[] }>('/admin/server-groups');

export const getServerGroup = (id: number) =>
  fetchAPI<import('../types').ServerGroup>(`/admin/server-groups/${id}`);

export const createServerGroup = (data: { name: string; description?: string; color?: string }) =>
  fetchAPI<import('../types').ServerGroup>('/admin/server-groups', {
    method: 'POST',
    body: JSON.stringify(data),
  });

export const updateServerGroup = (id: number, data: { name: string; description?: string; color?: string }) =>
  fetchAPI<import('../types').ServerGroup>(`/admin/server-groups/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });

export const deleteServerGroup = (id: number) =>
  fetchAPI<void>(`/admin/server-groups/${id}`, { method: 'DELETE' });

export const getServerGroupMembers = (id: number) =>
  fetchAPI<{ servers: import('../types').Server[] }>(`/admin/server-groups/${id}/members`);

export const addServerGroupMember = (groupId: number, serverId: number) =>
  fetchAPI<{ message: string }>(`/admin/server-groups/${groupId}/members`, {
    method: 'POST',
    body: JSON.stringify({ serverId }),
  });

export const removeServerGroupMember = (groupId: number, serverId: number) =>
  fetchAPI<void>(`/admin/server-groups/${groupId}/members/${serverId}`, { method: 'DELETE' });

// Replace the entire member list of a group atomically.
export const setServerGroupMembers = (groupId: number, serverIds: number[]) =>
  fetchAPI<{ message: string; memberCount: number }>(`/admin/server-groups/${groupId}/members`, {
    method: 'PUT',
    body: JSON.stringify({ serverIds }),
  });

// Server group membership
export const getServerGroupsForServer = (serverId: number) =>
  fetchAPI<{ groups: import('../types').ServerGroup[] }>(`/servers/${serverId}/groups`);

export const setServerGroups = (serverId: number, groupIds: number[]) =>
  fetchAPI<{ message: string }>(`/servers/${serverId}/groups`, {
    method: 'PUT',
    body: JSON.stringify({ groupIds }),
  });

// ============================================================================
// ADMIN: Enrollment Keys
// ============================================================================

export interface EnrollmentKey {
  id: number;
  name: string;
  keyPrefix: string;
  isActive: boolean;
  autoApprove: boolean;
  expiresAt: string | null;
  maxUses: number | null;
  usedCount: number;
  createdAt: string;
  updatedAt: string;
}

export const getEnrollmentKeys = () =>
  fetchAPI<{ keys: EnrollmentKey[] }>('/admin/enrollment-keys');

export const createEnrollmentKey = (data: { name: string; expiresAt?: string; maxUses?: number; autoApprove?: boolean }) =>
  fetchAPI<{ key: EnrollmentKey; fullKey: string }>('/admin/enrollment-keys', {
    method: 'POST',
    body: JSON.stringify(data),
  });

export const updateEnrollmentKey = (id: number, data: { name?: string; isActive?: boolean }) =>
  fetchAPI<EnrollmentKey>(`/admin/enrollment-keys/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });

export const deleteEnrollmentKey = (id: number) =>
  fetchAPI<void>(`/admin/enrollment-keys/${id}`, { method: 'DELETE' });

// ============================================================================
// ADMIN: API Tokens (MCP interface)
// ============================================================================

export interface APIToken {
  id: number;
  description: string;
  tokenPrefix: string;
  isReadOnly: boolean;
  isActive: boolean;
  createdBy?: number;
  createdByName?: string;
  createdAt: string;
  lastUsedAt: string | null;
  expiresAt: string | null;
}

export const getAPITokens = () =>
  fetchAPI<{ tokens: APIToken[] }>('/admin/api-tokens');

export const createAPIToken = (data: { description: string; isReadOnly: boolean; expiresAt?: string }) =>
  fetchAPI<{ token: APIToken; fullToken: string }>('/admin/api-tokens', {
    method: 'POST',
    body: JSON.stringify(data),
  });

export const deleteAPIToken = (id: number) =>
  fetchAPI<void>(`/admin/api-tokens/${id}`, { method: 'DELETE' });

// ============================================================================
// ADMIN: Registered Agents
// ============================================================================

export interface RegisteredAgent {
  id: number;
  serverId?: number;
  hostname: string;
  tokenPrefix: string;
  enrolledVia?: number;
  enrollmentKeyName?: string;
  status: 'pending' | 'active' | 'revoked';
  lastSeenAt: string | null;
  lastIp: string | null;
  agentVersion?: string;
  createdAt: string;
  lastAuthFailureAt?: string | null;
  authFailureIp?: string | null;
}

export const getRegisteredAgents = () =>
  fetchAPI<{ agents: RegisteredAgent[] }>('/admin/agents');

export const approveAgent = (id: number) =>
  fetchAPI<{ message: string }>(`/admin/agents/${id}/approve`, { method: 'PUT' });

export const revokeAgent = (id: number) =>
  fetchAPI<{ message: string }>(`/admin/agents/${id}/revoke`, { method: 'PUT' });

export const deleteAgent = (id: number) =>
  fetchAPI<void>(`/admin/agents/${id}`, { method: 'DELETE' });

// ============================================================================
// ADMIN: OVAL Sources
// ============================================================================

export interface OVALDistribution {
  id: number;
  name: string;
  displayName: string;
  urlTemplate: string;
  packageManager: string;
  versions: { version: string; codename?: string; lts?: boolean }[];
}

export interface OVALSource {
  id: number;
  distribution: string;
  version: string;
  sourceType: string;  // 'usn' or 'cve'
  codename: string;
  url: string;
  enabled: boolean;
  lastSyncAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export const getOVALDistributions = () =>
  fetchAPI<{ distributions: OVALDistribution[] }>('/admin/oval/distributions');

export const getOVALSources = () =>
  fetchAPI<{ sources: OVALSource[] }>('/admin/oval/sources');

export const enableOVALSource = (data: { distribution: string; version: string }) =>
  fetchAPI<OVALSource>('/admin/oval/sources', {
    method: 'POST',
    body: JSON.stringify(data),
  });

export const disableOVALSource = (id: number) =>
  fetchAPI<{ message: string }>(`/admin/oval/sources/${id}/disable`, { method: 'PUT' });

export const deleteOVALSource = (id: number) =>
  fetchAPI<void>(`/admin/oval/sources/${id}`, { method: 'DELETE' });

export const triggerOVALSync = (id: number) =>
  fetchAPI<{ message: string }>(`/admin/oval/sources/${id}/sync`, { method: 'POST' });

export const triggerOVALSyncAll = () =>
  fetchAPI<{ message: string }>('/admin/oval/sync-all', { method: 'POST' });

// ============================================================================
// ADMIN: NVD & ExploitDB Status
// ============================================================================

export interface SyncStatus {
  source: string;
  status: 'idle' | 'syncing' | 'success' | 'error';
  lastSyncAt: string | null;
  itemCount: number;
  error?: string;
}

export const getNVDStatus = () =>
  fetchAPI<{
    syncing: boolean;
    lastSync: string | null;
    cveCount: number;
    hasApiKey: boolean;
  }>('/admin/nvd/status');

export const triggerNVDSync = () =>
  fetchAPI<{ message: string }>('/admin/nvd/sync', { method: 'POST' });

export const getExploitDBStatus = () =>
  fetchAPI<{
    syncing: boolean;
    lastSync: string | null;
    exploitCount: number;
    withCVECount: number;
  }>('/admin/exploitdb/status');

export const triggerExploitDBSync = () =>
  fetchAPI<{ message: string }>('/admin/exploitdb/sync', { method: 'POST' });

export const getVEXStatus = () =>
  fetchAPI<{
    syncing: boolean;
    lastSync: string | null;
    statementCount: number;
    status?: string;
    recordsProcessed?: number;
    error?: string;
  }>('/admin/vex/status');

export const triggerVEXSync = () =>
  fetchAPI<{ message: string }>('/admin/vex/sync', { method: 'POST' });

export const getSyncStatus = () =>
  fetchAPI<{
    oval: { enabled: number; lastSync: string | null };
    nvd: { cveCount: number; lastSync: string | null; syncing: boolean };
    exploitdb: { exploitCount: number; lastSync: string | null; syncing: boolean };
  }>('/admin/sync/status');

// OVAL Database
export interface OVALDefinitionFilter {
  distribution?: string;
  version?: string;
  codename?: string;
  cveId?: string;
  severity?: string;
  sourceType?: string; // 'usn' | 'cve'
  package?: string;
  search?: string;
  hasExploit?: boolean; // when true, only definitions that have known exploits (ExploitDB)
  limit?: number;
  offset?: number;
  sortBy?: 'cveId' | 'severity' | 'createdAt';
  sortOrder?: 'asc' | 'desc';
}

export const getOVALDefinitions = (filter: OVALDefinitionFilter = {}) => {
  const searchParams = new URLSearchParams();
  if (filter.distribution) searchParams.set('distribution', filter.distribution);
  if (filter.version) searchParams.set('version', filter.version);
  if (filter.codename) searchParams.set('codename', filter.codename);
  if (filter.cveId) searchParams.set('cveId', filter.cveId);
  if (filter.severity) searchParams.set('severity', filter.severity);
  if (filter.sourceType) searchParams.set('sourceType', filter.sourceType);
  if (filter.package) searchParams.set('package', filter.package);
  if (filter.search) searchParams.set('search', filter.search);
  if (filter.hasExploit) searchParams.set('hasExploit', 'true');
  if (filter.limit) searchParams.set('limit', filter.limit.toString());
  if (filter.offset) searchParams.set('offset', filter.offset.toString());
  if (filter.sortBy) searchParams.set('sortBy', filter.sortBy);
  if (filter.sortOrder) searchParams.set('sortOrder', filter.sortOrder);

  return fetchAPI<{
    definitions: import('../types').OVALDefinition[];
    total: number;
    limit: number;
    offset: number;
  }>(`/oval/definitions?${searchParams}`);
};

export const getOVALDefinition = (id: number) =>
  fetchAPI<import('../types').OVALDefinition>(`/oval/definitions/${id}`);

// ============================================================================
// SCAN JOBS
// ============================================================================

export const getScans = (params?: { status?: string; search?: string; limit?: number; offset?: number }) => {
  const query = new URLSearchParams();
  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== '' && value !== null) {
        query.set(key, String(value));
      }
    });
  }
  const qs = query.toString();
  return fetchAPI<{
    jobs: import('../types').ScanJob[];
    total: number;
  }>(`/scans${qs ? '?' + qs : ''}`);
};

export const getScanStats = () =>
  fetchAPI<{ stats: import('../types').ScanStats }>('/scans/stats');

export const cancelScan = (id: string) =>
  fetchAPI<{ message: string }>(`/scans/${id}/cancel`, { method: 'POST' });

export const retryScan = (id: string) =>
  fetchAPI<{ message: string; jobId: string }>(`/scans/${id}/retry`, { method: 'POST' });
