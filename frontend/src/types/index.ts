// Server types
export interface Server {
  id: number;
  name: string;
  osFamily: string;
  osRelease: string;
  osCodename?: string;
  kernel?: string;
  arch?: string;
  packageManager?: string;
  ipv4Addrs: string[];
  lastScanAt: string | null;
  createdAt: string;
  updatedAt: string;
  findingsCount?: number;
  criticalCount?: number;
  highCount?: number;
}

// Server Package types
export interface ServerPackage {
  id: number;
  serverId: number;
  name: string;
  version: string;
  arch: string;
  sourcePackage: string;
  firstSeenAt: string;
  lastSeenAt: string;
  removedAt: string | null;
}

// Finding types
export interface Finding {
  id: number;
  serverId: number;
  cveId: string;
  packageName: string;
  packageVersion: string;
  fixState: string;
  fixedIn: string;
  cvss3Score: number | null;
  severity: string;
  summary: string;
  sourceLink: string;
  sourceType?: string;  // 'usn' | 'cve' (OVAL source)
  firstSeenAt: string;
  lastSeenAt: string;
  resolvedAt: string | null;
  createdAt: string;
  updatedAt: string;
  serverName?: string;
  // Best-available CVE description (OVAL preferred, NVD fallback)
  description?: string;
  // NVD enrichment
  nvdDescription?: string;
  nvdCvss3Score?: number | null;
  cvss3Vector?: string;
  cvss3Severity?: string;
  cvss2Score?: number | null;
  cweIds?: string[];
  cvePublishedAt?: string | null;
  // ExploitDB enrichment
  hasExploit?: boolean;
  exploitCount?: number;
  exploitIds?: number[];
  verifiedExploit?: boolean;
}

// Assessment types
export type AssessmentStatus = 'pending' | 'relevant' | 'not_relevant' | 'accepted_risk';

export interface Assessment {
  id: number;
  cveId: string;
  status: AssessmentStatus;
  comment: string;
  ticketUrl: string;
  assessedBy: string;
  assessedAt: string;
  createdAt: string;
  updatedAt: string;
  // Joined fields for display
  cvss3Score?: number;
  severity?: string;
  summary?: string;
  sourceLink?: string;
  affectedServers?: number;
  findingActive: boolean;
  hasFixAvailable: boolean;
}

// Reason template types
export interface ReasonTemplate {
  id: number;
  reason: string;
  appliesTo: 'not_relevant' | 'accepted_risk' | 'both';
  isActive: boolean;
  sortOrder: number;
  createdAt: string;
  updatedAt: string;
}

// Dashboard types
export interface DashboardStats {
  totalServers: number;
  totalFindings: number;
  activeFindings: number;
  resolvedFindings: number;
  criticalFindings: number;
  highFindings: number;
  pendingAssessments: number;
  severityBreakdown: Record<string, number>;
}

// Statistics types
export interface TopServer {
  id: number;
  name: string;
  findingsCount: number;
  criticalCount: number;
  highCount: number;
}

export interface TopCVE {
  cveId: string;
  cvss3Score: number | null;
  severity: string;
  sourceLink: string | null;
  serverCount: number;
  packageCount: number;
}

export interface AssessmentBySeverity {
  severity: string;
  pending: number;
  relevant: number;
  notRelevant: number;
  acceptedRisk: number;
  total: number;
}

export interface TrendDataPoint {
  date: string;
  totalFindings: number;
  newFindings: number;
  resolvedCount: number;
}

// API Response types
export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  limit: number;
  offset: number;
}

// Settings types
export interface Setting {
  key: string;
  value: string;
  description: string;
  updatedAt: string;
}

// Server Group types
export interface ServerGroup {
  id: number;
  name: string;
  description: string;
  color: string;
  serverCount?: number;
  createdAt: string;
  updatedAt: string;
}

// User types (for future OIDC)
export interface User {
  id: number;
  email: string;
  name: string;
  isAdmin: boolean;
  lastLoginAt: string | null;
  createdAt: string;
  updatedAt: string;
}

// OVAL Database types
export interface OVALTest {
  id: number;
  ovalId: string;
  testType: string;
  comment: string;
  packageName: string;
  packageNames?: string[];  // All packages tested by this test
  evrOperation: string;
  evrValue: string;
}

export interface OVALDefinition {
  id: number;
  sourceId: number;
  ovalId: string;
  class: string;
  title: string;
  description: string;
  severity: string;
  cveIds: string[];
  createdAt: string;
  distribution: string;
  version: string;
  codename: string;
  sourceType?: string; // 'usn' or 'cve'
  affectedPackages: string[];
  tests?: OVALTest[]; // Only in detail view
  // ExploitDB enrichment (only in detail view)
  hasExploit?: boolean;
  exploitCount?: number;
  exploitIds?: number[];
  verifiedExploit?: boolean;
}

// ============================================================================
// Report Schedules
// ============================================================================

export interface ReportSchedule {
  id: number;
  name: string;
  scheduleType: 'weekly' | 'monthly_dom' | 'monthly_dow';
  intervalValue: number;
  dayOfWeek?: number | null;     // 0=Sun..6=Sat
  weekOfMonth?: number | null;   // 1-5
  dayOfMonth?: number | null;    // 1-31
  timeHour: number;
  timeMinute: number;
  timezone: string;
  serverIds: number[];
  groupIds: number[];
  periodType: 'last_month' | 'last_week' | 'last_n_days';
  periodDays?: number | null;
  includeSeverityChart: boolean;
  includeTrendChart: boolean;
  includeTopCves: boolean;
  includeFullCveList: boolean;
  recipients: string[];
  enabled: boolean;
  lastRunAt?: string | null;
  nextRunAt?: string | null;
  lastError?: string;
  createdAt: string;
  updatedAt: string;
}

// ============================================================================
// SCAN JOBS
// ============================================================================

export type ScanJobStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
export type ScanTrigger = 'agent_report' | 'manual' | 'scheduled';

export interface ScanJob {
  id: string;
  serverId: number;
  serverName: string;
  triggerType: ScanTrigger;
  status: ScanJobStatus;
  retryCount: number;
  maxRetries: number;
  error?: string;
  newFindings?: number | null;
  updatedFindings?: number | null;
  resolvedFindings?: number | null;
  totalChecks?: number | null;
  durationMs?: number | null;
  createdAt: string;
  startedAt?: string | null;
  finishedAt?: string | null;
}

export interface ScanStats {
  queued: number;
  running: number;
  completed: number;
  failed: number;
  cancelled: number;
  queueDepth: number;
}
