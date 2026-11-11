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
  // Last agent report; reportAgeSeconds is measured by the server clock.
  lastReportAt: string | null;
  reportAgeSeconds: number;
  stale: boolean;
  // Set when the server was marked as disabled (switched off, kept in VulTrack).
  disabledAt?: string;
  disabledBy?: string;
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

// A package installed on one server (APT Packages page)
export interface InstalledPackage {
  id: number;
  serverId: number;
  serverName: string;
  os: string;
  name: string;
  version: string;
  previousVersion?: string;
  arch: string;
  sourcePackage: string;
  firstSeenAt: string;
  lastSeenAt: string;
}

// One package across all servers (APT Packages list)
export interface PackageSummary {
  name: string;
  sourcePackages: string[];
  versions: string[];
  archs: string[];
  serverCount: number;
  lastSeenAt: string;
}

// CISA KEV listing and FIRST EPSS score of a CVE (flattened into findings,
// groups and top CVEs by the API).
export interface ThreatIntel {
  inKev?: boolean;
  kevDateAdded?: string;
  kevDueDate?: string;
  kevRansomware?: boolean;
  epss?: number;
  epssPercentile?: number;
}

// CVE-level threat intelligence with the KEV details list views leave out.
export interface CVEThreatIntel extends ThreatIntel {
  kevVendorProject?: string;
  kevProduct?: string;
  kevVulnerabilityName?: string;
  kevNotes?: string;
  epssScoreDate?: string;
}

// Automated decision of a finding's (server, CVE) pair, shown next to findings.
export type DecisionState = 'applied' | 'shadow' | 'blocked' | 'rejected' | 'overridden';
export interface DecisionBadge {
  ruleIds: string[];
  guards?: string[];
  state: DecisionState;
}

// Finding types
export interface Finding extends ThreatIntel {
  autoDecision?: DecisionBadge;
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
  sourceType?: string;  // 'usn' | 'cve' (OVAL) | 'pkg' (Ubuntu package feed)
  fixPocket?: string;   // pocket the fix comes from; 'esm-*' needs Ubuntu Pro
  firstSeenAt: string;
  lastSeenAt: string;
  resolvedAt: string | null;
  createdAt: string;
  updatedAt: string;
  serverName?: string;
  // Best-available CVE description (OVAL preferred, NVD fallback)
  description?: string;
  // Canonical package feed enrichment
  ubuntuPriority?: string;
  ubuntuNotes?: string[];
  ubuntuMitigation?: string;
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
  // VEX enrichment (Ubuntu VEX data)
  vexStatus?: string | null;
  vexJustification?: string | null;
}

// Grouped Finding types — used by GET /findings?grouped=true on the Findings page.
export interface PackageFinding {
  id: number;
  name: string;
  version: string;
  fixedIn: string;
  fixState: string;
  fixPocket?: string;
  firstSeenAt: string;
  lastSeenAt: string;
  resolvedAt: string | null;
  vexStatus: string | null;
  vexJustification: string | null;
}

export interface GroupedFinding extends ThreatIntel {
  autoDecision?: DecisionBadge;
  serverId: number;
  serverName: string;
  cveId: string;
  severity: string;
  cvss3Score: number | null;
  nvdCvss3Score: number | null;
  sourceLink?: string;
  sourceType?: string;
  packages: PackageFinding[];
  packageCount: number;
  activeCount: number;
  allResolved: boolean;
  fixStates: string[];
  vexStatuses: string[];
  earliestFirstSeen: string;
  latestLastSeen: string;
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
  // Applies to every server; automated decisions never override it
  bindingAllServers?: boolean;
  // Joined fields for display
  cvss3Score?: number;
  severity?: string;
  summary?: string;
  sourceLink?: string;
  affectedServers?: number;
  findingActive: boolean;
  hasFixAvailable: boolean;
}

// AI assessment types
export type AIAssessmentStatus = 'pending' | 'processing' | 'completed' | 'failed';
export type AIConfidence = 'low' | 'medium' | 'high';

// Advisory LLM assessment of a CVE. Informational only — never sets the human assessment.
export interface AIAssessment {
  id: number;
  cveId: string;
  status: AIAssessmentStatus;
  attackVector: string;
  prerequisites: string;
  recommendedStatus: '' | AssessmentStatus; // empty until completed
  recommendationReasoning: string;
  confidence: '' | AIConfidence;
  model: string;
  promptHash: string;
  inputTokens: number;
  outputTokens: number;
  error?: string;
  retryCount: number;
  requestedBy?: string;
  createdAt: string;
  updatedAt: string;
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

export interface TopCVE extends ThreatIntel {
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
  includeAutoAssessments: boolean;
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

// =============================================================================
// Automated assessment (docs/AUTO_ASSESSMENT_PLAN.md)
// =============================================================================

export type AutoMode = 'off' | 'shadow' | 'active';

export interface AutoRuleInfo {
  id: string;
  version: number;
  description: string;
  mode: AutoMode;          // configured
  effectiveMode: AutoMode; // after the global mode
}

export interface AutoGuardInfo {
  id: string;
  description: string;
  enabled: boolean;
}

export interface AutoAssessmentConfig {
  mode: AutoMode;
  rules: AutoRuleInfo[];
  guards: AutoGuardInfo[];
  guardExploit: boolean;
  guardEpss: number;
  factSettleMinutes: number;
  unusedDays: number;
  activeRules: string[];
}

export interface KernelBuildStatus {
  release: string;
  version: string;
  arch: string;
  status: 'ok' | 'error';
  error?: string;
  sourceFiles: number;
  modulesVerified: boolean;
  servers: number;
  builtAt: string;
}

export interface KernelIntelStatus {
  cves: { total: number; withData: number; noFiles: number; errors: number; pending: number };
  builds: KernelBuildStatus[];
  running: boolean;
}

export interface AutoRuleStats {
  ruleId: string;
  decisions: number;
  applied: number;
  shadow: number;
  blocked: number;
  rejected: number;
  overridden: number;
  humanAgree: number;
  humanAccepted: number;
  humanDisagree: number;
}

export interface AutoAssessmentStats {
  rules: AutoRuleStats[] | null;
  guards: Record<string, number>;
  total: AutoRuleStats;
  openPairs: number;
  totalPairs: number;
  overrides: Record<string, number>;
  activity: { date: string; created: number; revoked: number; overrides: number }[];
  lastEventAt: string | null;
}

export interface PackageEvidence {
  package: string;
  version?: string;
  rule: string;
  ruleVersion: number;
  detail: string;
}

export interface DecisionEvidence {
  packages: PackageEvidence[];
  guards?: { id: string; detail: string }[];
}

export interface AutoDecision {
  serverId: number;
  serverName: string;
  cveId: string;
  verdict: string;
  source: string;
  ruleIds: string[];
  guards: string[];
  reason: string;
  evidence: DecisionEvidence;
  state: DecisionState;
  decidedAt: string;
  updatedAt: string;
  humanStatus?: string;
}

export interface DecisionEvent {
  id: number;
  serverId: number;
  serverName: string;
  cveId: string;
  event: 'auto_created' | 'auto_changed' | 'auto_revoked' | 'override_set' | 'override_removed';
  verdict?: string;
  ruleIds?: string[];
  guards?: string[];
  reason?: string;
  evidence?: DecisionEvidence;
  actor?: string;
  createdAt: string;
}

export type ServerOverrideStatus = 'relevant' | 'not_relevant' | 'accepted_risk' | 'manual';

export interface ServerStatus {
  serverId: number;
  serverName: string;
  packages: string[];
  status: 'open' | 'not_relevant' | 'relevant' | 'accepted_risk' | 'pending';
  source: 'override' | 'binding' | 'auto' | 'assessment' | 'none';
  override?: { status: ServerOverrideStatus; comment?: string; assessedBy?: string; assessedAt: string };
  decision?: AutoDecision;
}

// Runtime facts reported by the agent (docs/AGENT_RUNTIME_FACTS_PROMPT.md)
export interface FactCategoryState {
  category: 'kernel' | 'listeners' | 'packagesInUse' | 'services' | 'virtualization';
  hash: string;
  truncated: boolean;
  stableSince: string;
  reportedAt: string;
  data: unknown;
}

export interface ServerRuntime {
  schemaVersion?: number;
  collectedAt?: string;
  reportedAt?: string;
  errors: unknown;
  truncated: string[];
  categories: FactCategoryState[];
  moduleIndex?: { kernelRelease: string; hash: string; known: boolean; available: number; builtin: number };
  packageUsage?: { observedSince?: string; lastObservedAt?: string; observedDays: number; trackedPackages: number };
  unknown: string[];
}


// AI precondition analysis
export interface PreconditionCondition {
  type: string;
  package: string;
  unit: string;
  path: string;
  scope: string;
  necessary: boolean;
  confidence: 'low' | 'medium' | 'high';
  reason: string;
}

export interface PreconditionResult {
  determinable: boolean;
  paths: { requires: PreconditionCondition[] }[];
  reasoning: string;
  recommended_status_if_reachable: string;
}

export interface PreconditionAnalysis {
  cveId: string;
  status: 'pending' | 'ok' | 'error';
  model: string;
  current: boolean;
  refusedBy?: string;
  result?: PreconditionResult;
  error?: string;
  analysedAt?: string;
}

export interface PreconditionConfig {
  enabled: boolean;
  model: string;
  useBatch: boolean;
  budgetUsd: number;
  dailyMax: number;
  fallbackModel: string;
}

export interface PreconditionStatus {
  config: PreconditionConfig;
  models: string[];
  fallbackModels: string[];
  configured: boolean;
  running: boolean;
  spentMonth: number;
  spentTotal: number;
  avgCost: number;
  analyses: { ok: number; determinable: number; pending: number; errors: number; refused: number; byFallback: number };
  failures: { cveId: string; model: string; refused: boolean; fallback: boolean; terminal: boolean; error: string; at: string }[];
  batchesInProgress: number;
  lastError?: string;
}
