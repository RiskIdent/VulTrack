package models

import (
	"time"
)

// Server represents a scanned server
type Server struct {
	ID             int64      `json:"id"`
	Name           string     `json:"name"`
	OSFamily       string     `json:"osFamily"`
	OSRelease      string     `json:"osRelease"`
	OSCodename     string     `json:"osCodename,omitempty"`
	Kernel         string     `json:"kernel,omitempty"`
	Arch           string     `json:"arch,omitempty"`
	PackageManager string     `json:"packageManager,omitempty"` // 'dpkg' or 'rpm'
	IPv4Addrs      []string   `json:"ipv4Addrs"`
	LastScanAt     *time.Time `json:"lastScanAt"`
	CreatedAt      time.Time  `json:"createdAt"`
	UpdatedAt      time.Time  `json:"updatedAt"`

	// Computed fields (not stored in DB)
	FindingsCount int `json:"findingsCount,omitempty"`
	CriticalCount int `json:"criticalCount,omitempty"`
	HighCount     int `json:"highCount,omitempty"`
}

// Finding represents a vulnerability finding on a server
type Finding struct {
	ID             int64      `json:"id"`
	ServerID       int64      `json:"serverId"`
	CVEID          string     `json:"cveId"`
	PackageName    string     `json:"packageName"`
	PackageVersion string     `json:"packageVersion"`
	FixState       string     `json:"fixState"`
	FixedIn        string     `json:"fixedIn"`
	CVSS3Score     *float64   `json:"cvss3Score"`
	Severity       string     `json:"severity"`
	Summary        string     `json:"summary"`
	SourceLink     string     `json:"sourceLink"`
	SourceType     string     `json:"sourceType,omitempty"` // 'usn' or 'cve' (OVAL source); empty = legacy
	FirstSeenAt    time.Time  `json:"firstSeenAt"`
	LastSeenAt     time.Time  `json:"lastSeenAt"`
	ResolvedAt     *time.Time `json:"resolvedAt"`
	CreatedAt      time.Time  `json:"createdAt"`
	UpdatedAt      time.Time  `json:"updatedAt"`

	// Joined fields from servers
	ServerName string `json:"serverName,omitempty"`

	// Best-available CVE description (OVAL preferred, NVD fallback)
	Description string `json:"description,omitempty"`

	// Enrichment from NVD (cve_catalog)
	NVDDescription string     `json:"nvdDescription,omitempty"`
	NVDCvss3Score  *float64   `json:"nvdCvss3Score,omitempty"`
	CVSS3Vector    string     `json:"cvss3Vector,omitempty"`
	CVSS3Severity  string     `json:"cvss3Severity,omitempty"`
	CVSS2Score     *float64   `json:"cvss2Score,omitempty"`
	CWEIDs         []string   `json:"cweIds,omitempty"`
	CVEPublishedAt *time.Time `json:"cvePublishedAt,omitempty"`

	// Enrichment from ExploitDB
	HasExploit      bool  `json:"hasExploit"`
	ExploitCount    int   `json:"exploitCount,omitempty"`
	ExploitIDs      []int `json:"exploitIds,omitempty"`
	VerifiedExploit bool  `json:"verifiedExploit,omitempty"`

	// VEX enrichment (Ubuntu VEX data)
	VexStatus        *string `json:"vexStatus,omitempty"`
	VexJustification *string `json:"vexJustification,omitempty"`
}

// Assessment represents a user's evaluation of a CVE
type Assessment struct {
	ID         int64     `json:"id"`
	CVEID      string    `json:"cveId"`
	Status     string    `json:"status"` // pending, relevant, not_relevant, accepted_risk
	Comment    string    `json:"comment"`
	TicketURL  string    `json:"ticketUrl"`
	AssessedBy string    `json:"assessedBy"`
	AssessedAt time.Time `json:"assessedAt"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
	// Joined fields for display (not stored in assessments table)
	CVSS3Score      float64 `json:"cvss3Score,omitempty"`
	Severity        string  `json:"severity,omitempty"`
	Summary         string  `json:"summary,omitempty"`
	SourceLink      string  `json:"sourceLink,omitempty"`
	AffectedServers int     `json:"affectedServers,omitempty"`
	FindingActive   bool    `json:"findingActive"`
	HasFixAvailable bool    `json:"hasFixAvailable"`
}

// AssessmentStatus constants
const (
	AssessmentStatusPending      = "pending"
	AssessmentStatusRelevant     = "relevant"
	AssessmentStatusNotRelevant  = "not_relevant"
	AssessmentStatusAcceptedRisk = "accepted_risk"
)

// ReasonTemplate represents a predefined reason for assessments
type ReasonTemplate struct {
	ID        int64     `json:"id"`
	Reason    string    `json:"reason"`
	AppliesTo string    `json:"appliesTo"` // not_relevant, accepted_risk, both
	IsActive  bool      `json:"isActive"`
	SortOrder int       `json:"sortOrder"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Severity constants based on CVSS score
const (
	SeverityCritical = "critical" // 9.0 - 10.0
	SeverityHigh     = "high"     // 7.0 - 8.9
	SeverityMedium   = "medium"   // 4.0 - 6.9
	SeverityLow      = "low"      // 0.1 - 3.9
	SeverityNone     = "none"     // 0.0
)

// GetSeverity returns the severity level based on CVSS score
func GetSeverity(cvssScore float64) string {
	switch {
	case cvssScore >= 9.0:
		return SeverityCritical
	case cvssScore >= 7.0:
		return SeverityHigh
	case cvssScore >= 4.0:
		return SeverityMedium
	case cvssScore > 0:
		return SeverityLow
	default:
		return SeverityNone
	}
}

// FixState constants
const (
	FixStateNeeded   = "needed"
	FixStatePending  = "pending"
	FixStateDeferred = "deferred"
)

// Setting represents an application configuration setting
type Setting struct {
	Key         string    `json:"key"`
	Value       string    `json:"value"`
	Description string    `json:"description"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// ServerGroup represents a group of servers
type ServerGroup struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Color       string    `json:"color"`
	ServerCount int       `json:"serverCount,omitempty"` // Joined field
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// ServerGroupMember represents a server's membership in a group
type ServerGroupMember struct {
	ServerID int64     `json:"serverId"`
	GroupID  int64     `json:"groupId"`
	AddedAt  time.Time `json:"addedAt"`
}

// User represents an application user (OIDC-provisioned).
type User struct {
	ID          int64      `json:"id"`
	Email       string     `json:"email"`
	Name        string     `json:"name"`
	IsAdmin     bool       `json:"isAdmin"`
	LastLoginAt *time.Time `json:"lastLoginAt"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`

	// OIDC identity (not exposed in API)
	OIDCSubject string `json:"-"`
	OIDCIssuer  string `json:"-"`
}

// ============================================================================
// AGENT AUTHENTICATION
// ============================================================================

// EnrollmentKey represents a key for automatic agent deployment
type EnrollmentKey struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	KeyHash     string     `json:"-"`         // Never expose hash
	KeyPrefix   string     `json:"keyPrefix"` // First 8 chars for identification
	IsActive    bool       `json:"isActive"`
	AutoApprove bool       `json:"autoApprove"`
	UsageCount  int        `json:"usageCount"`
	CreatedAt   time.Time  `json:"createdAt"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
}

// EnrollmentKeyStatus constants
const (
	EnrollmentKeyActive   = true
	EnrollmentKeyInactive = false
)

// RegisteredAgent represents an agent that has enrolled with VulTrack
type RegisteredAgent struct {
	ID           int64      `json:"id"`
	ServerID     *int64     `json:"serverId,omitempty"`
	Hostname     string     `json:"hostname"`
	TokenHash    string     `json:"-"`           // Never expose hash
	TokenPrefix  string     `json:"tokenPrefix"` // First 8 chars for identification
	EnrolledVia  *int64     `json:"enrolledVia,omitempty"`
	Status       string     `json:"status"` // pending, active, revoked
	LastSeenAt   *time.Time `json:"lastSeenAt,omitempty"`
	LastIP       string     `json:"lastIp,omitempty"`
	AgentVersion string     `json:"agentVersion,omitempty"`
	CreatedAt    time.Time  `json:"createdAt"`

	// Joined fields
	EnrollmentKeyName string `json:"enrollmentKeyName,omitempty"`
}

// Agent status constants
const (
	AgentStatusPending = "pending"
	AgentStatusActive  = "active"
	AgentStatusRevoked = "revoked"
)

// ============================================================================
// SERVER PACKAGES
// ============================================================================

// ServerPackage represents an installed package on a server
type ServerPackage struct {
	ID              int64      `json:"id"`
	ServerID        int64      `json:"serverId"`
	Name            string     `json:"name"`
	Version         string     `json:"version"`
	PreviousVersion string     `json:"previousVersion,omitempty"`
	Arch            string     `json:"arch,omitempty"`
	SourcePackage   string     `json:"sourcePackage,omitempty"`
	FirstSeenAt     time.Time  `json:"firstSeenAt"`
	LastSeenAt      time.Time  `json:"lastSeenAt"`
	RemovedAt       *time.Time `json:"removedAt,omitempty"` // Soft-delete
	CreatedAt       time.Time  `json:"createdAt"`
	UpdatedAt       time.Time  `json:"updatedAt"`
}

// ============================================================================
// AGENT REPORT (for API requests)
// ============================================================================

// AgentReport represents the data sent by an agent
type AgentReport struct {
	Hostname       string        `json:"hostname"`
	AgentVersion   string        `json:"agentVersion,omitempty"`
	OSFamily       string        `json:"osFamily"`
	OSRelease      string        `json:"osRelease"`
	OSCodename     string        `json:"osCodename,omitempty"`
	Kernel         string        `json:"kernel"`
	Arch           string        `json:"arch"`
	PackageManager string        `json:"packageManager,omitempty"`
	IPv4Addrs      []string      `json:"ipv4Addrs"`
	ReportedAt     time.Time     `json:"reportedAt"`
	Packages       []PackageInfo `json:"packages"`
}

// PackageInfo represents package information from an agent report
type PackageInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
	Source  string `json:"source,omitempty"` // Source package name
}

// EnrollRequest represents an agent enrollment request
type EnrollRequest struct {
	Hostname       string   `json:"hostname"`
	OSFamily       string   `json:"osFamily,omitempty"`
	OSRelease      string   `json:"osRelease,omitempty"`
	OSCodename     string   `json:"osCodename,omitempty"`
	Kernel         string   `json:"kernel,omitempty"`
	Arch           string   `json:"arch,omitempty"`
	PackageManager string   `json:"packageManager,omitempty"`
	IPv4Addrs      []string `json:"ipv4Addrs"`
}

// EnrollResponse represents the response to an enrollment request
type EnrollResponse struct {
	AgentToken string `json:"agentToken"`
	Status     string `json:"status"` // active or pending
}

// ============================================================================
// OVAL DEFINITIONS
// ============================================================================

// OVALDistribution represents a known Linux distribution with OVAL support
type OVALDistribution struct {
	ID             int64           `json:"id"`
	Name           string          `json:"name"`           // 'ubuntu', 'debian', 'rhel', etc.
	DisplayName    string          `json:"displayName"`    // 'Ubuntu', 'Debian', etc.
	URLTemplate    string          `json:"urlTemplate"`    // USN / primary OVAL URL template
	URLTemplateCve string          `json:"urlTemplateCve"` // Optional CVE OVAL URL template
	PackageManager string          `json:"packageManager"` // 'dpkg' or 'rpm'
	Versions       []DistroVersion `json:"versions"`       // Available versions
}

// DistroVersion represents a version of a distribution
type DistroVersion struct {
	Version  string `json:"version"`
	Codename string `json:"codename,omitempty"`
	LTS      bool   `json:"lts,omitempty"`
}

// OVALSource represents a user-enabled OVAL source for a specific distribution version
type OVALSource struct {
	ID              int64      `json:"id"`
	Distribution    string     `json:"distribution"` // 'ubuntu', 'debian', etc.
	Version         string     `json:"version"`      // '24.04', '12', etc.
	SourceType      string     `json:"sourceType"`   // 'usn' or 'cve'
	Codename        string     `json:"codename"`     // 'noble', 'bookworm', etc.
	URL             string     `json:"url"`          // Resolved URL
	IsEnabled       bool       `json:"isEnabled"`
	LastSyncAt      *time.Time `json:"lastSyncAt,omitempty"`
	LastSyncStatus  string     `json:"lastSyncStatus,omitempty"` // 'success', 'failed', 'pending'
	LastSyncError   string     `json:"lastSyncError,omitempty"`
	DefinitionCount int        `json:"definitionCount,omitempty"`
	CreatedAt       time.Time  `json:"createdAt"`
	UpdatedAt       time.Time  `json:"updatedAt"`
}

// OVALDefinition represents an OVAL vulnerability definition
type OVALDefinition struct {
	ID          int64     `json:"id"`
	SourceID    int64     `json:"sourceId"`
	OvalID      string    `json:"ovalId"` // e.g., 'oval:com.ubuntu.noble:def:100'
	Class       string    `json:"class"`  // 'vulnerability', 'patch', etc.
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	CVEIDs      []string  `json:"cveIds"` // Array of CVE IDs
	CreatedAt   time.Time `json:"createdAt"`
}

// OVALTest represents an OVAL test (package version check)
type OVALTest struct {
	ID       int64  `json:"id"`
	SourceID int64  `json:"sourceId"`
	OvalID   string `json:"ovalId"`   // e.g., 'oval:com.ubuntu.noble:tst:100'
	TestType string `json:"testType"` // 'dpkginfo_test', 'rpminfo_test', etc.
	ObjectID int64  `json:"objectId"`
	StateID  int64  `json:"stateId"`
	Comment  string `json:"comment"`
}

// OVALObject represents an OVAL object (package name)
type OVALObject struct {
	ID         int64  `json:"id"`
	SourceID   int64  `json:"sourceId"`
	OvalID     string `json:"ovalId"`     // e.g., 'oval:com.ubuntu.noble:obj:100'
	ObjectType string `json:"objectType"` // 'dpkginfo_object', 'rpminfo_object', etc.
	Name       string `json:"name"`       // Package name
}

// OVALState represents an OVAL state (version comparison)
type OVALState struct {
	ID           int64  `json:"id"`
	SourceID     int64  `json:"sourceId"`
	OvalID       string `json:"ovalId"`       // e.g., 'oval:com.ubuntu.noble:ste:100'
	StateType    string `json:"stateType"`    // 'dpkginfo_state', 'rpminfo_state', etc.
	EVROperation string `json:"evrOperation"` // 'less than', 'equals', etc.
	EVRValue     string `json:"evrValue"`     // Version to compare
}

// OVALCriteria represents criteria in an OVAL definition (tree structure)
type OVALCriteria struct {
	ID           int64  `json:"id"`
	DefinitionID int64  `json:"definitionId"`
	ParentID     *int64 `json:"parentId,omitempty"`
	Operator     string `json:"operator"` // 'AND', 'OR'
	Negate       bool   `json:"negate"`
	Comment      string `json:"comment"`
}

// SyncStatus represents the status of a data sync operation
type SyncStatus struct {
	ID             int64      `json:"id"`
	SyncType       string     `json:"syncType"` // 'oval', 'nvd', 'exploitdb'
	SourceName     string     `json:"sourceName,omitempty"`
	Status         string     `json:"status"` // 'idle', 'syncing', 'success', 'error'
	StartedAt      *time.Time `json:"startedAt,omitempty"`
	ItemsProcessed int        `json:"itemsProcessed"`
	ErrorMessage   string     `json:"errorMessage,omitempty"`
}

// ============================================================================
// NVD CVE DATA
// ============================================================================

// CVEDetail represents a CVE entry from NVD
type CVEDetail struct {
	ID            int64          `json:"id"`
	CVEID         string         `json:"cveId"` // e.g., "CVE-2024-1234"
	Description   string         `json:"description"`
	CVSS2Score    *float64       `json:"cvss2Score,omitempty"`
	CVSS2Vector   string         `json:"cvss2Vector,omitempty"`
	CVSS3Score    *float64       `json:"cvss3Score,omitempty"`
	CVSS3Vector   string         `json:"cvss3Vector,omitempty"`
	CVSS3Severity string         `json:"cvss3Severity,omitempty"` // CRITICAL, HIGH, MEDIUM, LOW
	CWEIDs        []string       `json:"cweIds,omitempty"`
	References    []CVEReference `json:"references,omitempty"`
	PublishedAt   *time.Time     `json:"publishedAt,omitempty"`
	ModifiedAt    *time.Time     `json:"modifiedAt,omitempty"`
	CreatedAt     time.Time      `json:"createdAt"`
	UpdatedAt     time.Time      `json:"updatedAt"`
}

// CVEReference represents a reference URL for a CVE
type CVEReference struct {
	URL    string   `json:"url"`
	Source string   `json:"source,omitempty"`
	Tags   []string `json:"tags,omitempty"`
}

// ============================================================================
// REPORT SCHEDULES
// ============================================================================

// ReportSchedule represents a recurring report generation plan.
type ReportSchedule struct {
	ID            int64      `json:"id"`
	Name          string     `json:"name"`
	ScheduleType  string     `json:"scheduleType"`  // "weekly", "monthly_dom", "monthly_dow"
	IntervalValue int        `json:"intervalValue"`  // every N weeks/months
	DayOfWeek     *int       `json:"dayOfWeek"`      // 0=Sun..6=Sat
	WeekOfMonth   *int       `json:"weekOfMonth"`    // 1-5 (for monthly_dow)
	DayOfMonth    *int       `json:"dayOfMonth"`     // 1-31 (for monthly_dom)
	TimeHour      int        `json:"timeHour"`
	TimeMinute    int        `json:"timeMinute"`
	Timezone      string     `json:"timezone"`

	ServerIDs []int64 `json:"serverIds"`
	GroupIDs  []int64 `json:"groupIds"`

	PeriodType string `json:"periodType"` // "last_month", "last_week", "last_n_days"
	PeriodDays *int   `json:"periodDays"` // only for "last_n_days"

	IncludeSeverityChart bool `json:"includeSeverityChart"`
	IncludeTrendChart    bool `json:"includeTrendChart"`
	IncludeTopCVEs       bool `json:"includeTopCves"`
	IncludeFullCVEList   bool `json:"includeFullCveList"`

	Recipients []string `json:"recipients"`

	Enabled   bool       `json:"enabled"`
	LastRunAt *time.Time `json:"lastRunAt,omitempty"`
	NextRunAt *time.Time `json:"nextRunAt,omitempty"`
	LastError string     `json:"lastError,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}
