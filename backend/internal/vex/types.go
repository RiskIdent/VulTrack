package vex

// OpenVEX document structures (https://openvex.dev/ns/v0.2.0)

// Document represents a top-level OpenVEX document.
type Document struct {
	Metadata   Metadata    `json:"metadata"`
	Statements []Statement `json:"statements"`
}

// Metadata holds document-level metadata.
type Metadata struct {
	Context   string `json:"@context"`
	ID        string `json:"@id"`
	Author    string `json:"author"`
	Timestamp string `json:"timestamp"`
	Version   int    `json:"version"`
}

// Statement represents a single VEX statement.
type Statement struct {
	Vulnerability   Vulnerability `json:"vulnerability"`
	Timestamp       string        `json:"timestamp"`
	Products        []Product     `json:"products"`
	Status          string        `json:"status"`          // 'fixed' | 'not_affected' | 'affected' | 'under_investigation'
	StatusNotes     string        `json:"status_notes"`
	ActionStatement string        `json:"action_statement"`
}

// Vulnerability identifies the CVE or USN being described.
type Vulnerability struct {
	ID          string   `json:"@id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Aliases     []string `json:"aliases"`
}

// Product is a purl reference to a specific package/version/arch/distro.
type Product struct {
	ID string `json:"@id"` // e.g. "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1?arch=amd64&distro=jammy"
}

// Row is the normalised, deduplicated unit we store in vex_statements.
// One row per (CVE, package, distro, source_type).
type Row struct {
	CVEID         string
	PackageName   string
	Distro        string
	Status        string // storage value: 'not_affected' | 'will_not_fix' | 'under_investigation' | 'fixed'
	Justification string
	SourceType    string // 'cve' | 'usn'
	SourceID      string
}

// VEX status constants as stored in the findings table.
const (
	StatusNotAffected        = "not_affected"
	StatusWillNotFix         = "will_not_fix"
	StatusUnderInvestigation = "under_investigation"
	StatusFixed              = "fixed"
)

// statusPriority defines which status wins when multiple statements exist for
// the same (cve, package, distro, source_type). Lower number = higher priority.
var statusPriority = map[string]int{
	StatusNotAffected:        0,
	StatusFixed:              1,
	StatusUnderInvestigation: 2,
	StatusWillNotFix:         3,
}
