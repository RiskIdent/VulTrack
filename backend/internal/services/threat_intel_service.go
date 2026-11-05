package services

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vultrack/vultrack/internal/models"
)

// ThreatIntelService reads the CISA KEV and FIRST EPSS data kept up to date by
// the threatintel syncer.
type ThreatIntelService struct {
	db *pgxpool.Pool
}

// NewThreatIntelService creates a ThreatIntelService.
func NewThreatIntelService(db *pgxpool.Pool) *ThreatIntelService {
	return &ThreatIntelService{db: db}
}

// CVEThreatIntel is the KEV and EPSS data for one CVE, with the KEV details
// that list views leave out.
type CVEThreatIntel struct {
	models.ThreatIntel
	KEVVendorProject     string     `json:"kevVendorProject,omitempty"`
	KEVProduct           string     `json:"kevProduct,omitempty"`
	KEVVulnerabilityName string     `json:"kevVulnerabilityName,omitempty"`
	KEVNotes             string     `json:"kevNotes,omitempty"`
	EPSSScoreDate        *time.Time `json:"epssScoreDate,omitempty"`
}

// GetForCVE returns the KEV and EPSS data of a CVE. A CVE in neither source
// yields a zero value, not an error.
func (s *ThreatIntelService) GetForCVE(ctx context.Context, cveID string) (*CVEThreatIntel, error) {
	var t CVEThreatIntel
	err := s.db.QueryRow(ctx, `
		SELECT kev.cve_id IS NOT NULL, kev.date_added, kev.due_date,
		       COALESCE(kev.known_ransomware_use, false), ep.epss::float8, ep.percentile::float8,
		       COALESCE(kev.vendor_project, ''), COALESCE(kev.product, ''),
		       COALESCE(kev.vulnerability_name, ''), COALESCE(kev.notes, ''), ep.score_date
		FROM (SELECT $1::varchar AS cve_id) c
		LEFT JOIN kev_entries kev ON kev.cve_id = c.cve_id
		LEFT JOIN epss_scores ep ON ep.cve_id = c.cve_id
	`, cveID).Scan(&t.InKEV, &t.KEVDateAdded, &t.KEVDueDate, &t.KEVRansomware, &t.EPSS, &t.EPSSPercentile,
		&t.KEVVendorProject, &t.KEVProduct, &t.KEVVulnerabilityName, &t.KEVNotes, &t.EPSSScoreDate)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// ThreatIntelSourceStatus is the sync state of one feed.
type ThreatIntelSourceStatus struct {
	Source           string     `json:"source"`
	Records          int        `json:"records"` // rows currently stored
	LastSyncAt       *time.Time `json:"lastSyncAt,omitempty"`
	Status           string     `json:"status,omitempty"`
	Error            string     `json:"error,omitempty"`
	RecordsProcessed int        `json:"recordsProcessed"`
	IntervalHours    string     `json:"intervalHours"`
	Syncing          bool       `json:"syncing"`
}

// Status returns the sync state of KEV and EPSS. Syncing is filled in by the
// caller, which knows the syncer.
func (s *ThreatIntelService) Status(ctx context.Context) ([]ThreatIntelSourceStatus, error) {
	sources := []struct{ name, table string }{{"kev", "kev_entries"}, {"epss", "epss_scores"}}
	out := make([]ThreatIntelSourceStatus, 0, len(sources))
	for _, src := range sources {
		st := ThreatIntelSourceStatus{Source: src.name}
		// Table names come from the fixed list above.
		if err := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM `+src.table).Scan(&st.Records); err != nil {
			return nil, err
		}
		var status, errMsg *string
		var processed *int
		err := s.db.QueryRow(ctx, `
			SELECT last_sync_at, status, error_message, records_processed
			FROM sync_status WHERE source_type = $1 AND source_name = $1
		`, src.name).Scan(&st.LastSyncAt, &status, &errMsg, &processed)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		if status != nil {
			st.Status = *status
		}
		if errMsg != nil {
			st.Error = *errMsg
		}
		if processed != nil {
			st.RecordsProcessed = *processed
		}
		st.IntervalHours, _ = s.getInterval(ctx, src.name)
		out = append(out, st)
	}
	return out, nil
}

func (s *ThreatIntelService) getInterval(ctx context.Context, source string) (string, error) {
	var v string
	err := s.db.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, source+"_sync_interval_hours").Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return "24", nil
	}
	return v, err
}
