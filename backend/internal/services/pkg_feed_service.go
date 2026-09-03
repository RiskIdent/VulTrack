package services

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PkgFeedService stores and queries Canonical's package vulnerability feed
// (com.ubuntu.<series>.pkg.json.xz), the data `pro cves` evaluates.
type PkgFeedService struct {
	db *pgxpool.Pool
}

// NewPkgFeedService creates a new PkgFeedService
func NewPkgFeedService(db *pgxpool.Pool) *PkgFeedService {
	return &PkgFeedService{db: db}
}

// ============================================================================
// IMPORT
// ============================================================================

// PkgSourcePackage is a source package of the feed.
type PkgSourcePackage struct {
	Name string
	// IsKernel marks a kernel source package. Those are excluded from detection
	// because OVAL covers the kernel against the running kernel instead of every
	// installed kernel's binary packages.
	IsKernel bool
}

// PkgBinaryVersion maps one source version to the version of one of its binaries.
type PkgBinaryVersion struct {
	SourcePackage string
	SourceVersion string
	BinaryPackage string
	BinaryVersion string
	Pocket        string
}

// PkgCVEStatus is the status Canonical tracks for a CVE in one source package.
type PkgCVEStatus struct {
	SourcePackage string
	CVEID         string
	// Status is "vulnerable" (no fix published) or "fixed".
	Status string
	// SourceFixedVersion is set iff Status is "fixed".
	SourceFixedVersion string
}

// PkgCVEMetadata is the per-CVE information the feed carries.
type PkgCVEMetadata struct {
	CVEID          string
	UbuntuPriority string
	CVSSScore      *float64
	CVSSSeverity   string
	Description    string
	Notes          []string
	Mitigation     string
	PublishedAt    *time.Time
}

// PkgImportStats reports what an import stored.
type PkgImportStats struct {
	SourcePackages int
	KernelPackages int
	BinaryVersions int
	CVEStatuses    int
	CVEMetadata    int
	SkippedStatus  int // 'not-vulnerable' entries, which can never yield a finding
}

// PkgImport collects a feed import and writes it in one transaction.
//
// Rows are bulk-loaded with COPY because a release carries ~80k binary version
// rows and ~355k CVE statuses; per-row inserts make the sync take minutes.
type PkgImport struct {
	service  *PkgFeedService
	sourceID int64

	sourcePackages []PkgSourcePackage
	binaryVersions []PkgBinaryVersion
	cveStatuses    []PkgCVEStatus
	cveMetadata    []PkgCVEMetadata

	stats PkgImportStats
	tx    pgx.Tx
}

// pkgImportFlushThreshold bounds how many rows an import holds in memory before
// writing them out.
const pkgImportFlushThreshold = 50000

// BeginImport starts an import for a source. The source's existing feed data is
// cleared inside the same transaction, so a concurrent scan sees either the old
// or the new dataset but never a partial one.
func (s *PkgFeedService) BeginImport(ctx context.Context, sourceID int64) (*PkgImport, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}

	for _, table := range []string{
		"pkg_source_packages", "pkg_binary_versions", "pkg_cve_status", "pkg_cve_metadata",
	} {
		if _, err := tx.Exec(ctx, fmt.Sprintf("DELETE FROM %s WHERE source_id = $1", table), sourceID); err != nil {
			tx.Rollback(ctx)
			return nil, fmt.Errorf("failed to clear %s: %w", table, err)
		}
	}

	return &PkgImport{service: s, sourceID: sourceID, tx: tx}, nil
}

// AddSourcePackage records a source package of the feed.
func (i *PkgImport) AddSourcePackage(ctx context.Context, pkg PkgSourcePackage) error {
	i.sourcePackages = append(i.sourcePackages, pkg)
	i.stats.SourcePackages++
	if pkg.IsKernel {
		i.stats.KernelPackages++
	}
	return i.flushIfLarge(ctx)
}

// AddBinaryVersion records one source version -> binary version mapping.
func (i *PkgImport) AddBinaryVersion(ctx context.Context, bv PkgBinaryVersion) error {
	i.binaryVersions = append(i.binaryVersions, bv)
	i.stats.BinaryVersions++
	return i.flushIfLarge(ctx)
}

// AddCVEStatus records a CVE status. "not-vulnerable" entries are dropped: they
// are the majority of the feed and can never produce a finding.
func (i *PkgImport) AddCVEStatus(ctx context.Context, st PkgCVEStatus) error {
	if st.Status == "not-vulnerable" {
		i.stats.SkippedStatus++
		return nil
	}
	i.cveStatuses = append(i.cveStatuses, st)
	i.stats.CVEStatuses++
	return i.flushIfLarge(ctx)
}

// AddCVEMetadata records the feed's information about one CVE.
func (i *PkgImport) AddCVEMetadata(ctx context.Context, md PkgCVEMetadata) error {
	i.cveMetadata = append(i.cveMetadata, md)
	i.stats.CVEMetadata++
	return i.flushIfLarge(ctx)
}

func (i *PkgImport) flushIfLarge(ctx context.Context) error {
	if len(i.sourcePackages)+len(i.binaryVersions)+len(i.cveStatuses)+len(i.cveMetadata) < pkgImportFlushThreshold {
		return nil
	}
	return i.flush(ctx)
}

func (i *PkgImport) flush(ctx context.Context) error {
	if len(i.sourcePackages) > 0 {
		rows := i.sourcePackages
		_, err := i.tx.CopyFrom(ctx,
			pgx.Identifier{"pkg_source_packages"},
			[]string{"source_id", "name", "is_kernel"},
			pgx.CopyFromSlice(len(rows), func(n int) ([]any, error) {
				return []any{i.sourceID, rows[n].Name, rows[n].IsKernel}, nil
			}))
		if err != nil {
			return fmt.Errorf("failed to copy source packages: %w", err)
		}
		i.sourcePackages = i.sourcePackages[:0]
	}

	if len(i.binaryVersions) > 0 {
		rows := i.binaryVersions
		_, err := i.tx.CopyFrom(ctx,
			pgx.Identifier{"pkg_binary_versions"},
			[]string{"source_id", "source_package", "source_version", "binary_package", "binary_version", "pocket"},
			pgx.CopyFromSlice(len(rows), func(n int) ([]any, error) {
				return []any{i.sourceID, rows[n].SourcePackage, rows[n].SourceVersion,
					rows[n].BinaryPackage, rows[n].BinaryVersion, rows[n].Pocket}, nil
			}))
		if err != nil {
			return fmt.Errorf("failed to copy binary versions: %w", err)
		}
		i.binaryVersions = i.binaryVersions[:0]
	}

	if len(i.cveStatuses) > 0 {
		rows := i.cveStatuses
		_, err := i.tx.CopyFrom(ctx,
			pgx.Identifier{"pkg_cve_status"},
			[]string{"source_id", "source_package", "cve_id", "status", "source_fixed_version"},
			pgx.CopyFromSlice(len(rows), func(n int) ([]any, error) {
				var fixed *string
				if rows[n].SourceFixedVersion != "" {
					fixed = &rows[n].SourceFixedVersion
				}
				return []any{i.sourceID, rows[n].SourcePackage, rows[n].CVEID, rows[n].Status, fixed}, nil
			}))
		if err != nil {
			return fmt.Errorf("failed to copy CVE statuses: %w", err)
		}
		i.cveStatuses = i.cveStatuses[:0]
	}

	if len(i.cveMetadata) > 0 {
		rows := i.cveMetadata
		_, err := i.tx.CopyFrom(ctx,
			pgx.Identifier{"pkg_cve_metadata"},
			[]string{"source_id", "cve_id", "ubuntu_priority", "cvss_score", "cvss_severity",
				"description", "notes", "mitigation", "published_at"},
			pgx.CopyFromSlice(len(rows), func(n int) ([]any, error) {
				r := rows[n]
				return []any{i.sourceID, r.CVEID, r.UbuntuPriority, r.CVSSScore, r.CVSSSeverity,
					r.Description, r.Notes, r.Mitigation, r.PublishedAt}, nil
			}))
		if err != nil {
			return fmt.Errorf("failed to copy CVE metadata: %w", err)
		}
		i.cveMetadata = i.cveMetadata[:0]
	}

	return nil
}

// Commit writes the remaining rows and commits the import.
func (i *PkgImport) Commit(ctx context.Context) (*PkgImportStats, error) {
	if err := i.flush(ctx); err != nil {
		i.tx.Rollback(ctx)
		return nil, err
	}
	if err := i.tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit feed import: %w", err)
	}
	stats := i.stats
	return &stats, nil
}

// Rollback discards the import.
func (i *PkgImport) Rollback(ctx context.Context) {
	i.tx.Rollback(ctx)
}

// ============================================================================
// ENRICHMENT
// ============================================================================

// BackfillCVECatalog copies CVSS scores, descriptions and publication dates from
// the feed into cve_catalog for fields NVD has not filled.
//
// The feed ships them for the whole release in one download, while the NVD sync
// is rate-limited and lags behind. Only NULL fields are written, and the NVD
// sync overwrites unconditionally, so NVD stays authoritative wherever it has a
// value.
func (s *PkgFeedService) BackfillCVECatalog(ctx context.Context, sourceID int64) (int64, error) {
	tag, err := s.db.Exec(ctx, `
		INSERT INTO cve_catalog (cve_id, description, cvss3_score, cvss3_severity, published_at, updated_at)
		SELECT m.cve_id, NULLIF(m.description, ''), m.cvss_score, NULLIF(m.cvss_severity, ''), m.published_at, NOW()
		FROM pkg_cve_metadata m
		WHERE m.source_id = $1
		  AND (m.cvss_score IS NOT NULL OR NULLIF(m.description, '') IS NOT NULL)
		ON CONFLICT (cve_id) DO UPDATE SET
			description    = COALESCE(cve_catalog.description, EXCLUDED.description),
			cvss3_score    = COALESCE(cve_catalog.cvss3_score, EXCLUDED.cvss3_score),
			cvss3_severity = COALESCE(cve_catalog.cvss3_severity, EXCLUDED.cvss3_severity),
			published_at   = COALESCE(cve_catalog.published_at, EXCLUDED.published_at),
			updated_at     = NOW()
	`, sourceID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// AnalyzePkgTables refreshes planner statistics after an import replaced the
// whole dataset of a source.
func (s *PkgFeedService) AnalyzePkgTables(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `
		ANALYZE pkg_source_packages, pkg_binary_versions, pkg_cve_status, pkg_cve_metadata
	`)
	return err
}

// ============================================================================
// SCAN SUPPORT
// ============================================================================

// PkgCandidate is one CVE the feed tracks for an installed package.
type PkgCandidate struct {
	PackageName      string
	InstalledVersion string
	CVEID            string
	Status           string
	// FixedBinaryVersion is the version of this binary package in the source
	// version that fixes the CVE. Empty when the fix does not produce this binary
	// any more (a package transition) or when no fix exists yet.
	FixedBinaryVersion string
	Pocket             string
	UbuntuPriority     string
}

// GetScanCandidates returns every CVE the feed tracks for the server's installed
// packages, excluding kernel source packages.
//
// The source package of an installed binary comes from the agent's dpkg
// metadata when available and is otherwise resolved through the feed's own
// binary -> source mapping; the feed's mapping has gaps (a handful of source
// packages ship no binary list at all), so the agent's value is preferred.
func (s *PkgFeedService) GetScanCandidates(ctx context.Context, sourceID, serverID int64) ([]PkgCandidate, error) {
	rows, err := s.db.Query(ctx, `
		WITH installed AS (
			SELECT sp.name, sp.version, NULLIF(sp.source_package, '') AS declared_source
			FROM server_packages sp
			WHERE sp.server_id = $2 AND sp.removed_at IS NULL
		),
		resolved AS (
			SELECT DISTINCT
				i.name,
				i.version,
				COALESCE(i.declared_source, bv.source_package) AS source_package
			FROM installed i
			LEFT JOIN pkg_binary_versions bv
			  ON i.declared_source IS NULL
			 AND bv.source_id = $1
			 AND bv.binary_package = i.name
			WHERE COALESCE(i.declared_source, bv.source_package) IS NOT NULL
		)
		SELECT r.name, r.version, st.cve_id, st.status,
		       COALESCE(fix.binary_version, ''), COALESCE(fix.pocket, ''),
		       COALESCE(md.ubuntu_priority, '')
		FROM resolved r
		JOIN pkg_source_packages ps
		  ON ps.source_id = $1 AND ps.name = r.source_package AND ps.is_kernel = false
		JOIN pkg_cve_status st
		  ON st.source_id = $1 AND st.source_package = r.source_package
		LEFT JOIN pkg_binary_versions fix
		  ON fix.source_id = $1
		 AND fix.source_package = r.source_package
		 AND fix.source_version = st.source_fixed_version
		 AND fix.binary_package = r.name
		LEFT JOIN pkg_cve_metadata md
		  ON md.source_id = $1 AND md.cve_id = st.cve_id
	`, sourceID, serverID)
	if err != nil {
		return nil, fmt.Errorf("failed to query feed scan candidates: %w", err)
	}
	defer rows.Close()

	var candidates []PkgCandidate
	for rows.Next() {
		var c PkgCandidate
		if err := rows.Scan(&c.PackageName, &c.InstalledVersion, &c.CVEID, &c.Status,
			&c.FixedBinaryVersion, &c.Pocket, &c.UbuntuPriority); err != nil {
			return nil, err
		}
		candidates = append(candidates, c)
	}
	return candidates, rows.Err()
}

// GetCVEMetadata returns the feed's information about a CVE for the OVAL source
// matching a distribution release, or nil when the feed does not cover it.
func (s *PkgFeedService) GetCVEMetadata(ctx context.Context, cveID, distribution, version, codename string) (*PkgCVEMetadata, error) {
	var md PkgCVEMetadata
	err := s.db.QueryRow(ctx, `
		SELECT m.cve_id, COALESCE(m.ubuntu_priority, ''), m.cvss_score,
		       COALESCE(m.cvss_severity, ''), COALESCE(m.description, ''),
		       COALESCE(m.notes, ARRAY[]::text[]), COALESCE(m.mitigation, ''), m.published_at
		FROM pkg_cve_metadata m
		JOIN oval_sources os ON os.id = m.source_id
		WHERE m.cve_id = $1
		  AND os.distribution = LOWER($2)
		  AND (os.version = $3 OR ($4 <> '' AND os.codename = $4))
		LIMIT 1
	`, cveID, distribution, version, codename).Scan(
		&md.CVEID, &md.UbuntuPriority, &md.CVSSScore, &md.CVSSSeverity,
		&md.Description, &md.Notes, &md.Mitigation, &md.PublishedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &md, nil
}

// ============================================================================
// KERNEL CROSS-CHECK
// ============================================================================

// KernelVerdict is what the feed records about one CVE for one kernel source
// package.
type KernelVerdict struct {
	// Status is "vulnerable" or "fixed". It is empty when the feed tracks the
	// CVE but holds no actionable status for this source package, which means
	// Canonical triaged the source as not affected.
	Status string
	// SourceFixedVersion is set iff Status is "fixed".
	SourceFixedVersion string
}

// IsKernelSourcePackage reports whether name is a kernel source package this
// feed knows about.
//
// Callers must gate on this before trusting a source package name resolved from
// dpkg metadata. Ubuntu builds the signed kernel image in a separate
// "linux-signed" source package, which the feed does not contain at all — and a
// name the feed does not know has no status rows, so treating it as a kernel
// source would suppress every kernel finding instead of none.
func (s *PkgFeedService) IsKernelSourcePackage(ctx context.Context, sourceID int64, name string) (bool, error) {
	if name == "" {
		return false, nil
	}
	var known bool
	err := s.db.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pkg_source_packages
			WHERE source_id = $1 AND name = $2 AND is_kernel = true
		)
	`, sourceID, name).Scan(&known)
	return known, err
}

// KernelSourceForRelease resolves a kernel release string ("6.8.0-124-generic")
// to the kernel source package that produced it, through the feed's own binary
// package map.
//
// Returns "" when the release is unknown or maps to more than one source
// package. The latter is not rare: linux-hwe-6.14 and linux-riscv-6.14 both
// build "linux-image-6.14.0-33-generic", and only the agent's dpkg metadata can
// say which one a host actually installed.
func (s *PkgFeedService) KernelSourceForRelease(ctx context.Context, sourceID int64, release string) (string, error) {
	if release == "" {
		return "", nil
	}

	// The feed lists kernel binaries under both the signed and unsigned name.
	imageNames := []string{"linux-image-" + release, "linux-image-unsigned-" + release}

	rows, err := s.db.Query(ctx, `
		SELECT DISTINCT bv.source_package
		FROM pkg_binary_versions bv
		JOIN pkg_source_packages ps
		  ON ps.source_id = bv.source_id AND ps.name = bv.source_package AND ps.is_kernel = true
		WHERE bv.source_id = $1 AND bv.binary_package = ANY($2)
		LIMIT 2
	`, sourceID, imageNames)
	if err != nil {
		return "", fmt.Errorf("failed to resolve kernel source for %q: %w", release, err)
	}
	defer rows.Close()

	var resolved []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return "", err
		}
		resolved = append(resolved, name)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}

	if len(resolved) != 1 {
		return "", nil
	}
	return resolved[0], nil
}

// KernelVerdicts returns the feed's position on every CVE it knows, for one
// kernel source package.
//
// A CVE missing from the result is one the feed does not track at all, which
// callers must treat as "no opinion" rather than "not affected": the importer
// drops 'not-vulnerable' rows, so absence of a status row only means "not
// affected" for a CVE the feed actually covers.
func (s *PkgFeedService) KernelVerdicts(ctx context.Context, sourceID int64, kernelSource string) (map[string]KernelVerdict, error) {
	if kernelSource == "" {
		return nil, nil
	}

	rows, err := s.db.Query(ctx, `
		SELECT m.cve_id, COALESCE(st.status, ''), COALESCE(st.source_fixed_version, '')
		FROM pkg_cve_metadata m
		LEFT JOIN pkg_cve_status st
		  ON st.source_id = m.source_id
		 AND st.cve_id = m.cve_id
		 AND st.source_package = $2
		WHERE m.source_id = $1
	`, sourceID, kernelSource)
	if err != nil {
		return nil, fmt.Errorf("failed to load kernel verdicts for %q: %w", kernelSource, err)
	}
	defer rows.Close()

	verdicts := make(map[string]KernelVerdict)
	for rows.Next() {
		var cveID string
		var verdict KernelVerdict
		if err := rows.Scan(&cveID, &verdict.Status, &verdict.SourceFixedVersion); err != nil {
			return nil, err
		}
		verdicts[cveID] = verdict
	}
	return verdicts, rows.Err()
}
