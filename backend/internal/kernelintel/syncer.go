package kernelintel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"

	"github.com/vultrack/vultrack/internal/services"
)

// Syncer keeps the kernel data R-KMOD needs up to date: the program files of
// every kernel CVE with active findings, and the source map of every kernel
// build a server with runtime facts runs.
type Syncer struct {
	db       *pgxpool.Pool
	settings *services.SettingsService
	fetch    *Fetcher

	// CVERate is the pause between two CVE API requests.
	CVERate time.Duration
	// AfterChange runs when new data arrived (re-evaluate decisions).
	AfterChange func(reason string)

	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// NewSyncer creates a Syncer.
func NewSyncer(db *pgxpool.Pool, settings *services.SettingsService, fetch *Fetcher) *Syncer {
	return &Syncer{db: db, settings: settings, fetch: fetch, CVERate: 200 * time.Millisecond, stopCh: make(chan struct{})}
}

// Start runs a sync shortly after start-up and then every hour.
func (s *Syncer) Start() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		timer := time.NewTimer(5 * time.Minute)
		defer timer.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-timer.C:
				s.RunOnce(context.Background())
				timer.Reset(time.Hour)
			}
		}
	}()
}

// Stop stops the schedule.
func (s *Syncer) Stop() {
	close(s.stopCh)
	s.wg.Wait()
}

// Running reports whether a sync is in progress.
func (s *Syncer) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// RunOnce fetches what is missing. It does nothing while automated assessment
// is off, so a disabled feature causes no downloads.
func (s *Syncer) RunOnce(ctx context.Context) {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()

	cfg, err := s.settings.LoadAutoAssessmentConfig(ctx)
	if err != nil || cfg.Mode == services.AutoModeOff || cfg.RuleMode("R-KMOD") == services.AutoModeOff {
		return
	}
	// Builds first: a handful of downloads, while the first CVE fetch takes
	// about half an hour.
	builds, err := s.syncBuilds(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Kernel build sync failed")
	}
	cves, err := s.syncCVEFiles(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Kernel CVE files sync failed")
	}
	if (cves > 0 || builds > 0) && s.AfterChange != nil {
		s.AfterChange("kernel data")
	}
}

// syncCVEFiles fetches CVE records of kernel CVEs with active findings that
// were never fetched, failed more than a day ago, or are older than 30 days.
func (s *Syncer) syncCVEFiles(ctx context.Context) (int, error) {
	rows, err := s.db.Query(ctx, `
		SELECT DISTINCT f.cve_id
		FROM findings f
		LEFT JOIN kernel_cve_files k ON k.cve_id = f.cve_id
		WHERE f.package_name = 'kernel' AND f.resolved_at IS NULL
		  AND (k.cve_id IS NULL
		       OR (k.status = 'error' AND k.fetched_at < NOW() - interval '1 day')
		       OR k.fetched_at < NOW() - interval '30 days')
		ORDER BY f.cve_id
	`)
	if err != nil {
		return 0, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	log.Info().Int("cves", len(ids)).Msg("Fetching kernel CVE records")
	changed := 0
	for i, id := range ids {
		select {
		case <-s.stopCh:
			return changed, nil
		default:
		}
		files, err := s.fetch.FetchCVEFiles(ctx, id)
		status, errText := "ok", ""
		switch {
		case errors.Is(err, ErrNotFound):
			status = "not_found"
		case err != nil:
			status, errText = "error", err.Error()
		case len(files.ProgramFiles) == 0:
			status = "no_files"
		}
		if files.ProgramFiles == nil {
			files.ProgramFiles = []string{}
		}
		tag, dbErr := s.db.Exec(ctx, `
			INSERT INTO kernel_cve_files (cve_id, status, assigner, program_files, error, fetched_at)
			VALUES ($1, $2, NULLIF($3, ''), $4, NULLIF($5, ''), NOW())
			ON CONFLICT (cve_id) DO UPDATE SET
				status = EXCLUDED.status, assigner = COALESCE(EXCLUDED.assigner, kernel_cve_files.assigner),
				program_files = CASE WHEN EXCLUDED.status = 'error' THEN kernel_cve_files.program_files ELSE EXCLUDED.program_files END,
				error = EXCLUDED.error, fetched_at = NOW()
		`, id, status, files.Assigner, files.ProgramFiles, errText)
		if dbErr != nil {
			return changed, dbErr
		}
		if status == "ok" && tag.RowsAffected() > 0 {
			changed++
		}
		if (i+1)%500 == 0 {
			log.Info().Int("done", i+1).Int("of", len(ids)).Msg("Fetching kernel CVE records")
		}
		time.Sleep(s.CVERate)
	}
	return changed, nil
}

// syncBuilds maps every kernel build that a server with kernel facts runs and
// that has no map yet (failed builds are retried after a day).
func (s *Syncer) syncBuilds(ctx context.Context) (int, error) {
	rows, err := s.db.Query(ctx, `
		SELECT DISTINCT snap.data ->> 'release', sp.version, COALESCE(sp.source_package, ''), srv.arch
		FROM server_facts sf
		JOIN fact_snapshots snap ON snap.hash = sf.hash
		JOIN servers srv ON srv.id = sf.server_id
		JOIN server_packages sp ON sp.server_id = sf.server_id AND sp.removed_at IS NULL
		     AND sp.name = 'linux-modules-' || (snap.data ->> 'release')
		LEFT JOIN kernel_builds kb ON kb.release = snap.data ->> 'release' AND kb.version = sp.version AND kb.arch = srv.arch
		WHERE sf.category = 'kernel'
		  AND (kb.id IS NULL OR (kb.status = 'error' AND kb.built_at < NOW() - interval '1 day'))
	`)
	if err != nil {
		return 0, err
	}
	var inputs []BuildInput
	for rows.Next() {
		var in BuildInput
		if err := rows.Scan(&in.Release, &in.Version, &in.Source, &in.Arch); err != nil {
			rows.Close()
			return 0, err
		}
		inputs = append(inputs, in)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	built := 0
	for _, in := range inputs {
		select {
		case <-s.stopCh:
			return built, nil
		default:
		}
		start := time.Now()
		res, err := s.fetch.FetchBuild(ctx, in)
		if err != nil {
			log.Warn().Err(err).Str("kernel", in.Release).Str("version", in.Version).Msg("Kernel build map failed")
			if _, dbErr := s.db.Exec(ctx, `
				INSERT INTO kernel_builds (release, version, arch, status, error, built_at)
				VALUES ($1, $2, $3, 'error', $4, NOW())
				ON CONFLICT (release, version, arch) DO UPDATE SET status = 'error', error = EXCLUDED.error, built_at = NOW()
			`, in.Release, in.Version, in.Arch, err.Error()); dbErr != nil {
				return built, dbErr
			}
			continue
		}
		if err := s.saveBuild(ctx, in, res); err != nil {
			return built, err
		}
		built++
		log.Info().Str("kernel", in.Release).Str("version", in.Version).Int("sourceFiles", len(res.Map)).
			Bool("modulesVerified", res.ModulesVerified).Dur("duration", time.Since(start)).Msg("Kernel build mapped")
	}
	return built, nil
}

func (s *Syncer) saveBuild(ctx context.Context, in BuildInput, res *BuildResult) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var id int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO kernel_builds (release, version, arch, status, error, headers_package, source_files, modules_verified, shipped_modules, built_at)
		VALUES ($1, $2, $3, 'ok', NULL, $4, $5, $6, $7, NOW())
		ON CONFLICT (release, version, arch) DO UPDATE SET
			status = 'ok', error = NULL, headers_package = EXCLUDED.headers_package,
			source_files = EXCLUDED.source_files, modules_verified = EXCLUDED.modules_verified,
			shipped_modules = EXCLUDED.shipped_modules, built_at = NOW()
		RETURNING id
	`, in.Release, in.Version, in.Arch, res.HeadersPackage, len(res.Map), res.ModulesVerified, res.ShippedModules).Scan(&id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM kernel_source_files WHERE build_id = $1`, id); err != nil {
		return err
	}
	paths := make([]string, 0, len(res.Map))
	for p := range res.Map {
		paths = append(paths, p)
	}
	_, err = tx.CopyFrom(ctx, pgx.Identifier{"kernel_source_files"}, []string{"build_id", "path", "targets"},
		pgx.CopyFromSlice(len(paths), func(i int) ([]any, error) {
			b, err := json.Marshal(res.Map[paths[i]])
			if err != nil {
				return nil, fmt.Errorf("encode targets: %w", err)
			}
			return []any{id, paths[i], b}, nil
		}))
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Status summarises the kernel data for the UI.
type Status struct {
	CVEs struct {
		Total    int `json:"total"`
		WithData int `json:"withData"` // records listing program files
		NoFiles  int `json:"noFiles"`  // records without program files (other CNAs)
		Errors   int `json:"errors"`
		Pending  int `json:"pending"` // kernel CVEs with findings not fetched yet
	} `json:"cves"`
	Builds  []BuildStatus `json:"builds"`
	Running bool          `json:"running"`
}

// BuildStatus is one mapped kernel build.
type BuildStatus struct {
	Release         string    `json:"release"`
	Version         string    `json:"version"`
	Arch            string    `json:"arch"`
	Status          string    `json:"status"`
	Error           string    `json:"error,omitempty"`
	SourceFiles     int       `json:"sourceFiles"`
	ModulesVerified bool      `json:"modulesVerified"`
	Servers         int       `json:"servers"`
	BuiltAt         time.Time `json:"builtAt"`
}

// GetStatus reports the state of the kernel data.
func (s *Syncer) GetStatus(ctx context.Context) (*Status, error) {
	st := &Status{Builds: []BuildStatus{}, Running: s.Running()}
	if err := s.db.QueryRow(ctx, `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE status = 'ok'), COUNT(*) FILTER (WHERE status IN ('no_files', 'not_found')),
		       COUNT(*) FILTER (WHERE status = 'error')
		FROM kernel_cve_files
	`).Scan(&st.CVEs.Total, &st.CVEs.WithData, &st.CVEs.NoFiles, &st.CVEs.Errors); err != nil {
		return nil, err
	}
	if err := s.db.QueryRow(ctx, `
		SELECT COUNT(DISTINCT f.cve_id) FROM findings f
		LEFT JOIN kernel_cve_files k ON k.cve_id = f.cve_id
		WHERE f.package_name = 'kernel' AND f.resolved_at IS NULL AND k.cve_id IS NULL
	`).Scan(&st.CVEs.Pending); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `
		SELECT kb.release, kb.version, kb.arch, kb.status, COALESCE(kb.error, ''), kb.source_files, kb.modules_verified, kb.built_at,
		       (SELECT COUNT(DISTINCT sf.server_id) FROM server_facts sf
		        JOIN fact_snapshots snap ON snap.hash = sf.hash
		        JOIN server_packages sp ON sp.server_id = sf.server_id AND sp.removed_at IS NULL
		             AND sp.name = 'linux-modules-' || (snap.data ->> 'release')
		        WHERE sf.category = 'kernel' AND snap.data ->> 'release' = kb.release AND sp.version = kb.version)
		FROM kernel_builds kb ORDER BY kb.release DESC, kb.version DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var b BuildStatus
		if err := rows.Scan(&b.Release, &b.Version, &b.Arch, &b.Status, &b.Error, &b.SourceFiles, &b.ModulesVerified, &b.BuiltAt, &b.Servers); err != nil {
			return nil, err
		}
		st.Builds = append(st.Builds, b)
	}
	return st, rows.Err()
}
