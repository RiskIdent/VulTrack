package threatintel

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"

	"github.com/vultrack/vultrack/internal/services"
)

// Source identifies one of the two feeds. The value is also the source_type and
// source_name of its sync_status row.
type Source string

const (
	SourceKEV  Source = "kev"
	SourceEPSS Source = "epss"
)

// Sources lists the feeds in sync order.
var Sources = []Source{SourceKEV, SourceEPSS}

const (
	kevURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	epssURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

	// Sanity floors: a download below these is treated as broken, so a
	// truncated or empty file never wipes the stored data. Today KEV has
	// ~1,800 entries and EPSS ~400,000 rows.
	minKEVEntries = 1000
	minEPSSRows   = 200000

	maxKEVBytes  = 50 << 20  // decoded JSON
	maxEPSSBytes = 200 << 20 // decompressed CSV
)

// Syncer keeps kev_entries and epss_scores up to date.
type Syncer struct {
	db              *pgxpool.Pool
	settingsService *services.SettingsService
	httpClient      *http.Client
	urls            map[Source]string

	mu      sync.Mutex
	running map[Source]bool

	stopCh chan struct{}
	wg     sync.WaitGroup

	// afterSync runs after every successful sync of a feed.
	afterSync func(src Source)
}

// SetAfterSync registers a function that runs after every successful sync.
func (s *Syncer) SetAfterSync(f func(src Source)) {
	s.afterSync = f
}

// New creates the syncer for both feeds.
func New(db *pgxpool.Pool, settingsService *services.SettingsService) *Syncer {
	return &Syncer{
		db:              db,
		settingsService: settingsService,
		httpClient:      &http.Client{Timeout: 5 * time.Minute},
		urls:            map[Source]string{SourceKEV: kevURL, SourceEPSS: epssURL},
		running:         map[Source]bool{},
		stopCh:          make(chan struct{}),
	}
}

// Start runs the background schedule: shortly after start-up, then hourly it
// syncs every feed whose interval has passed.
func (s *Syncer) Start() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		timer := time.NewTimer(3 * time.Minute) // let the other syncers start first
		defer timer.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-timer.C:
				for _, src := range Sources {
					if s.due(src) {
						if err := s.Sync(context.Background(), src); err != nil {
							log.Error().Err(err).Str("source", string(src)).Msg("Threat intel sync failed")
						}
					}
				}
				timer.Reset(time.Hour)
			}
		}
	}()
	log.Info().Msg("Threat intel syncer (KEV, EPSS) started")
}

// Stop stops the schedule and waits for it to finish.
func (s *Syncer) Stop() {
	close(s.stopCh)
	s.wg.Wait()
}

// IsSyncing reports whether a sync of src is running.
func (s *Syncer) IsSyncing(src Source) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running[src]
}

// TriggerSync starts a sync of src in the background.
func (s *Syncer) TriggerSync(src Source) error {
	if _, ok := s.urls[src]; !ok {
		return fmt.Errorf("unknown threat intel source %q", src)
	}
	if s.IsSyncing(src) {
		return fmt.Errorf("%s sync already running", src)
	}
	go func() {
		if err := s.Sync(context.Background(), src); err != nil {
			log.Error().Err(err).Str("source", string(src)).Msg("Manual threat intel sync failed")
		}
	}()
	return nil
}

func (s *Syncer) interval(src Source) time.Duration {
	value, err := s.settingsService.GetValue(context.Background(), string(src)+"_sync_interval_hours")
	if hours, convErr := strconv.Atoi(value); err == nil && convErr == nil && hours > 0 {
		return time.Duration(hours) * time.Hour
	}
	return 24 * time.Hour
}

func (s *Syncer) due(src Source) bool {
	var last *time.Time
	err := s.db.QueryRow(context.Background(), `
		SELECT last_sync_at FROM sync_status WHERE source_type = $1 AND source_name = $1
	`, string(src)).Scan(&last)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		log.Error().Err(err).Str("source", string(src)).Msg("Read threat intel sync status")
		return false
	}
	return last == nil || time.Since(*last) >= s.interval(src)
}

// Sync downloads and stores one feed. Only one sync per feed runs at a time.
func (s *Syncer) Sync(ctx context.Context, src Source) error {
	s.mu.Lock()
	if s.running[src] {
		s.mu.Unlock()
		return fmt.Errorf("%s sync already running", src)
	}
	s.running[src] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.running[src] = false
		s.mu.Unlock()
	}()

	start := time.Now()
	s.setStatus(ctx, src, "syncing", "", 0)

	var n int
	var err error
	switch src {
	case SourceKEV:
		n, err = s.syncKEV(ctx)
	case SourceEPSS:
		n, err = s.syncEPSS(ctx)
	default:
		err = fmt.Errorf("unknown source %q", src)
	}
	if err != nil {
		s.setStatus(ctx, src, "error", err.Error(), 0)
		return err
	}
	s.setStatus(ctx, src, "success", "", n)
	if s.afterSync != nil {
		s.afterSync(src)
	}
	log.Info().Str("source", string(src)).Int("records", n).Dur("duration", time.Since(start)).Msg("Threat intel sync completed")
	return nil
}

func (s *Syncer) download(ctx context.Context, src Source) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.urls[src], nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "VulTrack")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("download %s: HTTP %d", src, resp.StatusCode)
	}
	return resp.Body, nil
}

func (s *Syncer) syncKEV(ctx context.Context) (int, error) {
	body, err := s.download(ctx, SourceKEV)
	if err != nil {
		return 0, err
	}
	defer body.Close()
	entries, version, err := ParseKEV(io.LimitReader(body, maxKEVBytes))
	if err != nil {
		return 0, err
	}
	if len(entries) < minKEVEntries {
		return 0, fmt.Errorf("KEV catalog %s has only %d entries; refusing to replace the stored catalog", version, len(entries))
	}
	return len(entries), StoreKEV(ctx, s.db, entries)
}

// StoreKEV replaces the stored catalog with entries: new and changed rows are
// upserted (unchanged rows are not rewritten), rows no longer listed are deleted.
func StoreKEV(ctx context.Context, db *pgxpool.Pool, entries []KEVEntry) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE kev_import (LIKE kev_entries INCLUDING DEFAULTS) ON COMMIT DROP
	`); err != nil {
		return err
	}
	_, err = tx.CopyFrom(ctx, pgx.Identifier{"kev_import"},
		[]string{"cve_id", "vendor_project", "product", "vulnerability_name", "date_added", "due_date", "known_ransomware_use", "notes"},
		pgx.CopyFromSlice(len(entries), func(i int) ([]any, error) {
			e := entries[i]
			return []any{e.CVEID, e.VendorProject, e.Product, e.VulnerabilityName, e.DateAdded, e.DueDate, e.KnownRansomwareUse, e.Notes}, nil
		}))
	if err != nil {
		return fmt.Errorf("copy KEV entries: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO kev_entries (cve_id, vendor_project, product, vulnerability_name, date_added, due_date, known_ransomware_use, notes, updated_at)
		SELECT cve_id, vendor_project, product, vulnerability_name, date_added, due_date, known_ransomware_use, notes, NOW()
		FROM kev_import
		ON CONFLICT (cve_id) DO UPDATE SET
			vendor_project = EXCLUDED.vendor_project,
			product = EXCLUDED.product,
			vulnerability_name = EXCLUDED.vulnerability_name,
			date_added = EXCLUDED.date_added,
			due_date = EXCLUDED.due_date,
			known_ransomware_use = EXCLUDED.known_ransomware_use,
			notes = EXCLUDED.notes,
			updated_at = NOW()
		WHERE (kev_entries.vendor_project, kev_entries.product, kev_entries.vulnerability_name,
		       kev_entries.date_added, kev_entries.due_date, kev_entries.known_ransomware_use, kev_entries.notes)
		      IS DISTINCT FROM
		      (EXCLUDED.vendor_project, EXCLUDED.product, EXCLUDED.vulnerability_name,
		       EXCLUDED.date_added, EXCLUDED.due_date, EXCLUDED.known_ransomware_use, EXCLUDED.notes)
	`); err != nil {
		return fmt.Errorf("upsert KEV entries: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM kev_entries k WHERE NOT EXISTS (SELECT 1 FROM kev_import i WHERE i.cve_id = k.cve_id)
	`); err != nil {
		return fmt.Errorf("delete delisted KEV entries: %w", err)
	}
	return tx.Commit(ctx)
}

func (s *Syncer) syncEPSS(ctx context.Context) (int, error) {
	body, err := s.download(ctx, SourceEPSS)
	if err != nil {
		return 0, err
	}
	defer body.Close()
	gz, err := gzip.NewReader(body)
	if err != nil {
		return 0, fmt.Errorf("open EPSS gzip: %w", err)
	}
	defer gz.Close()
	er, err := NewEPSSReader(io.LimitReader(gz, maxEPSSBytes))
	if err != nil {
		return 0, err
	}
	return StoreEPSS(ctx, s.db, er, minEPSSRows)
}

// StoreEPSS replaces all stored scores with the rows of er in one transaction.
// If the file has fewer than minRows rows or any row is malformed, nothing
// changes.
func StoreEPSS(ctx context.Context, db *pgxpool.Pool, er *EPSSReader, minRows int) (int, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	// TRUNCATE inside the transaction: readers keep seeing the old scores until
	// the commit (they wait for the brief lock rather than seeing an empty table).
	if _, err := tx.Exec(ctx, `TRUNCATE epss_scores`); err != nil {
		return 0, err
	}
	scoreDate := er.ScoreDate.UTC().Truncate(24 * time.Hour)
	n, err := tx.CopyFrom(ctx, pgx.Identifier{"epss_scores"},
		[]string{"cve_id", "epss", "percentile", "score_date"},
		pgx.CopyFromFunc(func() ([]any, error) {
			row, err := er.Next()
			if errors.Is(err, io.EOF) {
				return nil, nil
			}
			if err != nil {
				return nil, err
			}
			return []any{row.CVEID, row.EPSS, row.Percentile, scoreDate}, nil
		}))
	if err != nil {
		return 0, fmt.Errorf("copy EPSS scores: %w", err)
	}
	if int(n) < minRows {
		return 0, fmt.Errorf("EPSS file has only %d rows; refusing to replace the stored scores", n)
	}
	return int(n), tx.Commit(ctx)
}

// setStatus records the feed's state. last_sync_at only moves on success, so
// it always means "data current as of".
func (s *Syncer) setStatus(ctx context.Context, src Source, status, errMsg string, records int) {
	_, err := s.db.Exec(ctx, `
		INSERT INTO sync_status (source_type, source_name, status, error_message, records_processed, last_sync_at, updated_at)
		VALUES ($1, $1, $2::varchar, NULLIF($3, ''), $4, CASE WHEN $2::varchar = 'success' THEN NOW() END, NOW())
		ON CONFLICT (source_type, source_name) DO UPDATE SET
			status = EXCLUDED.status,
			error_message = EXCLUDED.error_message,
			records_processed = CASE WHEN EXCLUDED.status = 'success' THEN EXCLUDED.records_processed ELSE sync_status.records_processed END,
			last_sync_at = COALESCE(EXCLUDED.last_sync_at, sync_status.last_sync_at),
			updated_at = NOW()
	`, string(src), status, errMsg, records)
	if err != nil {
		log.Error().Err(err).Str("source", string(src)).Msg("Update threat intel sync status")
	}
}
