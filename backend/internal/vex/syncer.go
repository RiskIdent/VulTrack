package vex

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/ulikunitz/xz"
	"github.com/vultrack/vultrack/internal/services"
)

const (
	defaultDownloadURL    = "https://security-metadata.canonical.com/vex/vex-all.tar.xz"
	defaultSyncIntervalH  = 24
	settingKeyURL         = "vex_download_url"
	settingKeyIntervalH   = "vex_sync_interval_hours"
	workerCount           = 8
	insertBatchSize       = 2000
)

// Syncer manages periodic download and import of Ubuntu VEX data.
type Syncer struct {
	vexService      *services.VEXService
	settingsService *services.SettingsService
	httpClient      *http.Client

	running bool
	mu      sync.Mutex
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// New creates a new VEX Syncer.
func New(vexService *services.VEXService, settingsService *services.SettingsService) *Syncer {
	return &Syncer{
		vexService:      vexService,
		settingsService: settingsService,
		httpClient: &http.Client{
			Timeout: 30 * time.Minute, // large archive download
		},
		stopCh: make(chan struct{}),
	}
}

// Start launches the background sync scheduler.
func (s *Syncer) Start() {
	s.wg.Add(1)
	go s.scheduleLoop()
	log.Info().Msg("VEX syncer started")
}

// Stop signals the syncer to stop and waits for it.
func (s *Syncer) Stop() {
	close(s.stopCh)
	s.wg.Wait()
	log.Info().Msg("VEX syncer stopped")
}

// IsSyncing returns true if a sync is currently running.
func (s *Syncer) IsSyncing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// TriggerSync starts an asynchronous sync and returns immediately.
func (s *Syncer) TriggerSync(ctx context.Context) error {
	go func() {
		if err := s.Sync(context.Background()); err != nil {
			log.Error().Err(err).Msg("Manual VEX sync failed")
		}
	}()
	return nil
}

// scheduleLoop periodically triggers a sync based on the configured interval.
func (s *Syncer) scheduleLoop() {
	defer s.wg.Done()

	// Start 3 minutes after boot to avoid thundering-herd with other syncers.
	timer := time.NewTimer(3 * time.Minute)
	defer timer.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-timer.C:
			s.syncIfNeeded()
			timer.Reset(s.getSyncInterval())
		}
	}
}

func (s *Syncer) getSyncInterval() time.Duration {
	ctx := context.Background()
	settings, err := s.settingsService.GetAll(ctx)
	if err != nil {
		return defaultSyncIntervalH * time.Hour
	}
	for _, setting := range settings {
		if setting.Key == settingKeyIntervalH {
			var hours int
			if _, err := fmt.Sscanf(setting.Value, "%d", &hours); err == nil && hours > 0 {
				return time.Duration(hours) * time.Hour
			}
		}
	}
	return defaultSyncIntervalH * time.Hour
}

func (s *Syncer) getDownloadURL(ctx context.Context) string {
	settings, err := s.settingsService.GetAll(ctx)
	if err != nil {
		return defaultDownloadURL
	}
	for _, setting := range settings {
		if setting.Key == settingKeyURL && setting.Value != "" {
			return setting.Value
		}
	}
	return defaultDownloadURL
}

func (s *Syncer) syncIfNeeded() {
	ctx := context.Background()
	interval := s.getSyncInterval()

	lastSync, err := s.vexService.GetLastSyncTime(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get VEX last sync time")
		return
	}
	if lastSync != nil && time.Since(*lastSync) < interval {
		log.Debug().Time("lastSync", *lastSync).Dur("interval", interval).Msg("VEX sync not needed yet")
		return
	}

	go func() {
		if err := s.Sync(context.Background()); err != nil {
			log.Error().Err(err).Msg("VEX sync failed")
		}
	}()
}

// Sync downloads, parses and imports the full VEX dataset.
func (s *Syncer) Sync(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("VEX sync already running")
	}
	s.running = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()

	startTime := time.Now()
	log.Info().Msg("Starting VEX sync")
	s.vexService.UpdateSyncStatus(ctx, "syncing", "", 0)

	// Determine the next generation number.
	currentGen, err := s.vexService.GetCurrentGeneration(ctx)
	if err != nil {
		s.vexService.UpdateSyncStatus(ctx, "failed", err.Error(), 0)
		return fmt.Errorf("failed to get current VEX generation: %w", err)
	}
	nextGen := currentGen + 1

	downloadURL := s.getDownloadURL(ctx)

	// Stream the archive: HTTP → xz → tar → per-file parse → batch insert.
	count, err := s.streamAndImport(ctx, downloadURL, nextGen)
	if err != nil {
		s.vexService.UpdateSyncStatus(ctx, "failed", err.Error(), count)
		return fmt.Errorf("VEX import failed: %w", err)
	}

	// Atomically remove the old generation.
	deleted, err := s.vexService.DeleteOldGenerations(ctx, nextGen)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to delete old VEX generations")
	}

	s.vexService.UpdateSyncStatus(ctx, "success", "", count)

	log.Info().
		Int("imported", count).
		Int64("deleted", deleted).
		Int("generation", nextGen).
		Dur("duration", time.Since(startTime)).
		Msg("VEX sync completed")

	return nil
}

// streamAndImport downloads the .tar.xz to a tempfile and then parses it
// locally. We used to stream HTTP → xz → tar → parser → DB in one pipeline,
// but that couples the HTTP body's read rate to the database insert rate.
// Under load (many concurrent scans hammering the same DB), inserts queue up,
// the tar reader stalls waiting for backpressure to clear, and the upstream
// server's idle timeout kills the connection — surfacing as a confusing
// "tar read error: unexpected EOF" partway through. Buffering to disk first
// decouples the two phases so DB load can never break the download.
func (s *Syncer) streamAndImport(ctx context.Context, url string, generation int) (int, error) {
	archive, err := s.downloadArchive(ctx, url)
	if err != nil {
		return 0, err
	}
	defer func() {
		path := archive.Name()
		archive.Close()
		if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
			log.Warn().Err(rmErr).Str("path", path).Msg("Failed to remove VEX tempfile")
		}
	}()

	return s.importArchive(ctx, archive, generation)
}

// downloadArchive fetches url to a tempfile, verifies the byte count against
// Content-Length when the server provides one, and rewinds the file for reading.
// A truncated transfer fails fast here rather than later during tar parsing.
func (s *Syncer) downloadArchive(ctx context.Context, url string) (*os.File, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "VulTrack/1.0")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	tmp, err := os.CreateTemp("", "vultrack-vex-*.tar.xz")
	if err != nil {
		return nil, fmt.Errorf("create tempfile: %w", err)
	}
	cleanup := func() {
		path := tmp.Name()
		tmp.Close()
		os.Remove(path)
	}

	log.Info().
		Str("url", url).
		Str("path", tmp.Name()).
		Int64("expectedBytes", resp.ContentLength).
		Msg("Downloading VEX archive to tempfile")

	startTime := time.Now()
	n, err := io.Copy(tmp, resp.Body)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("download to tempfile: %w", err)
	}

	if resp.ContentLength > 0 && n != resp.ContentLength {
		cleanup()
		return nil, fmt.Errorf("truncated download: got %d bytes, expected %d", n, resp.ContentLength)
	}

	log.Info().
		Int64("bytes", n).
		Dur("duration", time.Since(startTime)).
		Msg("VEX archive downloaded")

	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return nil, fmt.Errorf("rewind tempfile: %w", err)
	}

	return tmp, nil
}

// importArchive reads a local .tar.xz, parses each VEX JSON file in parallel,
// and bulk-inserts rows into vex_statements with the given generation. This
// phase can take arbitrarily long under DB load without any external risk.
func (s *Syncer) importArchive(ctx context.Context, src io.Reader, generation int) (int, error) {
	xzReader, err := xz.NewReader(src)
	if err != nil {
		return 0, fmt.Errorf("xz decompress init failed: %w", err)
	}

	tarReader := tar.NewReader(xzReader)

	// Fan-out: file contents → worker pool → parsed rows → batch inserter
	type fileEntry struct {
		name string
		data []byte
	}

	fileCh := make(chan fileEntry, workerCount*2)
	rowCh := make(chan Row, insertBatchSize*2)

	// Workers: parse JSON files in parallel.
	var parseWg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		parseWg.Add(1)
		go func() {
			defer parseWg.Done()
			for entry := range fileCh {
				sourceType := sourceTypeFromPath(entry.name)
				// Derive a stable source ID from the filename (e.g. "CVE-2024-0046" or "USN-1234-1").
				sourceName := strings.TrimSuffix(filepath.Base(entry.name), ".json")
				rows, err := ParseFile(entry.data, sourceType, sourceName)
				if err != nil {
					log.Warn().Err(err).Str("file", entry.name).Msg("Failed to parse VEX file")
					continue
				}
				for _, r := range rows {
					rowCh <- r
				}
			}
		}()
	}

	// Close rowCh after all workers are done.
	go func() {
		parseWg.Wait()
		close(rowCh)
	}()

	// Batch inserter goroutine.
	var totalCount int
	var insertErr error
	insertDone := make(chan struct{})
	go func() {
		defer close(insertDone)
		batch := make([]services.VEXRow, 0, insertBatchSize)
		for row := range rowCh {
			batch = append(batch, services.VEXRow{
				CVEID:         row.CVEID,
				PackageName:   row.PackageName,
				Distro:        row.Distro,
				Status:        row.Status,
				Justification: row.Justification,
				SourceType:    row.SourceType,
				SourceID:      row.SourceID,
			})
			if len(batch) >= insertBatchSize {
				deduped := dedupBatch(batch)
				n, err := s.vexService.BulkInsert(ctx, deduped, generation)
				totalCount += n
				if err != nil {
					log.Warn().Err(err).Msg("VEX batch insert error")
					insertErr = err
				}
				batch = batch[:0]
			}
		}
		// Flush remainder.
		if len(batch) > 0 {
			deduped := dedupBatch(batch)
			n, err := s.vexService.BulkInsert(ctx, deduped, generation)
			totalCount += n
			if err != nil {
				log.Warn().Err(err).Msg("VEX final batch insert error")
				insertErr = err
			}
		}
	}()

	// Read tar entries and dispatch to workers.
	fileCount := 0
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			close(fileCh)
			return totalCount, fmt.Errorf("tar read error: %w", err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		if !strings.HasSuffix(header.Name, ".json") {
			continue
		}

		data, err := io.ReadAll(io.LimitReader(tarReader, 10*1024*1024))
		if err != nil {
			// The tar reader is stateful: once a body read fails, no further
			// headers can be read cleanly. Bail out instead of silently
			// skipping — continuing here used to mask truncated streams as a
			// single warning followed by an EOF in the next Next() call.
			close(fileCh)
			return totalCount, fmt.Errorf("read tar entry %q: %w", header.Name, err)
		}

		fileCh <- fileEntry{name: header.Name, data: data}
		fileCount++

		if fileCount%5000 == 0 {
			log.Info().Int("files", fileCount).Int("rows", totalCount).Msg("VEX import progress")
		}
	}

	close(fileCh)
	<-insertDone

	log.Info().Int("files", fileCount).Msg("VEX archive fully processed")

	if insertErr != nil {
		return totalCount, insertErr
	}
	return totalCount, nil
}

// dedupBatch removes duplicate rows within a batch that share the same
// (CVEID, PackageName, Distro, SourceType) unique key, keeping the last
// occurrence. PostgreSQL rejects a single INSERT ... ON CONFLICT DO UPDATE
// that would update the same row more than once.
func dedupBatch(batch []services.VEXRow) []services.VEXRow {
	seen := make(map[string]int, len(batch))
	for i, r := range batch {
		key := r.CVEID + "|" + r.PackageName + "|" + r.Distro + "|" + r.SourceType
		seen[key] = i
	}
	if len(seen) == len(batch) {
		return batch // no duplicates
	}
	out := make([]services.VEXRow, 0, len(seen))
	// Preserve order: re-iterate and keep only the last-indexed entry.
	added := make(map[string]bool, len(seen))
	for i := len(batch) - 1; i >= 0; i-- {
		key := batch[i].CVEID + "|" + batch[i].PackageName + "|" + batch[i].Distro + "|" + batch[i].SourceType
		if !added[key] {
			added[key] = true
			out = append(out, batch[i])
		}
	}
	// Reverse to maintain original order.
	for l, r := 0, len(out)-1; l < r; l, r = l+1, r-1 {
		out[l], out[r] = out[r], out[l]
	}
	return out
}

// sourceTypeFromPath infers "cve" or "usn" from the archive entry path.
// Expected paths: vex/cve/2024/CVE-2024-0046.json  or  vex/usn/USN-1234-1.json
func sourceTypeFromPath(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i, p := range parts {
		if p == "cve" && i+1 < len(parts) {
			return "cve"
		}
		if p == "usn" {
			return "usn"
		}
	}
	return "cve"
}
