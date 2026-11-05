package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

// RuntimeFactsService stores the runtime facts agents report (loaded kernel
// modules, listening sockets, packages in use, services, virtualization) and
// serves them to rules and the UI. See docs/AGENT_RUNTIME_FACTS_PROMPT.md for
// the format and docs/AUTO_ASSESSMENT_PLAN.md §5–6 for the design.
type RuntimeFactsService struct {
	db *pgxpool.Pool
}

// NewRuntimeFactsService creates a RuntimeFactsService.
func NewRuntimeFactsService(db *pgxpool.Pool) *RuntimeFactsService {
	return &RuntimeFactsService{db: db}
}

// RuntimeSchemaVersion is the runtime object version this backend understands.
const RuntimeSchemaVersion = 1

// FactCategories are the fact categories, in display order.
var FactCategories = []string{"kernel", "listeners", "packagesInUse", "services", "virtualization"}

// maxRuntimeBytes bounds the runtime object accepted from one report (the agent
// keeps it below 1 MB; the module index is sent only when it changes).
const maxRuntimeBytes = 2 << 20

type runtimeReport struct {
	SchemaVersion int             `json:"schemaVersion"`
	CollectedAt   *time.Time      `json:"collectedAt"`
	Errors        json.RawMessage `json:"errors"`
	Truncated     []string        `json:"truncated"`

	Kernel         json.RawMessage `json:"kernel"`
	Listeners      json.RawMessage `json:"listeners"`
	PackagesInUse  json.RawMessage `json:"packagesInUse"`
	Services       json.RawMessage `json:"services"`
	Virtualization json.RawMessage `json:"virtualization"`
}

func (r runtimeReport) category(name string) json.RawMessage {
	switch name {
	case "kernel":
		return r.Kernel
	case "listeners":
		return r.Listeners
	case "packagesInUse":
		return r.PackagesInUse
	case "services":
		return r.Services
	case "virtualization":
		return r.Virtualization
	}
	return nil
}

// present reports whether a JSON value was sent (and is not null).
func present(v json.RawMessage) bool {
	s := strings.TrimSpace(string(v))
	return s != "" && s != "null"
}

// canonicalJSON re-encodes a JSON value with sorted object keys and no
// insignificant whitespace, so identical content always hashes the same.
func canonicalJSON(v json.RawMessage) ([]byte, error) {
	var x any
	if err := json.Unmarshal(v, &x); err != nil {
		return nil, err
	}
	return json.Marshal(x)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// IngestResult tells what a report changed.
type IngestResult struct {
	Changed   []string // categories whose content changed (or appeared)
	Unchanged []string
	Removed   []string // categories no longer reported (now unknown)
	IndexNew  bool     // a kernel module index was stored
}

// Ingest stores the runtime object of one report. A missing or unsupported
// runtime object makes every category unknown. Unchanged categories cost one
// UPDATE in total; only changed content is written as a new snapshot.
func (s *RuntimeFactsService) Ingest(ctx context.Context, serverID int64, raw json.RawMessage) (IngestResult, error) {
	var res IngestResult
	if !present(raw) {
		return s.forget(ctx, serverID, &res)
	}
	if len(raw) > maxRuntimeBytes {
		log.Warn().Int64("serverId", serverID).Int("bytes", len(raw)).Msg("Runtime facts too large; ignored")
		return s.forget(ctx, serverID, &res)
	}
	var rep runtimeReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		log.Warn().Err(err).Int64("serverId", serverID).Msg("Runtime facts not parseable; ignored")
		return s.forget(ctx, serverID, &res)
	}
	if rep.SchemaVersion != RuntimeSchemaVersion {
		log.Warn().Int64("serverId", serverID).Int("schemaVersion", rep.SchemaVersion).Msg("Unsupported runtime facts schema; ignored")
		return s.forget(ctx, serverID, &res)
	}

	// Canonical content and hash per reported category. The kernel module
	// index travels separately: it is stored per kernel release, and only its
	// hash stays in the kernel facts, so a resend of the index does not look
	// like a change of the server's kernel state.
	type fact struct {
		data []byte
		hash string
	}
	facts := map[string]fact{}
	var index *moduleIndexUpload
	for _, cat := range FactCategories {
		v := rep.category(cat)
		if !present(v) {
			continue
		}
		if cat == "kernel" {
			stripped, idx, err := splitModuleIndex(v)
			if err != nil {
				log.Warn().Err(err).Int64("serverId", serverID).Msg("Kernel facts not parseable; treated as unknown")
				continue
			}
			v, index = stripped, idx
		}
		data, err := canonicalJSON(v)
		if err != nil {
			log.Warn().Err(err).Int64("serverId", serverID).Str("category", cat).Msg("Fact category not parseable; treated as unknown")
			continue
		}
		facts[cat] = fact{data: data, hash: sha256Hex(data)}
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer tx.Rollback(ctx)

	have := map[string]string{}
	rows, err := tx.Query(ctx, `SELECT category, hash FROM server_facts WHERE server_id = $1`, serverID)
	if err != nil {
		return res, err
	}
	for rows.Next() {
		var c, h string
		if err := rows.Scan(&c, &h); err != nil {
			rows.Close()
			return res, err
		}
		have[c] = h
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return res, err
	}

	for _, cat := range FactCategories {
		f, reported := facts[cat]
		old, stored := have[cat]
		truncated := slices.Contains(rep.Truncated, cat)
		switch {
		case !reported && stored:
			res.Removed = append(res.Removed, cat)
			if _, err := tx.Exec(ctx, `DELETE FROM server_facts WHERE server_id = $1 AND category = $2`, serverID, cat); err != nil {
				return res, err
			}
		case !reported:
		case stored && old == f.hash:
			res.Unchanged = append(res.Unchanged, cat)
			if _, err := tx.Exec(ctx, `
				UPDATE server_facts SET reported_at = NOW(), truncated = $3 WHERE server_id = $1 AND category = $2
			`, serverID, cat, truncated); err != nil {
				return res, err
			}
		default:
			res.Changed = append(res.Changed, cat)
			if _, err := tx.Exec(ctx, `
				INSERT INTO fact_snapshots (hash, category, data) VALUES ($1, $2, $3) ON CONFLICT (hash) DO NOTHING
			`, f.hash, cat, f.data); err != nil {
				return res, err
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO server_facts (server_id, category, hash, truncated, stable_since, reported_at)
				VALUES ($1, $2, $3, $4, NOW(), NOW())
				ON CONFLICT (server_id, category) DO UPDATE SET
					hash = EXCLUDED.hash, truncated = EXCLUDED.truncated,
					stable_since = NOW(), reported_at = NOW()
			`, serverID, cat, f.hash, truncated); err != nil {
				return res, err
			}
		}
	}

	errs := []byte("[]")
	if present(rep.Errors) {
		if b, err := canonicalJSON(rep.Errors); err == nil {
			errs = b
		}
	}
	truncatedList := rep.Truncated
	if truncatedList == nil {
		truncatedList = []string{}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO server_runtime (server_id, schema_version, collected_at, errors, truncated, reported_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (server_id) DO UPDATE SET
			schema_version = EXCLUDED.schema_version, collected_at = EXCLUDED.collected_at,
			errors = EXCLUDED.errors, truncated = EXCLUDED.truncated, reported_at = NOW()
	`, serverID, rep.SchemaVersion, rep.CollectedAt, errs, truncatedList); err != nil {
		return res, err
	}

	if index != nil {
		tag, err := tx.Exec(ctx, `
			INSERT INTO kernel_module_index (kernel_release, hash, available, builtin)
			VALUES ($1, $2, $3, $4) ON CONFLICT (kernel_release, hash) DO NOTHING
		`, index.release, index.hash, index.available, index.builtin)
		if err != nil {
			return res, err
		}
		res.IndexNew = tag.RowsAffected() > 0
	}

	return res, tx.Commit(ctx)
}

// forget makes every fact category of the server unknown.
func (s *RuntimeFactsService) forget(ctx context.Context, serverID int64, res *IngestResult) (IngestResult, error) {
	rows, err := s.db.Query(ctx, `DELETE FROM server_facts WHERE server_id = $1 RETURNING category`, serverID)
	if err != nil {
		return *res, err
	}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			rows.Close()
			return *res, err
		}
		res.Removed = append(res.Removed, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return *res, err
	}
	_, err = s.db.Exec(ctx, `DELETE FROM server_runtime WHERE server_id = $1`, serverID)
	return *res, err
}

type moduleIndexUpload struct {
	release            string
	hash               string
	available, builtin []string
}

// splitModuleIndex removes moduleIndex.available/builtin from the kernel facts
// (keeping moduleIndex.hash) and returns them when they are present and match
// their hash. A mismatching index is dropped with a warning; the kernel facts
// themselves are kept.
func splitModuleIndex(kernel json.RawMessage) (json.RawMessage, *moduleIndexUpload, error) {
	var k map[string]json.RawMessage
	if err := json.Unmarshal(kernel, &k); err != nil {
		return nil, nil, err
	}
	rawIdx, ok := k["moduleIndex"]
	if !ok || !present(rawIdx) {
		return kernel, nil, nil
	}
	var idx struct {
		Hash      string    `json:"hash"`
		Available *[]string `json:"available"`
		Builtin   *[]string `json:"builtin"`
	}
	if err := json.Unmarshal(rawIdx, &idx); err != nil {
		return nil, nil, fmt.Errorf("moduleIndex: %w", err)
	}
	var release string
	_ = json.Unmarshal(k["release"], &release)

	hashOnly, _ := json.Marshal(map[string]string{"hash": idx.Hash})
	k["moduleIndex"] = hashOnly
	stripped, err := json.Marshal(k)
	if err != nil {
		return nil, nil, err
	}

	if idx.Available == nil || idx.Builtin == nil {
		return stripped, nil, nil
	}
	available := append([]string{}, *idx.Available...)
	builtin := append([]string{}, *idx.Builtin...)
	sort.Strings(available)
	sort.Strings(builtin)
	if want := ModuleIndexHash(release, available, builtin); release == "" || want != idx.Hash {
		log.Warn().Str("kernel", release).Str("sent", idx.Hash).Str("computed", want).
			Msg("Kernel module index does not match its hash; not stored")
		return stripped, nil, nil
	}
	return stripped, &moduleIndexUpload{release: release, hash: idx.Hash, available: available, builtin: builtin}, nil
}

// ModuleIndexHash computes the module index hash as the agent does:
// "sha256:" + hex(sha256(release + "\n" + sorted available joined by "\n" +
// "\n" + sorted builtin joined by "\n")).
func ModuleIndexHash(release string, available, builtin []string) string {
	sum := sha256.Sum256([]byte(release + "\n" + strings.Join(available, "\n") + "\n" + strings.Join(builtin, "\n")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// FactCategoryState is one stored category of a server.
type FactCategoryState struct {
	Category    string          `json:"category"`
	Hash        string          `json:"hash"`
	Truncated   bool            `json:"truncated"`
	StableSince time.Time       `json:"stableSince"`
	ReportedAt  time.Time       `json:"reportedAt"`
	Data        json.RawMessage `json:"data"`
}

// ServerRuntime is everything known about a server's runtime.
type ServerRuntime struct {
	SchemaVersion *int                `json:"schemaVersion,omitempty"`
	CollectedAt   *time.Time          `json:"collectedAt,omitempty"`
	ReportedAt    *time.Time          `json:"reportedAt,omitempty"`
	Errors        json.RawMessage     `json:"errors"`
	Truncated     []string            `json:"truncated"`
	Categories    []FactCategoryState `json:"categories"`
	ModuleIndex   *ModuleIndexSummary `json:"moduleIndex,omitempty"`
	Unknown       []string            `json:"unknown"` // categories without data
}

// ModuleIndexSummary describes the module index of the server's kernel.
type ModuleIndexSummary struct {
	KernelRelease string `json:"kernelRelease"`
	Hash          string `json:"hash"`
	Known         bool   `json:"known"` // the index itself has been received
	Available     int    `json:"available"`
	Builtin       int    `json:"builtin"`
}

// Get returns the stored runtime facts of a server.
func (s *RuntimeFactsService) Get(ctx context.Context, serverID int64) (*ServerRuntime, error) {
	rt := &ServerRuntime{Errors: json.RawMessage("[]"), Truncated: []string{}, Categories: []FactCategoryState{}, Unknown: []string{}}
	var errs []byte
	err := s.db.QueryRow(ctx, `
		SELECT schema_version, collected_at, reported_at, errors, truncated FROM server_runtime WHERE server_id = $1
	`, serverID).Scan(&rt.SchemaVersion, &rt.CollectedAt, &rt.ReportedAt, &errs, &rt.Truncated)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if len(errs) > 0 {
		rt.Errors = errs
	}

	rows, err := s.db.Query(ctx, `
		SELECT f.category, f.hash, f.truncated, f.stable_since, f.reported_at, s.data
		FROM server_facts f JOIN fact_snapshots s ON s.hash = f.hash
		WHERE f.server_id = $1
	`, serverID)
	if err != nil {
		return nil, err
	}
	byCat := map[string]FactCategoryState{}
	for rows.Next() {
		var c FactCategoryState
		if err := rows.Scan(&c.Category, &c.Hash, &c.Truncated, &c.StableSince, &c.ReportedAt, &c.Data); err != nil {
			rows.Close()
			return nil, err
		}
		byCat[c.Category] = c
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, cat := range FactCategories {
		if c, ok := byCat[cat]; ok {
			rt.Categories = append(rt.Categories, c)
		} else {
			rt.Unknown = append(rt.Unknown, cat)
		}
	}

	if k, ok := byCat["kernel"]; ok {
		var kd struct {
			Release     string `json:"release"`
			ModuleIndex struct {
				Hash string `json:"hash"`
			} `json:"moduleIndex"`
		}
		if json.Unmarshal(k.Data, &kd) == nil && kd.ModuleIndex.Hash != "" {
			mi := &ModuleIndexSummary{KernelRelease: kd.Release, Hash: kd.ModuleIndex.Hash}
			err := s.db.QueryRow(ctx, `
				SELECT cardinality(available), cardinality(builtin) FROM kernel_module_index
				WHERE kernel_release = $1 AND hash = $2
			`, kd.Release, kd.ModuleIndex.Hash).Scan(&mi.Available, &mi.Builtin)
			if err == nil {
				mi.Known = true
			} else if !errors.Is(err, pgx.ErrNoRows) {
				return nil, err
			}
			rt.ModuleIndex = mi
		}
	}
	return rt, nil
}

// CleanupSnapshots deletes snapshots and module indexes nothing refers to any
// more and that are older than retention: not a server's current facts, and
// not cited by an automated decision or the audit trail
// (evidence -> 'facts' -> category = hash).
func (s *RuntimeFactsService) CleanupSnapshots(ctx context.Context, retention time.Duration) (int64, int64, error) {
	cutoff := time.Now().Add(-retention)
	tag, err := s.db.Exec(ctx, `
		DELETE FROM fact_snapshots s
		WHERE s.created_at < $1
		  AND NOT EXISTS (SELECT 1 FROM server_facts f WHERE f.hash = s.hash)
		  AND NOT EXISTS (SELECT 1 FROM auto_decisions d WHERE d.evidence -> 'facts' ->> s.category = s.hash)
		  AND NOT EXISTS (SELECT 1 FROM decision_events e WHERE e.evidence -> 'facts' ->> s.category = s.hash)
	`, cutoff)
	if err != nil {
		return 0, 0, err
	}
	idx, err := s.db.Exec(ctx, `
		DELETE FROM kernel_module_index k
		WHERE k.received_at < $1
		  AND NOT EXISTS (
		      SELECT 1 FROM server_facts f JOIN fact_snapshots s ON s.hash = f.hash
		      WHERE f.category = 'kernel'
		        AND s.data ->> 'release' = k.kernel_release
		        AND s.data -> 'moduleIndex' ->> 'hash' = k.hash)
	`, cutoff)
	if err != nil {
		return tag.RowsAffected(), 0, err
	}
	return tag.RowsAffected(), idx.RowsAffected(), nil
}
