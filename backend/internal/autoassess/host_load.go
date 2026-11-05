package autoassess

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/vultrack/vultrack/internal/services"
)

// moduleIndexCache keeps module indexes in memory; they are content-addressed
// (release + hash), so an entry never goes stale.
type moduleIndexCache struct {
	mu      sync.Mutex
	entries map[string]*moduleIndex
}

type moduleIndex struct {
	available, builtin map[string]bool
}

func (c *moduleIndexCache) get(ctx context.Context, tx pgx.Tx, release, hash string) (*moduleIndex, error) {
	key := release + "\x00" + hash
	c.mu.Lock()
	if mi, ok := c.entries[key]; ok {
		c.mu.Unlock()
		return mi, nil
	}
	c.mu.Unlock()

	var available, builtin []string
	err := tx.QueryRow(ctx, `
		SELECT available, builtin FROM kernel_module_index WHERE kernel_release = $1 AND hash = $2
	`, release, hash).Scan(&available, &builtin)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	mi := &moduleIndex{available: make(map[string]bool, len(available)), builtin: make(map[string]bool, len(builtin))}
	for _, p := range available {
		mi.available[ModulePath(p)] = true
	}
	for _, p := range builtin {
		mi.builtin[ModulePath(p)] = true
	}
	c.mu.Lock()
	if c.entries == nil || len(c.entries) >= 32 {
		c.entries = map[string]*moduleIndex{}
	}
	c.entries[key] = mi
	c.mu.Unlock()
	return mi, nil
}

// kernelFacts is the part of the agent's kernel facts the rules read.
type kernelFacts struct {
	Release         string `json:"release"`
	ModulesDisabled *bool  `json:"modulesDisabled"`
	LoadedModules   *[]struct {
		Name string `json:"name"`
		Path string `json:"path"`
	} `json:"loadedModules"`
	BlacklistedModules []struct {
		Name           string `json:"name"`
		InstallCommand string `json:"installCommand"`
	} `json:"blacklistedModules"`
	ModuleIndex struct {
		Hash string `json:"hash"`
	} `json:"moduleIndex"`
}

// blockingInstallCommands are modprobe install commands that never load the
// module.
var blockingInstallCommands = map[string]bool{
	"/bin/false": true, "/bin/true": true, "/usr/bin/false": true, "/usr/bin/true": true,
}

// loadHost reads the host context the enabled rules need: the running kernel
// for R-KMOD, the packages and their usage for R-UNUSED. Parts no enabled rule
// needs, or that are unknown, stay nil.
func (e *Evaluator) loadHost(ctx context.Context, tx pgx.Tx, serverID int64, findings []Finding, rules []Rule, unusedWindow time.Duration) (*Host, error) {
	h := &Host{FactHashes: map[string]string{}, FactsAge: map[string]time.Duration{}}
	if _, err := loadKernelHost(ctx, e, tx, serverID, findings, rules, h); err != nil {
		return nil, err
	}
	for _, r := range rules {
		if r.ID() == "R-UNUSED" {
			if err := loadPackageHost(ctx, tx, serverID, h, unusedWindow); err != nil {
				return nil, err
			}
		}
	}
	return h, nil
}

// loadPackageHost reads packageInfo and the usage observation. A truncated
// or unreadable packageInfo leaves Packages nil.
func loadPackageHost(ctx context.Context, tx pgx.Tx, serverID int64, h *Host, window time.Duration) error {
	var (
		hash       string
		truncated  bool
		ageSeconds float64
		data       []byte
	)
	err := tx.QueryRow(ctx, `
		SELECT sf.hash, sf.truncated, EXTRACT(EPOCH FROM NOW() - sf.stable_since)::float8, snap.data
		FROM server_facts sf JOIN fact_snapshots snap ON snap.hash = sf.hash
		WHERE sf.server_id = $1 AND sf.category = 'packageInfo'
	`, serverID).Scan(&hash, &truncated, &ageSeconds, &data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var entries []PackageInfo
	if truncated || json.Unmarshal(data, &entries) != nil {
		return nil
	}
	usage, err := services.GetPackageUsage(ctx, tx, serverID)
	if err != nil {
		return err
	}
	p := NewPackageHost(entries)
	p.ObservedFor, p.LastInUse, p.Window = usage.ObservedFor, usage.LastInUse, window
	h.Packages = p
	h.FactHashes["packageInfo"] = hash
	h.FactsAge["packageInfo"] = time.Duration(ageSeconds * float64(time.Second))
	return nil
}

// loadKernelHost fills h.Kernel when R-KMOD is enabled and the server has
// kernel findings.
func loadKernelHost(ctx context.Context, e *Evaluator, tx pgx.Tx, serverID int64, findings []Finding, rules []Rule, h *Host) (*Host, error) {
	needKernel := false
	for _, r := range rules {
		if r.ID() == "R-KMOD" {
			needKernel = true
		}
	}
	var kernelCVEs []string
	if needKernel {
		for _, f := range findings {
			if f.Package == "kernel" {
				kernelCVEs = append(kernelCVEs, f.CVEID)
			}
		}
	}
	if len(kernelCVEs) == 0 {
		return h, nil
	}

	var (
		hash, scanKernel, arch string
		truncated              bool
		ageSeconds             float64
		data                   []byte
	)
	err := tx.QueryRow(ctx, `
		SELECT sf.hash, sf.truncated, EXTRACT(EPOCH FROM NOW() - sf.stable_since)::float8, snap.data, COALESCE(srv.kernel, ''), COALESCE(srv.arch, '')
		FROM servers srv
		JOIN server_facts sf ON sf.server_id = srv.id AND sf.category = 'kernel'
		JOIN fact_snapshots snap ON snap.hash = sf.hash
		WHERE srv.id = $1
	`, serverID).Scan(&hash, &truncated, &ageSeconds, &data, &scanKernel, &arch)
	if errors.Is(err, pgx.ErrNoRows) {
		return h, nil // kernel facts unknown
	}
	if err != nil {
		return nil, err
	}
	var kf kernelFacts
	if err := json.Unmarshal(data, &kf); err != nil || kf.LoadedModules == nil {
		return h, nil // unreadable, or loaded modules not collected
	}
	h.FactHashes["kernel"] = hash
	h.FactsAge["kernel"] = time.Duration(ageSeconds * float64(time.Second))

	k := &KernelHost{
		Release: kf.Release, ScanKernel: scanKernel, Truncated: truncated,
		ModulesDisabled: kf.ModulesDisabled != nil && *kf.ModulesDisabled,
		Loaded:          map[string]bool{}, InstallBlocked: map[string]string{},
		CVEs: map[string]KernelCVE{},
	}
	h.Kernel = k
	for _, m := range *kf.LoadedModules {
		k.Loaded[ModuleName(m.Name)] = true
		if m.Path != "" {
			k.Loaded[ModulePath(m.Path)] = true
		}
	}
	for _, b := range kf.BlacklistedModules {
		if blockingInstallCommands[b.InstallCommand] {
			k.InstallBlocked[ModuleName(b.Name)] = b.InstallCommand
		}
	}
	if kf.Release == "" || kf.Release != scanKernel {
		return h, nil
	}

	if kf.ModuleIndex.Hash != "" {
		mi, err := e.modIndex.get(ctx, tx, kf.Release, kf.ModuleIndex.Hash)
		if err != nil {
			return nil, err
		}
		if mi != nil {
			k.IndexKnown, k.Available, k.Builtin = true, mi.available, mi.builtin
		}
	}

	var buildID int64
	var b KernelBuild
	err = tx.QueryRow(ctx, `
		SELECT kb.id, kb.version, kb.modules_verified
		FROM kernel_builds kb
		JOIN server_packages sp ON sp.server_id = $1 AND sp.removed_at IS NULL
		     AND sp.name = 'linux-modules-' || kb.release AND sp.version = kb.version
		WHERE kb.release = $2 AND kb.arch = $3 AND kb.status = 'ok'
		LIMIT 1
	`, serverID, kf.Release, arch).Scan(&buildID, &b.Version, &b.ModulesVerified)
	if errors.Is(err, pgx.ErrNoRows) {
		return h, nil // build not mapped (yet)
	}
	if err != nil {
		return nil, err
	}
	k.Build = &b

	rows, err := tx.Query(ctx, `
		SELECT k.cve_id, k.program_files,
		       (SELECT jsonb_object_agg(s.path, s.targets) FROM kernel_source_files s
		        WHERE s.build_id = $2 AND s.path = ANY(k.program_files))
		FROM kernel_cve_files k
		WHERE k.cve_id = ANY($1) AND k.status = 'ok'
	`, kernelCVEs, buildID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var c KernelCVE
		var targets []byte
		if err := rows.Scan(&id, &c.Files, &targets); err != nil {
			return nil, err
		}
		if targets != nil {
			if err := json.Unmarshal(targets, &c.Targets); err != nil {
				return nil, err
			}
		}
		k.CVEs[id] = c
	}
	return h, rows.Err()
}
