package services_test

// Runtime facts: change detection per category, unknown vs empty, the kernel
// module index, and snapshot cleanup.
//
// Requires a throwaway PostgreSQL; see internal/testdb for the setup command.

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vultrack/vultrack/internal/services"
	"github.com/vultrack/vultrack/internal/testdb"
)

func TestRuntimeFacts(t *testing.T) {
	pool, ctx := testdb.Setup(t, "runtime_facts_tests")
	rf := services.NewRuntimeFactsService(pool)

	var serverID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO servers (name, os_family, os_release, os_codename, kernel, arch, package_manager)
		VALUES ('rt-test', 'ubuntu', '24.04', 'noble', '6.8.0-124-generic', 'amd64', 'dpkg') RETURNING id
	`).Scan(&serverID); err != nil {
		t.Fatal(err)
	}

	release := "6.8.0-124-generic"
	available := []string{"kernel/drivers/net/wireless/ath/ath9k/ath9k.ko.zst", "kernel/fs/cramfs/cramfs.ko.zst"}
	builtin := []string{"kernel/fs/ext4/ext4.ko"}
	indexHash := services.ModuleIndexHash(release, available, builtin)

	kernel := func(withIndex bool, hash string) string {
		idx := fmt.Sprintf(`{"hash": %q}`, hash)
		if withIndex {
			a, _ := json.Marshal(available)
			b, _ := json.Marshal(builtin)
			idx = fmt.Sprintf(`{"hash": %q, "available": %s, "builtin": %s}`, hash, a, b)
		}
		return fmt.Sprintf(`{"release": %q, "modulesDisabled": false,
			"loadedModules": [{"name": "ext4"}], "moduleIndex": %s}`, release, idx)
	}
	report := func(parts ...string) json.RawMessage {
		return json.RawMessage(`{"schemaVersion": 1, "collectedAt": "2026-11-05T10:00:00Z", ` + strings.Join(parts, ", ") + `}`)
	}
	listeners := `"listeners": [{"protocol": "tcp", "address": "0.0.0.0", "port": 22, "process": "sshd", "package": "openssh-server"}]`
	inUse := `"packagesInUse": [{"package": "libssl3t64", "processes": ["sshd"]}]`
	count := func(q string) int {
		var n int
		if err := pool.QueryRow(ctx, q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	stableSince := func(cat string) time.Time {
		var ts time.Time
		if err := pool.QueryRow(ctx, `SELECT stable_since FROM server_facts WHERE server_id = $1 AND category = $2`, serverID, cat).Scan(&ts); err != nil {
			t.Fatal(err)
		}
		return ts
	}

	res, err := rf.Ingest(ctx, serverID, report(`"kernel": `+kernel(true, indexHash), listeners, inUse))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Changed, ",") != "kernel,listeners,packagesInUse" || !res.IndexNew {
		t.Fatalf("first report = %+v", res)
	}
	rt, err := rf.Get(ctx, serverID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rt.Categories) != 3 || strings.Join(rt.Unknown, ",") != "services,virtualization,packageInfo" {
		t.Errorf("categories %d, unknown %v", len(rt.Categories), rt.Unknown)
	}
	if rt.ModuleIndex == nil || !rt.ModuleIndex.Known || rt.ModuleIndex.Available != 2 || rt.ModuleIndex.Builtin != 1 {
		t.Errorf("module index = %+v", rt.ModuleIndex)
	}
	if strings.Contains(string(rt.Categories[0].Data), "cramfs") {
		t.Error("the module index lists must not be stored in the kernel facts")
	}
	firstListeners := stableSince("listeners")

	t.Run("an identical report changes nothing; the index may be omitted; key order is irrelevant", func(t *testing.T) {
		snaps := count(`SELECT COUNT(*) FROM fact_snapshots`)
		reordered := `"listeners": [{"port": 22, "address": "0.0.0.0", "protocol": "tcp", "package": "openssh-server", "process": "sshd"}]`
		res, err := rf.Ingest(ctx, serverID, report(`"kernel": `+kernel(false, indexHash), reordered, inUse))
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Changed) != 0 || len(res.Unchanged) != 3 || res.IndexNew {
			t.Errorf("result = %+v", res)
		}
		if count(`SELECT COUNT(*) FROM fact_snapshots`) != snaps || !stableSince("listeners").Equal(firstListeners) {
			t.Error("an unchanged report must not write snapshots or move stable_since")
		}
	})

	t.Run("a change writes one snapshot and moves stable_since", func(t *testing.T) {
		time.Sleep(10 * time.Millisecond)
		changed := `"listeners": [{"protocol": "tcp", "address": "127.0.0.1", "port": 22, "process": "sshd", "package": "openssh-server"}]`
		res, err := rf.Ingest(ctx, serverID, report(`"kernel": `+kernel(false, indexHash), changed, inUse, `"truncated": ["packagesInUse"]`))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(res.Changed, ",") != "listeners" {
			t.Errorf("result = %+v", res)
		}
		if !stableSince("listeners").After(firstListeners) {
			t.Error("stable_since did not move")
		}
		rt, _ := rf.Get(ctx, serverID)
		for _, c := range rt.Categories {
			if c.Category == "packagesInUse" && !c.Truncated {
				t.Error("packagesInUse should be marked truncated")
			}
		}
	})

	t.Run("an omitted category becomes unknown; an empty list is a fact", func(t *testing.T) {
		res, err := rf.Ingest(ctx, serverID, report(`"kernel": `+kernel(false, indexHash), `"listeners": []`))
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(res.Removed, "packagesInUse") || !slices.Contains(res.Changed, "listeners") {
			t.Errorf("result = %+v", res)
		}
		rt, _ := rf.Get(ctx, serverID)
		if !slices.Contains(rt.Unknown, "packagesInUse") || slices.Contains(rt.Unknown, "listeners") {
			t.Errorf("unknown = %v", rt.Unknown)
		}
	})

	t.Run("a module index that does not match its hash is not stored", func(t *testing.T) {
		before := count(`SELECT COUNT(*) FROM kernel_module_index`)
		res, err := rf.Ingest(ctx, serverID, report(`"kernel": `+kernel(true, "sha256:forged"), `"listeners": []`))
		if err != nil {
			t.Fatal(err)
		}
		if res.IndexNew || count(`SELECT COUNT(*) FROM kernel_module_index`) != before {
			t.Error("forged index stored")
		}
		if !slices.Contains(res.Changed, "kernel") {
			t.Errorf("the kernel facts themselves are kept and now cite the other hash: %+v", res)
		}
	})

	t.Run("an unsupported schema or no runtime object makes everything unknown", func(t *testing.T) {
		res, err := rf.Ingest(ctx, serverID, json.RawMessage(`{"schemaVersion": 2, "listeners": []}`))
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Removed) != 2 || count(`SELECT COUNT(*) FROM server_facts`) != 0 {
			t.Errorf("result = %+v", res)
		}
		if _, err := rf.Ingest(ctx, serverID, report(listeners)); err != nil {
			t.Fatal(err)
		}
		if _, err := rf.Ingest(ctx, serverID, nil); err != nil {
			t.Fatal(err)
		}
		rt, _ := rf.Get(ctx, serverID)
		if len(rt.Categories) != 0 || rt.ReportedAt != nil {
			t.Errorf("runtime after an old-style report = %+v", rt)
		}
	})

	t.Run("cleanup removes old unreferenced snapshots only", func(t *testing.T) {
		if _, err := rf.Ingest(ctx, serverID, report(listeners)); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE fact_snapshots SET created_at = NOW() - interval '40 days'`); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE kernel_module_index SET received_at = NOW() - interval '40 days'`); err != nil {
			t.Fatal(err)
		}
		total := count(`SELECT COUNT(*) FROM fact_snapshots`)
		snaps, idx, err := rf.CleanupSnapshots(ctx, 30*24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if int(snaps) != total-1 || count(`SELECT COUNT(*) FROM fact_snapshots`) != 1 {
			t.Errorf("deleted %d of %d, %d left; only the current listeners snapshot should stay", snaps, total, count(`SELECT COUNT(*) FROM fact_snapshots`))
		}
		if idx != 1 {
			t.Errorf("module indexes deleted = %d, want 1 (no server runs that kernel any more)", idx)
		}
	})
}
