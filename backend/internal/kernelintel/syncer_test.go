package kernelintel

// Requires a throwaway PostgreSQL; see internal/testdb for the setup command.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vultrack/vultrack/internal/services"
	"github.com/vultrack/vultrack/internal/testdb"
)

func TestSyncer(t *testing.T) {
	pool, ctx := testdb.Setup(t, "kernelintel_tests")
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	const release = "6.8.0-147-generic"
	var srv int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO servers (name, os_family, os_release, os_codename, kernel, arch, package_manager)
		VALUES ('k1', 'ubuntu', '24.04', 'noble', $1, 'amd64', 'dpkg') RETURNING id`, release).Scan(&srv); err != nil {
		t.Fatal(err)
	}
	for _, cve := range []string{"CVE-1", "CVE-2", "CVE-3"} {
		exec(`INSERT INTO findings (server_id, cve_id, package_name, package_version, fix_state, severity, source_type, first_seen_at, last_seen_at)
		      VALUES ($1, $2, 'kernel', '1', 'affected', 'high', 'oval', NOW(), NOW())`, srv, cve)
	}
	exec(`INSERT INTO server_packages (server_id, name, version, arch, source_package, first_seen_at, last_seen_at)
	      VALUES ($1, 'linux-modules-' || $2, '6.8.0-147.147', 'amd64', 'linux', NOW(), NOW())`, srv, release)
	raw, _ := json.Marshal(map[string]any{"schemaVersion": 1, "kernel": map[string]any{"release": release, "loadedModules": []any{}}})
	if _, err := services.NewRuntimeFactsService(pool).Ingest(ctx, srv, raw); err != nil {
		t.Fatal(err)
	}

	tree := map[string]string{}
	for p, c := range testTree {
		tree["./usr/src/linux-headers-6.8.0-147/"+p] = c
	}
	files := map[string][]byte{
		"/pkg/linux-headers-6.8.0-147-generic_6.8.0-147.147_amd64.deb": makeDeb(t, map[string]string{"./usr/src/linux-headers-6.8.0-147-generic/.config": testConfig}),
		"/pkg/linux-headers-6.8.0-147_6.8.0-147.147_all.deb":           makeDeb(t, tree),
		"/pkg/linux-modules-6.8.0-147-generic_6.8.0-147.147_amd64.deb": makeDeb(t, map[string]string{"./lib/modules/" + release + "/kernel/net/sctp/sctp.ko.zst": ""}),
		"/cve/CVE-1": []byte(`{"cveMetadata":{"assignerShortName":"Linux"},"containers":{"cna":{"affected":[{"product":"Linux","programFiles":["net/sctp/socket.c"]}]}}}`),
		"/cve/CVE-2": []byte(`{"cveMetadata":{"assignerShortName":"redhat"},"containers":{"cna":{"affected":[{"product":"kernel"}]}}}`),
	}
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b, ok := files[r.URL.Path]; ok {
			w.Write(b)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/cve/") {
			http.NotFound(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	defer hs.Close()

	settings := services.NewSettingsService(pool)
	s := NewSyncer(pool, settings, &Fetcher{HTTP: hs.Client(), CVEAPI: hs.URL + "/cve/",
		PackageURL: func(f string) string { return hs.URL + "/pkg/" + f }})
	s.CVERate = 0
	var changes []string
	s.AfterChange = func(r string) { changes = append(changes, r) }

	// Off: nothing is fetched.
	if err := settings.SetMultiple(ctx, map[string]string{services.SettingAutoMode: "off"}); err != nil {
		t.Fatal(err)
	}
	s.RunOnce(context.Background())
	st, err := s.GetStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.CVEs.Total != 0 || len(st.Builds) != 0 || st.CVEs.Pending != 3 {
		t.Fatalf("mode off must not fetch: %+v", st)
	}

	if err := settings.SetMultiple(ctx, map[string]string{services.SettingAutoMode: "shadow"}); err != nil {
		t.Fatal(err)
	}
	s.RunOnce(context.Background())
	st, err = s.GetStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.CVEs.Total != 3 || st.CVEs.WithData != 1 || st.CVEs.NoFiles != 2 || st.CVEs.Pending != 0 {
		t.Errorf("CVE status %+v", st.CVEs)
	}
	if len(st.Builds) != 1 || st.Builds[0].Status != "ok" || !st.Builds[0].ModulesVerified || st.Builds[0].Servers != 1 {
		t.Fatalf("builds %+v", st.Builds)
	}
	var targets []Target
	if err := pool.QueryRow(ctx, `SELECT targets FROM kernel_source_files WHERE path = 'net/sctp/socket.c'`).Scan(&targets); err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].Module != "kernel/net/sctp/sctp.ko" || !targets[0].Shipped {
		t.Errorf("targets %+v", targets)
	}
	if len(changes) != 1 {
		t.Errorf("AfterChange calls %v", changes)
	}

	// Nothing new: no downloads, no re-evaluation.
	s.RunOnce(context.Background())
	if len(changes) != 1 {
		t.Errorf("an idle sync triggered a re-evaluation: %v", changes)
	}
}
