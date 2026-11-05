package preconditions

// The analyzer against a fake Anthropic API: candidates from the triage
// queue, synchronous and batch analyses, cost accounting, budget and daily
// limit, and the decisions AI-PRE derives from them.
//
// Requires a throwaway PostgreSQL; see internal/testdb for the setup command.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/vultrack/vultrack/internal/ai"
	"github.com/vultrack/vultrack/internal/autoassess"
	"github.com/vultrack/vultrack/internal/services"
	"github.com/vultrack/vultrack/internal/testdb"
)

// fakeAPI answers like the Messages and Message Batches APIs. Every analysis
// says: the CVE needs a non-loopback listener of nginx-core.
type fakeAPI struct {
	mu       sync.Mutex
	calls    int
	batched  []string // custom ids submitted
	batchEnd bool
}

func analysisJSON() string {
	r := ai.PreconditionResult{Determinable: true, Reasoning: "network service", RecommendedStatusIfReachable: "relevant",
		Paths: []ai.AttackPath{{Requires: []ai.Condition{{Type: ai.CondNetworkListener, Package: "nginx-core",
			Scope: "non_loopback", Necessary: true, Confidence: "high", Reason: "remote request"}}}}}
	b, _ := json.Marshal(r)
	return string(b)
}

func message() map[string]any {
	return map[string]any{
		"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-sonnet-5-5",
		"content":     []map[string]any{{"type": "text", "text": analysisJSON()}},
		"stop_reason": "end_turn",
		"usage":       map[string]any{"input_tokens": 1000, "output_tokens": 2000, "cache_read_input_tokens": 3000, "cache_creation_input_tokens": 0},
	}
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	batch := func(status string) map[string]any {
		return map[string]any{"id": "msgbatch_1", "type": "message_batch", "processing_status": status,
			"request_counts": map[string]int{"processing": 0, "succeeded": len(f.batched)},
			"created_at":     "2026-11-05T10:00:00Z", "expires_at": "2026-11-06T10:00:00Z"}
	}
	switch {
	case r.Method == "POST" && r.URL.Path == "/v1/messages":
		f.calls++
		json.NewEncoder(w).Encode(message())
	case r.Method == "POST" && r.URL.Path == "/v1/messages/batches":
		var body struct {
			Requests []struct {
				CustomID string `json:"custom_id"`
			} `json:"requests"`
		}
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &body)
		for _, rq := range body.Requests {
			f.batched = append(f.batched, rq.CustomID)
		}
		json.NewEncoder(w).Encode(batch("in_progress"))
	case r.Method == "GET" && r.URL.Path == "/v1/messages/batches/msgbatch_1":
		status := "in_progress"
		if f.batchEnd {
			status = "ended"
		}
		json.NewEncoder(w).Encode(batch(status))
	case r.Method == "GET" && r.URL.Path == "/v1/messages/batches/msgbatch_1/results":
		w.Header().Set("Content-Type", "application/x-jsonl")
		for _, id := range f.batched {
			line, _ := json.Marshal(map[string]any{"custom_id": id, "result": map[string]any{"type": "succeeded", "message": message()}})
			fmt.Fprintf(w, "%s\n", line)
		}
	default:
		http.Error(w, `{"type":"error","error":{"type":"not_found_error","message":"no"}}`, http.StatusNotFound)
	}
}

func TestAnalyzer(t *testing.T) {
	pool, ctx := testdb.Setup(t, "preconditions_tests")
	fake := &fakeAPI{}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	t.Setenv("ANTHROPIC_BASE_URL", srv.URL)

	settings := services.NewSettingsService(pool)
	findings := services.NewFindingService(pool)
	an := New(pool, settings, findings, ai.New("test-key", "", 30))
	eval := autoassess.New(pool, settings)
	var changes int
	an.AfterChange = func(string) { changes++ }

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	var srvID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO servers (name, os_family, os_release, os_codename, kernel, arch, package_manager)
		VALUES ('web', 'ubuntu', '24.04', 'noble', '6.8.0', 'amd64', 'dpkg') RETURNING id`).Scan(&srvID); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 4; i++ {
		cve := fmt.Sprintf("CVE-2026-000%d", i)
		exec(`INSERT INTO cve_catalog (cve_id, description, cvss3_score, cvss3_vector) VALUES ($1, 'Heap overflow in nginx request parsing', 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')`, cve)
		exec(`INSERT INTO findings (server_id, cve_id, package_name, package_version, fix_state, severity, source_type, cvss3_score, first_seen_at, last_seen_at)
		      VALUES ($1, $2, 'nginx-core', '1.24', 'affected', 'high', 'usn', 9.8, NOW(), NOW())`, srvID, cve)
	}
	// CVE-4 is already decided by a rule on its only server: no analysis needed.
	exec(`INSERT INTO auto_decisions (server_id, cve_id, rule_ids, reason) VALUES ($1, 'CVE-2026-0004', '{R-VEX}', 'vex')`, srvID)

	// Off: nothing happens.
	an.RunOnce(context.Background())
	if fake.calls != 0 || len(fake.batched) != 0 {
		t.Fatal("disabled analysis called the API")
	}

	// Synchronous, daily limit 2.
	if err := settings.SetMultiple(ctx, map[string]string{
		services.SettingPreEnabled: "true", services.SettingPreBatch: "false", services.SettingPreDaily: "2"}); err != nil {
		t.Fatal(err)
	}
	an.RunOnce(context.Background())
	st, err := an.GetStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if fake.calls != 2 || st.Analyses.OK != 2 || changes != 1 {
		t.Fatalf("sync run: %d calls, status %+v, changes %d", fake.calls, st.Analyses, changes)
	}
	// 1000 in + 2000 out + 3000 cache read on Sonnet 5.5: 0.002 + 0.02 + 0.0006
	if want := 2 * 0.0226; st.SpentMonth < want-1e-9 || st.SpentMonth > want+1e-9 {
		t.Errorf("spent %f, want %f", st.SpentMonth, want)
	}
	an.RunOnce(context.Background())
	if fake.calls != 2 {
		t.Error("the daily limit was exceeded")
	}

	// Batch: the remaining CVE (CVE-3; CVE-4 is decided), results later.
	exec(`UPDATE precondition_analyses SET requested_at = NOW() - interval '2 days'`)
	if err := settings.SetMultiple(ctx, map[string]string{services.SettingPreBatch: "true"}); err != nil {
		t.Fatal(err)
	}
	an.RunOnce(context.Background())
	if strings.Join(fake.batched, ",") != "CVE-2026-0003" {
		t.Fatalf("batched %v", fake.batched)
	}
	an.RunOnce(context.Background()) // batch still running
	if st, _ := an.GetStatus(ctx); st.Analyses.Pending != 1 || st.BatchesInProgress != 1 {
		t.Errorf("pending batch: %+v", st)
	}
	fake.batchEnd = true
	an.RunOnce(context.Background())
	st, _ = an.GetStatus(ctx)
	if st.Analyses.OK != 3 || st.Analyses.Pending != 0 || st.BatchesInProgress != 0 {
		t.Errorf("collected batch: %+v", st)
	}
	if want := 2*0.0226 + 0.0113; st.SpentMonth < want-1e-9 || st.SpentMonth > want+1e-9 {
		t.Errorf("spent %f, want %f (batch at half price)", st.SpentMonth, want)
	}

	// Budget reached: no new analyses even with a fresh day.
	exec(`UPDATE precondition_analyses SET requested_at = NOW() - interval '2 days', prompt_hash = 'old'`)
	if err := settings.SetMultiple(ctx, map[string]string{services.SettingPreBudget: "0.05"}); err != nil {
		t.Fatal(err)
	}
	before := len(fake.batched)
	an.RunOnce(context.Background())
	if len(fake.batched) != before {
		t.Error("submitted beyond the budget")
	}

	// AI-PRE: nginx listens publicly here, so the CVE stays open; on a host
	// where it only listens on loopback it is dismissed.
	listeners := func(addr string) {
		raw, _ := json.Marshal(map[string]any{"schemaVersion": 1,
			"listeners": []map[string]any{{"protocol": "tcp", "address": addr, "port": 443, "process": "nginx", "exe": "/usr/sbin/nginx", "package": "nginx-core", "hostNetns": true}},
			"services":  []map[string]any{}, "kernel": map[string]any{"release": "6.8.0", "loadedModules": []any{}}})
		if _, err := services.NewRuntimeFactsService(pool).Ingest(ctx, srvID, raw); err != nil {
			t.Fatal(err)
		}
		exec(`UPDATE server_facts SET stable_since = NOW() - interval '1 day' WHERE server_id = $1`, srvID)
	}
	decided := func() int {
		var n int
		pool.QueryRow(ctx, `SELECT COUNT(*) FROM auto_decisions WHERE source = 'ai'`).Scan(&n)
		return n
	}
	listeners("0.0.0.0")
	if _, err := eval.EvaluateServer(ctx, srvID); err != nil {
		t.Fatal(err)
	}
	if decided() != 0 {
		t.Error("a public listener must keep the CVEs open")
	}
	listeners("127.0.0.1")
	if _, err := eval.EvaluateServer(ctx, srvID); err != nil {
		t.Fatal(err)
	}
	if n := decided(); n != 3 {
		t.Errorf("AI-PRE decisions %d, want 3", n)
	}
	var reason string
	pool.QueryRow(ctx, `SELECT reason FROM auto_decisions WHERE cve_id = 'CVE-2026-0001'`).Scan(&reason)
	if !strings.Contains(reason, "no process of nginx-core listens on a non-loopback address") {
		t.Errorf("reason %q", reason)
	}
}
