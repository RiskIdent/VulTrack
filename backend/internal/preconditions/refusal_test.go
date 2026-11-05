package preconditions

// Refusals: logged and stored, and analysed by the fallback model when one is
// configured, synchronously right away and in batch mode on the next run.
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
	"github.com/vultrack/vultrack/internal/services"
	"github.com/vultrack/vultrack/internal/testdb"
)

// refusingAPI: Sonnet declines CVE-2026-0001, every other call succeeds.
type refusingAPI struct {
	mu      sync.Mutex
	calls   []string // model:cve
	batches map[string][][2]string
	n       int
}

func (f *refusingAPI) answer(model, cve string) map[string]any {
	f.calls = append(f.calls, model+":"+cve)
	m := message()
	m["model"] = model
	if model == "claude-sonnet-5-5" && cve == "CVE-2026-0001" {
		m["stop_reason"] = "refusal"
		m["content"] = []any{}
		m["stop_details"] = map[string]any{"type": "refusal", "category": "cyber", "explanation": "declined"}
	}
	return m
}

func cveOf(text string) string {
	i := strings.Index(text, "CVE-")
	return strings.Fields(text[i:])[0]
}

func (f *refusingAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	type params struct {
		Model    string `json:"model"`
		Messages []struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"messages"`
	}
	b, _ := io.ReadAll(r.Body)
	switch {
	case r.Method == "POST" && r.URL.Path == "/v1/messages":
		var p params
		json.Unmarshal(b, &p)
		json.NewEncoder(w).Encode(f.answer(p.Model, cveOf(p.Messages[0].Content[0].Text)))
	case r.Method == "POST" && r.URL.Path == "/v1/messages/batches":
		var body struct {
			Requests []struct {
				CustomID string `json:"custom_id"`
				Params   params `json:"params"`
			} `json:"requests"`
		}
		json.Unmarshal(b, &body)
		f.n++
		id := fmt.Sprintf("msgbatch_%d", f.n)
		for _, rq := range body.Requests {
			f.batches[id] = append(f.batches[id], [2]string{rq.Params.Model, rq.CustomID})
		}
		json.NewEncoder(w).Encode(map[string]any{"id": id, "type": "message_batch", "processing_status": "in_progress",
			"request_counts": map[string]int{}, "created_at": "2026-11-05T10:00:00Z", "expires_at": "2026-11-06T10:00:00Z"})
	case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/results"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/messages/batches/"), "/results")
		w.Header().Set("Content-Type", "application/x-jsonl")
		for _, req := range f.batches[id] {
			line, _ := json.Marshal(map[string]any{"custom_id": req[1], "result": map[string]any{"type": "succeeded", "message": f.answer(req[0], req[1])}})
			fmt.Fprintf(w, "%s\n", line)
		}
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/messages/batches/"):
		id := strings.TrimPrefix(r.URL.Path, "/v1/messages/batches/")
		json.NewEncoder(w).Encode(map[string]any{"id": id, "type": "message_batch", "processing_status": "ended",
			"request_counts": map[string]int{}, "created_at": "2026-11-05T10:00:00Z", "expires_at": "2026-11-06T10:00:00Z"})
	default:
		http.Error(w, `{"type":"error","error":{"type":"not_found_error","message":"no"}}`, http.StatusNotFound)
	}
}

func TestRefusalFallback(t *testing.T) {
	for _, batch := range []bool{false, true} {
		t.Run(fmt.Sprintf("batch=%v", batch), func(t *testing.T) {
			pool, ctx := testdb.Setup(t, "precondition_refusal_tests")
			fake := &refusingAPI{batches: map[string][][2]string{}}
			srv := httptest.NewServer(fake)
			defer srv.Close()
			t.Setenv("ANTHROPIC_BASE_URL", srv.URL)
			settings := services.NewSettingsService(pool)
			an := New(pool, settings, services.NewFindingService(pool), ai.New("test-key", "", 30))

			var srvID int64
			if err := pool.QueryRow(ctx, `INSERT INTO servers (name, os_family, os_release, os_codename, kernel, arch, package_manager)
				VALUES ('web', 'ubuntu', '24.04', 'noble', '6.8.0', 'amd64', 'dpkg') RETURNING id`).Scan(&srvID); err != nil {
				t.Fatal(err)
			}
			for _, cve := range []string{"CVE-2026-0001", "CVE-2026-0002"} {
				if _, err := pool.Exec(ctx, `INSERT INTO cve_catalog (cve_id, description, cvss3_score) VALUES ($1, 'Some flaw', 9.0)`, cve); err != nil {
					t.Fatal(err)
				}
				if _, err := pool.Exec(ctx, `INSERT INTO findings (server_id, cve_id, package_name, package_version, fix_state, severity, source_type, cvss3_score, first_seen_at, last_seen_at)
					VALUES ($1, $2, 'nginx-core', '1', 'affected', 'high', 'usn', 9.0, NOW(), NOW())`, srvID, cve); err != nil {
					t.Fatal(err)
				}
			}
			set := func(kv map[string]string) {
				if err := settings.SetMultiple(ctx, kv); err != nil {
					t.Fatal(err)
				}
			}
			set(map[string]string{services.SettingPreEnabled: "true", services.SettingPreBatch: fmt.Sprint(batch)})

			// Without fallback: the refusal is stored and listed, nothing else.
			an.RunOnce(context.Background())
			an.RunOnce(context.Background()) // batch mode: collect
			st, err := an.GetStatus(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if st.Analyses.OK != 1 || st.Analyses.Refused != 1 || len(st.Failures) != 1 || !st.Failures[0].Refused ||
				!strings.Contains(st.Failures[0].Error, `category "cyber"`) {
				t.Fatalf("after refusal: %+v %+v", st.Analyses, st.Failures)
			}
			calls := len(fake.calls)
			an.RunOnce(context.Background())
			if len(fake.calls) != calls {
				t.Errorf("a refusal must not be retried with the same model: %v", fake.calls)
			}

			// With fallback: Opus analyses the declined CVE.
			set(map[string]string{services.SettingPreFallback: "claude-opus-5-5"})
			an.RunOnce(context.Background())
			an.RunOnce(context.Background())
			st, _ = an.GetStatus(ctx)
			if st.Analyses.OK != 2 || st.Analyses.ByFallback != 1 || len(st.Failures) != 0 {
				t.Fatalf("after fallback: %+v %+v (calls %v)", st.Analyses, st.Failures, fake.calls)
			}
			a1, err := an.GetAnalysis(ctx, "CVE-2026-0001")
			if err != nil {
				t.Fatal(err)
			}
			if a1.Model != "claude-opus-5-5" || a1.RefusedBy != "claude-sonnet-5-5" || !a1.Current {
				t.Errorf("fallback analysis %+v", a1)
			}
			calls = len(fake.calls)
			an.RunOnce(context.Background())
			an.RunOnce(context.Background())
			if len(fake.calls) != calls {
				t.Errorf("a fallback analysis is current; no new calls expected: %v", fake.calls[calls:])
			}
		})
	}
}
