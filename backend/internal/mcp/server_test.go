package mcp

import (
	"context"
	"testing"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vultrack/vultrack/internal/models"
)

// writeToolNames are the mutating tools that must only ever be exposed by the
// read-write server, never by the read-only server.
var writeToolNames = []string{
	"upsert_assessment",
	"delete_assessment",
	"trigger_server_scan",
	"create_server_group",
	"update_server_group",
	"delete_server_group",
	"set_server_group_members",
}

// connectClient connects an in-memory client to the given server and returns the
// client session, registering cleanup on the test.
func connectClient(t *testing.T, server *mcpsdk.Server) *mcpsdk.ClientSession {
	t.Helper()
	ctx := context.Background()

	clientTransport, serverTransport := mcpsdk.NewInMemoryTransports()

	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })

	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "test", Version: "0"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = clientSession.Close() })

	return clientSession
}

// listToolNames returns the set of tool names the server advertises.
func listToolNames(t *testing.T, server *mcpsdk.Server) map[string]bool {
	t.Helper()
	res, err := connectClient(t, server).ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	names := make(map[string]bool, len(res.Tools))
	for _, tool := range res.Tools {
		names[tool.Name] = true
	}
	return names
}

func TestReadOnlyServerExcludesWriteTools(t *testing.T) {
	ro, rw := BuildServers(Deps{})

	roTools := listToolNames(t, ro)
	rwTools := listToolNames(t, rw)

	// The read-only server must expose NONE of the write tools; the read-write
	// server MUST expose every write tool.
	for _, name := range writeToolNames {
		if roTools[name] {
			t.Errorf("read-only server unexpectedly exposes write tool %q", name)
		}
		if !rwTools[name] {
			t.Errorf("read-write server is missing write tool %q", name)
		}
	}

	// Read tools must appear on both servers.
	readTools := []string{
		"list_servers", "get_server", "list_findings", "get_finding",
		"get_cve", "list_cve_servers", "list_triage_queue", "list_assessments",
		"get_dashboard_stats", "get_severity_stats", "get_trend_stats",
		"get_top_servers", "get_top_cves", "get_assessments_by_severity",
		"list_server_groups", "get_server_group", "get_server_group_members",
	}
	for _, name := range readTools {
		if !roTools[name] {
			t.Errorf("read-only server is missing read tool %q", name)
		}
		if !rwTools[name] {
			t.Errorf("read-write server is missing read tool %q", name)
		}
	}

	if len(rwTools) <= len(roTools) {
		t.Errorf("expected read-write (%d) to expose more tools than read-only (%d)", len(rwTools), len(roTools))
	}
}

// TestReadOnlyServerRejectsWriteCall verifies that even an explicit attempt to
// invoke a write tool against the read-only server fails, because the tool is
// not registered there — the call never reaches a handler.
func TestReadOnlyServerRejectsWriteCall(t *testing.T) {
	ro, _ := BuildServers(Deps{})
	session := connectClient(t, ro)

	_, err := session.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name:      "upsert_assessment",
		Arguments: map[string]any{"cveId": "CVE-2024-0001", "status": "relevant"},
	})
	if err == nil {
		t.Fatal("expected error calling write tool on read-only server, got nil")
	}
}

func TestTokenAudit(t *testing.T) {
	ctx := context.WithValue(context.Background(), TokenContextKey,
		&models.APIToken{TokenPrefix: "abc12345", Description: "triage agent"})
	prefix, desc := tokenAudit(ctx)
	if prefix != "abc12345" || desc != "triage agent" {
		t.Errorf("tokenAudit = (%q, %q), want (abc12345, triage agent)", prefix, desc)
	}

	prefix, desc = tokenAudit(context.Background())
	if prefix != "unknown" || desc != "" {
		t.Errorf("tokenAudit with no token = (%q, %q), want (unknown, \"\")", prefix, desc)
	}
}
