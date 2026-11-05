package handlers

// Agent API v2: pending and admin-revoked registrations get 403 with a code
// instead of 401, so agents stop re-enrolling; forced re-enrollment supersedes
// the old registration instead of revoking it (docs/AGENT_API.md).
//
// Requires a throwaway PostgreSQL; see internal/testdb for the setup command.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vultrack/vultrack/internal/auth"
	"github.com/vultrack/vultrack/internal/database"
	"github.com/vultrack/vultrack/internal/models"
	"github.com/vultrack/vultrack/internal/services"
	"github.com/vultrack/vultrack/internal/testdb"
)

type agentAPI struct {
	t    *testing.T
	ctx  context.Context
	pool *pgxpool.Pool
	h    *Handler
	app  *fiber.App
}

func newAgentAPI(t *testing.T) *agentAPI {
	pool, ctx := testdb.Setup(t, "agent_registration_tests")
	h := &Handler{
		agentService:        services.NewAgentService(pool),
		enrollmentService:   services.NewEnrollmentService(pool),
		settingsService:     services.NewSettingsService(pool),
		serverService:       services.NewServerService(pool),
		packageService:      services.NewPackageService(pool),
		runtimeFactsService: services.NewRuntimeFactsService(pool),
		jwtSecret:           []byte("test-secret-test-secret-test-secret"),
	}
	app := fiber.New(fiber.Config{ErrorHandler: h.errorHandler})
	app.Post("/api/v2/agent/enroll", h.enrollAgentV2)
	app.Post("/api/v2/agent/token", h.refreshAgentToken)
	app.Post("/api/v2/agent/report", h.receiveAgentReportV2)
	return &agentAPI{t: t, ctx: ctx, pool: pool, h: h, app: app}
}

// call sends a request and returns the status and the decoded JSON body.
func (a *agentAPI) call(path, bearer string, body any) (int, map[string]any) {
	a.t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := a.app.Test(req, -1)
	if err != nil {
		a.t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func (a *agentAPI) key(autoApprove bool) string {
	a.t.Helper()
	_, full, err := a.h.enrollmentService.CreateEnrollmentKey(a.ctx, "test", autoApprove, nil)
	if err != nil {
		a.t.Fatal(err)
	}
	return full
}

type enrolled struct {
	id      int64
	access  string
	refresh string
}

func (a *agentAPI) enroll(key, host string, force bool) (int, map[string]any, enrolled) {
	a.t.Helper()
	status, body := a.call("/api/v2/agent/enroll", key, map[string]any{"hostname": host, "force": force})
	var e enrolled
	if status == fiber.StatusCreated {
		e.access, _ = body["accessToken"].(string)
		e.refresh, _ = body["refreshToken"].(string)
		claims, err := auth.ValidateAgentJWT(a.h.jwtSecret, e.access)
		if err != nil {
			a.t.Fatal(err)
		}
		e.id = parseID(a.t, claims.Subject)
	}
	return status, body, e
}

func parseID(t *testing.T, s string) int64 {
	var id int64
	if err := json.Unmarshal([]byte(s), &id); err != nil {
		t.Fatalf("subject %q: %v", s, err)
	}
	return id
}

var report = map[string]any{
	"hostname": "host-a", "osFamily": "ubuntu", "osRelease": "24.04", "kernel": "6.8.0",
	"arch": "amd64", "ipv4Addrs": []string{"10.0.0.1"},
}

func (a *agentAPI) status(id int64) string {
	a.t.Helper()
	var s string
	if err := a.pool.QueryRow(a.ctx, `SELECT status FROM registered_agents WHERE id = $1`, id).Scan(&s); err != nil {
		a.t.Fatal(err)
	}
	return s
}

func expect(t *testing.T, what string, status int, body map[string]any, wantStatus int, wantCode string) {
	t.Helper()
	if status != wantStatus {
		t.Errorf("%s: status %d, want %d (body %v)", what, status, wantStatus, body)
		return
	}
	if code, _ := body["code"].(string); code != wantCode {
		t.Errorf("%s: code %q, want %q (body %v)", what, code, wantCode, body)
	}
	if _, ok := body["error"].(string); wantStatus >= 400 && !ok {
		t.Errorf("%s: body has no error message: %v", what, body)
	}
}

func TestAgentRegistrationStates(t *testing.T) {
	a := newAgentAPI(t)
	manual, auto := a.key(false), a.key(true)

	// --- pending ---
	st, body, pending := a.enroll(manual, "host-p", false)
	if st != fiber.StatusCreated || body["status"] != models.AgentStatusPending {
		t.Fatalf("enroll pending: %d %v", st, body)
	}
	st, body = a.call("/api/v2/agent/token", pending.refresh, nil)
	expect(t, "refresh while pending", st, body, fiber.StatusForbidden, "agent_pending")
	st, body = a.call("/api/v2/agent/token", pending.refresh, nil)
	expect(t, "refresh while pending, again (token not rotated)", st, body, fiber.StatusForbidden, "agent_pending")
	st, body = a.call("/api/v2/agent/report", pending.access, report)
	expect(t, "report while pending", st, body, fiber.StatusForbidden, "agent_pending")

	// approved: the same refresh token now works and rotates
	if err := a.h.agentService.Approve(a.ctx, pending.id); err != nil {
		t.Fatal(err)
	}
	st, body = a.call("/api/v2/agent/token", pending.refresh, nil)
	if st != fiber.StatusOK || body["refreshToken"] == nil {
		t.Fatalf("refresh after approval: %d %v", st, body)
	}
	rotated := body["refreshToken"].(string)
	st, _ = a.call("/api/v2/agent/token", pending.refresh, nil)
	if st != fiber.StatusUnauthorized {
		t.Errorf("the rotated-away token must give 401, got %d", st)
	}

	// --- revoked by an administrator ---
	if err := a.h.agentService.Revoke(a.ctx, pending.id); err != nil {
		t.Fatal(err)
	}
	st, body = a.call("/api/v2/agent/token", rotated, nil)
	expect(t, "refresh after admin revocation", st, body, fiber.StatusForbidden, "agent_revoked")
	if _, err := a.pool.Exec(a.ctx, `UPDATE agent_refresh_tokens SET expires_at = NOW() - interval '1 day' WHERE agent_id = $1`, pending.id); err != nil {
		t.Fatal(err)
	}
	st, body = a.call("/api/v2/agent/token", rotated, nil)
	expect(t, "refresh after admin revocation, expired token", st, body, fiber.StatusForbidden, "agent_revoked")
	st, body = a.call("/api/v2/agent/report", pending.access, report)
	expect(t, "report after admin revocation", st, body, fiber.StatusForbidden, "agent_revoked")

	for _, force := range []bool{false, true} {
		st, body, _ = a.enroll(auto, "host-p", force)
		expect(t, "enroll a revoked host", st, body, fiber.StatusForbidden, "agent_revoked")
	}
	if err := a.h.agentService.Delete(a.ctx, pending.id); err != nil {
		t.Fatal(err)
	}
	if st, body, _ = a.enroll(auto, "host-p", false); st != fiber.StatusCreated {
		t.Errorf("enroll after the admin deleted the revoked registration: %d %v", st, body)
	}

	// --- superseded by a forced re-enrollment ---
	_, _, first := a.enroll(auto, "host-a", false)
	st, body, second := a.enroll(auto, "host-a", false)
	if st != fiber.StatusConflict {
		t.Errorf("second enrollment without force: %d %v", st, body)
	}
	st, _, second = a.enroll(auto, "host-a", true)
	if st != fiber.StatusCreated {
		t.Fatalf("forced re-enrollment: %d", st)
	}
	if s := a.status(first.id); s != models.AgentStatusSuperseded {
		t.Errorf("replaced registration status = %q, want superseded", s)
	}
	st, body = a.call("/api/v2/agent/token", first.refresh, nil)
	expect(t, "refresh of a superseded registration", st, body, fiber.StatusUnauthorized, "")
	st, body = a.call("/api/v2/agent/report", first.access, report)
	expect(t, "report of a superseded registration", st, body, fiber.StatusUnauthorized, "")
	st, _ = a.call("/api/v2/agent/report", second.access, report)
	if st != fiber.StatusOK {
		t.Errorf("report of the new registration: %d", st)
	}
	listed, err := a.h.agentService.GetAll(a.ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, ag := range listed {
		if ag.Status == models.AgentStatusSuperseded {
			t.Error("superseded registrations must not be listed by default")
		}
	}

	// --- deleted ---
	if err := a.h.agentService.Delete(a.ctx, second.id); err != nil {
		t.Fatal(err)
	}
	st, body = a.call("/api/v2/agent/report", second.access, report)
	expect(t, "report of a deleted registration", st, body, fiber.StatusUnauthorized, "")
}

func TestSupersededMigration(t *testing.T) {
	a := newAgentAPI(t)
	insert := func(host, status string, age time.Duration) int64 {
		var id int64
		if err := a.pool.QueryRow(a.ctx, `
			INSERT INTO registered_agents (hostname, token_hash, token_prefix, status, created_at)
			VALUES ($1, md5(random()::text), 'at_x', $2, NOW() - make_interval(secs => $3)) RETURNING id
		`, host, status, age.Seconds()).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	replaced := insert("host-1", "revoked", 48*time.Hour) // a newer registration exists
	current := insert("host-1", "active", 24*time.Hour)
	adminRevoked := insert("host-2", "revoked", 24*time.Hour) // no newer registration

	if _, err := a.pool.Exec(a.ctx, `DELETE FROM schema_migrations WHERE name = '2026-11-agents-superseded'`); err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(a.pool); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[int64]string{replaced: "superseded", current: "active", adminRevoked: "revoked"} {
		if got := a.status(id); got != want {
			t.Errorf("registration %d: %q, want %q", id, got, want)
		}
	}

	// It runs once: a later admin revocation with newer rows stays revoked.
	later := insert("host-3", "revoked", 48*time.Hour)
	insert("host-3", "active", time.Hour)
	if err := database.Migrate(a.pool); err != nil {
		t.Fatal(err)
	}
	if got := a.status(later); got != "revoked" {
		t.Errorf("the migration ran again: %q", got)
	}
}
