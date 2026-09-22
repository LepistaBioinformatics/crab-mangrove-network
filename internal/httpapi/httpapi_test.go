package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/LepistaBioinformatics/crab-mangrove-network/internal/activity"
	"github.com/LepistaBioinformatics/crab-mangrove-network/internal/actor"
	"github.com/LepistaBioinformatics/crab-mangrove-network/internal/mangrovelog"
)

const token = "shared-secret"

type fakeMembers struct{}

func (fakeMembers) SubscriptionMembers(string, string) ([]string, error) {
	return []string{"alice", "bob"}, nil
}

type threeMembers struct{}

func (threeMembers) SubscriptionMembers(string, string) ([]string, error) {
	return []string{"alice", "bob", "carol"}, nil
}

func newServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	as, err := actor.NewStore(dir)
	if err != nil {
		t.Fatalf("actor store: %v", err)
	}
	lg, err := mangrovelog.New(dir)
	if err != nil {
		t.Fatalf("log: %v", err)
	}
	n := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	return &Server{
		Actors: as, Log: lg, Members: fakeMembers{}, Token: token,
		Now: func() time.Time { n = n.Add(time.Second); return n },
	}
}

func tup(acc string) actor.Tuple {
	return actor.Tuple{TenantID: "t1", SubsAccID: "s1", Role: "alpha", UserAccID: acc}
}

func call(t *testing.T, s *Server, path string, body any, auth bool) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	if auth {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)

	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func TestUnauthenticatedIsRefused(t *testing.T) {
	s := newServer(t)
	for _, path := range []string{"/internal/v1/publish", "/internal/v1/timeline", "/internal/v1/revoke"} {
		rec, _ := call(t, s, path, map[string]any{"tuple": tup("alice")}, false)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s answered %d without a token, want 401", path, rec.Code)
		}
	}
}

// TestForgedActorIsRefused: the body cannot choose who is speaking. An actor
// field in the request is ignored entirely -- identity comes from the verified
// tuple, the way it does everywhere else in this stack.
func TestForgedActorIsRefused(t *testing.T) {
	s := newServer(t)
	rec, out := call(t, s, "/internal/v1/publish", map[string]any{
		"tuple":  tup("alice"),
		"actor":  actor.ServiceID("mallory"), // attempted forgery
		"object": map[string]any{"type": "MemoryNote", "cell": "soil-ph", "content": "5.8"},
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("publish answered %d: %v", rec.Code, out)
	}
	got := out["activity"].(map[string]any)["actor"].(string)
	if got != actor.ServiceID("alice") {
		t.Fatalf("activity was authored by %q; the body chose the actor", got)
	}
}

func TestPublishRefusesAnOutOfReachAddresseeAndWritesNothing(t *testing.T) {
	s := newServer(t)
	rec, out := call(t, s, "/internal/v1/publish", map[string]any{
		"tuple": tup("alice"),
		"to": []string{
			actor.ServiceID("bob"),
			actor.ServiceID("mallory"), // not a member
		},
		"object": map[string]any{"type": "MemoryNote", "cell": "soil-ph", "content": "5.8"},
	}, true)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("answered %d, want 403", rec.Code)
	}
	if out["addressee"] != actor.ServiceID("mallory") {
		t.Errorf("refusal did not name the offending addressee: %v", out)
	}
	if out["delivered"] != false {
		t.Errorf("refusal must state delivered=false so no client renders a partial success: %v", out)
	}
	// Nothing was written: the reachable half must not have been delivered.
	acts, err := s.Log.Read("t1", "s1")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(acts) != 0 {
		t.Fatalf("a refused publish wrote %d activities", len(acts))
	}
}

func TestAgentCannotAddressTheTenant(t *testing.T) {
	s := newServer(t)
	rec, _ := call(t, s, "/internal/v1/publish", map[string]any{
		"tuple":  tup("alice"),
		"to":     []string{actor.TenantGroupID("t1")},
		"object": map[string]any{"type": "MemoryNote", "cell": "c", "content": "x"},
	}, true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("an agent reached the tenant group: %d", rec.Code)
	}

	// The same call from a human whose profile licenses the tenant succeeds.
	rec, _ = call(t, s, "/internal/v1/publish", map[string]any{
		"tuple": tup("alice"), "as": "person", "tenantLicensed": true,
		"to":     []string{actor.TenantGroupID("t1")},
		"object": map[string]any{"type": "MemoryNote", "cell": "c", "content": "x"},
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("a licensed human could not reach the tenant group: %d", rec.Code)
	}
}

// Share widens too, so it goes through the same gate. This is the test that
// catches a second widening verb being added without the check.
func TestShareRefusesAnOutOfReachTarget(t *testing.T) {
	s := newServer(t)
	rec, _ := call(t, s, "/internal/v1/share", map[string]any{
		"tuple": tup("alice"), "objectId": "mangrove:obj:1",
		"target": actor.SubscriptionGroupID("s2"),
	}, true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("share reached a foreign subscription: %d", rec.Code)
	}
}

// TestAdmitRequiredBeforeIngest is FR-B7. An object addressed at somebody is
// visible to that HUMAN, and does not enter their AGENT's memory until the
// human admits it. Without this, steering a colleague's agent is one share
// away.
func TestAdmitRequiredBeforeIngest(t *testing.T) {
	s := newServer(t)

	rec, out := call(t, s, "/internal/v1/publish", map[string]any{
		"tuple":  tup("bob"),
		"to":     []string{actor.ServiceID("alice")},
		"object": map[string]any{"type": "MemoryNote", "cell": "soil-ph", "content": "6.4"},
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("publish: %d %v", rec.Code, out)
	}
	sentID := out["activity"].(map[string]any)["id"].(string)

	// Before admission: held, not ingested.
	_, out = call(t, s, "/internal/v1/timeline", map[string]any{
		"tuple": tup("alice"), "reading": "received",
	}, true)
	held, _ := out["held"].([]any)
	claims, _ := out["claims"].([]any)
	if len(held) != 1 {
		t.Fatalf("want 1 held item before admission, got %d (%v)", len(held), out)
	}
	if len(claims) != 0 {
		t.Fatalf("an unadmitted object is already in the agent's memory: %v", claims)
	}

	// Admit, then it is ingested.
	rec, _ = call(t, s, "/internal/v1/admit", map[string]any{
		"tuple": tup("alice"), "as": "person", "activityId": sentID,
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("admit: %d", rec.Code)
	}

	_, out = call(t, s, "/internal/v1/timeline", map[string]any{
		"tuple": tup("alice"), "reading": "received",
	}, true)
	held, _ = out["held"].([]any)
	claims, _ = out["claims"].([]any)
	if len(held) != 0 || len(claims) != 1 {
		t.Fatalf("after admission want 0 held / 1 claim, got %d/%d (%v)", len(held), len(claims), out)
	}
}

// ONE RECIPIENT'S ADMISSION MUST NOT CLEAR ANOTHER'S HOLD.
//
// Keying admission by activity alone makes Carol's Accept let the object into
// Alice's agent, which is precisely the thing FR-B7 exists to stop: memory
// entering somebody's agent without that person admitting it.
func TestAdmissionIsPerRecipient(t *testing.T) {
	s := newServer(t)
	s.Members = threeMembers{}

	_, out := call(t, s, "/internal/v1/publish", map[string]any{
		"tuple":  tup("bob"),
		"to":     []string{actor.ServiceID("alice"), actor.ServiceID("carol")},
		"object": map[string]any{"type": "MemoryNote", "cell": "soil-ph", "content": "6.4"},
	}, true)
	sentID := out["activity"].(map[string]any)["id"].(string)

	// Carol admits it for herself.
	rec, _ := call(t, s, "/internal/v1/admit", map[string]any{
		"tuple": tup("carol"), "as": "person", "activityId": sentID,
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("carol could not admit: %d", rec.Code)
	}

	// Alice admitted nothing, so for Alice it is still held.
	_, out = call(t, s, "/internal/v1/timeline", map[string]any{
		"tuple": tup("alice"), "reading": "received",
	}, true)
	held, _ := out["held"].([]any)
	claims, _ := out["claims"].([]any)
	if len(held) != 1 || len(claims) != 0 {
		t.Fatalf("carol's admission leaked into alice's agent: held=%d claims=%d (%v)", len(held), len(claims), out)
	}
}

// A governing role holder accepting a group publication must not clear the
// hold for the direct addressees of that same activity either.
func TestGovernanceDecisionIsNotAnAdmission(t *testing.T) {
	s := newServer(t)
	s.Members = threeMembers{}

	_, out := call(t, s, "/internal/v1/publish", map[string]any{
		"tuple": tup("bob"),
		"to": []string{
			actor.SubscriptionGroupID("s1"),
			actor.ServiceID("alice"),
		},
		"object": map[string]any{"type": "MemoryNote", "cell": "soil-ph", "content": "6.4"},
	}, true)
	sentID := out["activity"].(map[string]any)["id"].(string)

	rec, _ := call(t, s, "/internal/v1/decide", map[string]any{
		"tuple": tup("carol"), "as": "person", "activityId": sentID,
		"accept": true, "governs": true,
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("decide: %d", rec.Code)
	}

	_, out = call(t, s, "/internal/v1/timeline", map[string]any{
		"tuple": tup("alice"), "reading": "received",
	}, true)
	if held, _ := out["held"].([]any); len(held) != 1 {
		t.Fatalf("a governance Accept cleared a direct addressee's hold: %v", out)
	}
}

// The human's authority is asymmetric: a bot cannot revoke on its own
// authority, and cannot reverse its human.
func TestOnlyTheHumanMayRevoke(t *testing.T) {
	s := newServer(t)
	rec, _ := call(t, s, "/internal/v1/revoke", map[string]any{
		"tuple": tup("alice"), "as": "service",
		"objectId": "mangrove:obj:1", "cell": "soil-ph",
	}, true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("an agent revoked on its own authority: %d", rec.Code)
	}

	rec, _ = call(t, s, "/internal/v1/revoke", map[string]any{
		"tuple": tup("alice"), "as": "person",
		"objectId": "mangrove:obj:1", "cell": "soil-ph",
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("the human could not revoke: %d", rec.Code)
	}
}

// A cross-scope publication waits on a role holder, and only a role holder may
// decide it. A Reject is a normal result, not an error.
func TestCrossScopePublicationIsPendingUntilAGoverningRoleDecides(t *testing.T) {
	s := newServer(t)

	_, out := call(t, s, "/internal/v1/publish", map[string]any{
		"tuple":  tup("alice"),
		"to":     []string{actor.SubscriptionGroupID("s1")},
		"object": map[string]any{"type": "MemoryNote", "cell": "soil-ph", "content": "5.8"},
	}, true)
	if out["pending"] != true {
		t.Fatalf("a subscription-scope publish was not marked pending: %v", out)
	}
	actID := out["activity"].(map[string]any)["id"].(string)

	_, out = call(t, s, "/internal/v1/timeline", map[string]any{
		"tuple": tup("bob"), "reading": "pending",
	}, true)
	if pend, _ := out["pending"].([]any); len(pend) != 1 {
		t.Fatalf("want 1 pending decision, got %v", out)
	}

	// Without a governing role, no decision.
	rec, _ := call(t, s, "/internal/v1/decide", map[string]any{
		"tuple": tup("bob"), "as": "person", "activityId": actID, "accept": true,
	}, true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("somebody with no governing role decided a scope: %d", rec.Code)
	}

	// With one, it resolves and leaves the pending list.
	rec, _ = call(t, s, "/internal/v1/decide", map[string]any{
		"tuple": tup("bob"), "as": "person", "activityId": actID,
		"accept": true, "governs": true,
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("a role holder could not decide: %d", rec.Code)
	}

	_, out = call(t, s, "/internal/v1/timeline", map[string]any{
		"tuple": tup("bob"), "reading": "pending",
	}, true)
	if pend, _ := out["pending"].([]any); len(pend) != 0 {
		t.Fatalf("a decided activity is still pending: %v", out)
	}
}

func TestPublishValidatesTheObject(t *testing.T) {
	s := newServer(t)
	for name, obj := range map[string]map[string]any{
		"no cell":  {"type": "MemoryNote", "content": "x"},
		"bad type": {"type": "Note", "cell": "c", "content": "x"},
	} {
		rec, _ := call(t, s, "/internal/v1/publish", map[string]any{
			"tuple": tup("alice"), "object": obj,
		}, true)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: answered %d, want 400", name, rec.Code)
		}
	}
}

// Read is the receipt and Like is endorsement; they are different verbs.
func TestReactEmitsTheStandardVerbs(t *testing.T) {
	s := newServer(t)
	for kind, want := range map[string]activity.Type{
		"read": activity.Read, "like": activity.Like, "flag": activity.Flag,
	} {
		_, out := call(t, s, "/internal/v1/react", map[string]any{
			"tuple": tup("alice"), "kind": kind, "ref": "mangrove:obj:1",
		}, true)
		got := out["activity"].(map[string]any)["type"].(string)
		if got != string(want) {
			t.Errorf("kind %q emitted %q, want %q", kind, got, want)
		}
	}
	rec, _ := call(t, s, "/internal/v1/react", map[string]any{
		"tuple": tup("alice"), "kind": "yeet", "ref": "mangrove:obj:1",
	}, true)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown reaction kind answered %d", rec.Code)
	}
}

func TestHealthzNeedsNoToken(t *testing.T) {
	s := newServer(t)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz answered %d", rec.Code)
	}
}
