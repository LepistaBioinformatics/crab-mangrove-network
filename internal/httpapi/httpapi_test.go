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
	"github.com/LepistaBioinformatics/crab-mangrove-network/internal/blob"
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
	bs, err := blob.New(dir, 0)
	if err != nil {
		t.Fatalf("blob store: %v", err)
	}
	n := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	return &Server{
		Actors: as, Log: lg, Blobs: bs, Members: fakeMembers{}, Token: token,
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

// TestAgentCannotAddressItsOwnSubscriptionGroup is the levelling decision seen
// from the wire (AD-030). It used to succeed: a workspace tuple names a
// subscription, and that was taken to license a broadcast to it. It does not --
// membership is not governance, and an MCP token cannot prove governance.
func TestAgentCannotAddressItsOwnSubscriptionGroup(t *testing.T) {
	s := newServer(t)
	rec, _ := call(t, s, "/internal/v1/publish", map[string]any{
		"tuple":  tup("alice"),
		"to":     []string{actor.SubscriptionGroupID("s1")},
		"object": map[string]any{"type": "MemoryNote", "cell": "c", "content": "x"},
	}, true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("an agent broadcast to its own subscription group: %d", rec.Code)
	}

	rec, _ = call(t, s, "/internal/v1/publish", map[string]any{
		"tuple": tup("alice"), "as": "person", "groupsLicensed": true,
		"to":     []string{actor.SubscriptionGroupID("s1")},
		"object": map[string]any{"type": "MemoryNote", "cell": "c", "content": "x"},
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("a governing human could not reach its own subscription group: %d", rec.Code)
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

// THE GATE A SHARE INTO A GROUP RESTS ON.
//
// `viewer.reach` grants a shared group its audience with NO governance decision,
// on the grounds that the Add already passed `reach.Check` -- so an unlicensed
// caller reaching a group HERE would be reaching every member of it with nothing
// in the way. Asserted for both groups and for the member's own subscription,
// which is the one an agent belongs to and still may not address.
func TestShareRefusesAGroupWithoutTheLicenceForIt(t *testing.T) {
	for _, c := range []struct {
		name     string
		target   string
		licences map[string]any
	}{
		{"own subscription, unlicensed", actor.SubscriptionGroupID("s1"), map[string]any{}},
		{"the tenant, unlicensed", actor.TenantGroupID("t1"), map[string]any{}},
		{"the tenant, with only the group licence", actor.TenantGroupID("t1"), map[string]any{"groupsLicensed": true}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newServer(t)
			body := map[string]any{
				"tuple": tup("alice"), "as": "person",
				"objectId": "mangrove:obj:1", "target": c.target,
			}
			for k, v := range c.licences {
				body[k] = v
			}
			rec, _ := call(t, s, "/internal/v1/share", body, true)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("share reached %s: %d %s", c.target, rec.Code, rec.Body.String())
			}
		})
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
		// Addressing a Group at all takes governance now, so this publisher is
		// a governing human rather than an agent. The test is about what an
		// Accept does afterwards, which is unchanged either way.
		"groupsLicensed": true,
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

// A GROUP PUBLICATION IS ACCEPTED AT SOURCE BY ITS LICENSED AUTHOR.
//
// The pending step exists so a role holder vets what travels to their scope.
// Reaching the publish handler with a group in the audience MEANS the author
// holds the licence for it -- the gate refuses everybody else -- so the vetting
// already happened, by the same person, when they published. Asking them to then
// approve their own post is ceremony that reads as a malfunction: the author
// watches their publication reach nobody and has no reason to look in Pending.
//
// The Accept is EMITTED, not inferred, so the log still says who let it travel.
func TestAGroupPublicationIsAcceptedAtSourceByItsAuthor(t *testing.T) {
	s := newServer(t)

	_, out := call(t, s, "/internal/v1/publish", map[string]any{
		"tuple": tup("alice"), "as": "person", "groupsLicensed": true,
		"to":     []string{actor.SubscriptionGroupID("s1")},
		"object": map[string]any{"type": "MemoryNote", "cell": "soil-ph", "content": "5.8"},
	}, true)
	if out["pending"] != false {
		t.Fatalf("a licensed author's group publish was left pending: %v", out)
	}
	actID := out["activity"].(map[string]any)["id"].(string)

	// The acceptance is in the log, by the author, naming the scope -- an
	// inferred one would leave no record of who let it travel.
	acts, err := s.Log.Read("t1", "s1")
	if err != nil {
		t.Fatal(err)
	}
	var accepted bool
	for _, a := range acts {
		if a.Type == activity.Accept && a.InReplyTo == actID {
			accepted = true
			if a.Actor != actor.PersonID("alice") {
				t.Errorf("accepted by %s, want the author", a.Actor)
			}
			if a.Target != actor.SubscriptionGroupID("s1") {
				t.Errorf("accept names %q, want the group", a.Target)
			}
		}
	}
	if !accepted {
		t.Fatal("no acceptance was written; nothing records who let it travel")
	}

	// NOTHING IS WAITING ON ANYBODY. The point of accepting at source is that the
	// decision has been made, so no role holder is left with a queue of their own
	// colleagues' posts to rubber-stamp.
	_, out = call(t, s, "/internal/v1/timeline", map[string]any{
		"tuple": tup("bob"), "reading": "pending",
	}, true)
	if pend, _ := out["pending"].([]any); len(pend) != 0 {
		t.Fatalf("a publication accepted at source is still queued for a decision: %v", out)
	}

	// The decide route stays, and still refuses somebody with no governing role.
	// Today nothing unlicensed can address a group at all, so nothing reaches
	// that queue -- but the mechanism is what answers "somebody proposed this to
	// my scope", and it must not rot while it is unused.
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

// TestGroupPublicationReachesTheWholeScope is the arm nothing covered.
//
// Found by mutation while the visibility rule was being factored out: breaking
// "reaches them through a group a governing role accepted" failed NOT ONE test,
// although two tests publish to a group and one of them has a role holder
// accept. They assert the DECISION; none asserted that the decision is what
// makes the publication readable by the rest of the scope -- which is the whole
// point of having one.
func TestGroupPublicationReachesTheWholeScope(t *testing.T) {
	s := newServer(t)
	s.Members = threeMembers{}

	_, out := call(t, s, "/internal/v1/publish", map[string]any{
		"tuple": tup("alice"), "as": "person", "groupsLicensed": true,
		"to":     []string{actor.SubscriptionGroupID("s1")},
		"object": map[string]any{"type": "MemoryNote", "cell": "soil-ph", "content": "5.8"},
	}, true)
	actID := out["activity"].(map[string]any)["id"].(string)

	received := func(who string) int {
		t.Helper()
		_, out := call(t, s, "/internal/v1/timeline", map[string]any{
			"tuple": tup(who), "reading": "received",
		}, true)
		claims, _ := out["claims"].([]any)
		held, _ := out["held"].([]any)
		if len(held) != 0 {
			t.Fatalf("%s holds a group publication; a group is not a direct address: %v", who, out)
		}
		return len(claims)
	}

	// It reaches the scope at once, because publishing to a group you govern IS
	// the decision. carol was never named: the group is what carries it to her.
	if n := received("carol"); n != 1 {
		t.Fatalf("a group publication did not reach the scope: %d claims", n)
	}
	_ = actID
	// And the author still does not see their own publication as received.
	if n := received("alice"); n != 0 {
		t.Fatalf("the author received their own publication: %d claims", n)
	}
}

// TestRevokeReachesTheRecipientAndNotOnlyTheAuthor pins a defect that shipped:
// the author saw `deleted: true` and every person they had shared with went on
// reading the claim as live, with not even a strikethrough.
//
// The cause was that a Delete was emitted with no audience at all. The reduction
// only ever sees the activities a reader can reach, so the tombstone reached
// nobody but the person who wrote it. A revoke that convinces only the person
// who performed it is worse than no revoke: they stop worrying about content
// that is still being read.
func TestRevokeReachesTheRecipientAndNotOnlyTheAuthor(t *testing.T) {
	s := newServer(t)
	s.Members = threeMembers{}

	_, out := call(t, s, "/internal/v1/publish", map[string]any{
		"tuple": tup("alice"), "as": "person",
		"to":     []string{actor.ServiceID("bob")},
		"object": map[string]any{"type": "MemoryNote", "cell": "soil-ph", "content": "6.4"},
	}, true)
	act := out["activity"].(map[string]any)
	objID := act["object"].(map[string]any)["id"].(string)

	rec, _ := call(t, s, "/internal/v1/admit", map[string]any{
		"tuple": tup("bob"), "as": "person", "activityId": act["id"].(string),
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("admit: %d", rec.Code)
	}

	deletedForBob := func() (int, bool) {
		t.Helper()
		_, out := call(t, s, "/internal/v1/timeline", map[string]any{
			"tuple": tup("bob"), "reading": "received",
		}, true)
		claims, _ := out["claims"].([]any)
		if len(claims) == 0 {
			return 0, false
		}
		return len(claims), claims[0].(map[string]any)["deleted"] == true
	}

	if n, deleted := deletedForBob(); n != 1 || deleted {
		t.Fatalf("before the revoke bob should hold one live claim, got n=%d deleted=%v", n, deleted)
	}

	rec, _ = call(t, s, "/internal/v1/revoke", map[string]any{
		"tuple": tup("alice"), "as": "person", "objectId": objID, "cell": "soil-ph",
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: %d", rec.Code)
	}

	if _, deleted := deletedForBob(); !deleted {
		t.Error("the recipient still reads a revoked claim as live; the tombstone did not travel")
	}
	// The author's own view was always right, and must stay right.
	_, out = call(t, s, "/internal/v1/timeline", map[string]any{
		"tuple": tup("alice"), "reading": "published",
	}, true)
	claims, _ := out["claims"].([]any)
	if len(claims) != 1 || claims[0].(map[string]any)["deleted"] != true {
		t.Errorf("the author's view of their own revoke regressed: %v", out)
	}
}

// The union, not the last activity: something published privately and shared
// onward later has reached more people than its Create says, and a tombstone
// copying only the Create would leave exactly those later recipients reading it.
func TestARevokeReachesPeopleAddedAfterTheFirstPublication(t *testing.T) {
	s := newServer(t)
	s.Members = threeMembers{}

	_, out := call(t, s, "/internal/v1/publish", map[string]any{
		"tuple": tup("alice"), "as": "person",
		"to":     []string{},
		"object": map[string]any{"type": "MemoryNote", "cell": "soil-ph", "content": "6.4"},
	}, true)
	objID := out["activity"].(map[string]any)["object"].(map[string]any)["id"].(string)

	rec, _ := call(t, s, "/internal/v1/share", map[string]any{
		"tuple": tup("alice"), "as": "person",
		"objectId": objID, "target": actor.ServiceID("bob"),
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("share: %d %s", rec.Code, rec.Body.String())
	}

	rec, _ = call(t, s, "/internal/v1/revoke", map[string]any{
		"tuple": tup("alice"), "as": "person", "objectId": objID, "cell": "soil-ph",
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: %d", rec.Code)
	}

	// The Delete must name bob, who only ever appeared on the Share.
	deleteTo := out["activity"].(map[string]any)
	_ = deleteTo
	acts, err := s.Log.Read("t1", "s1")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, a := range acts {
		if a.Type != activity.Delete {
			continue
		}
		for _, addr := range a.Audience() {
			if addr == actor.ServiceID("bob") {
				found = true
			}
		}
	}
	if !found {
		t.Error("the tombstone did not name somebody the object only reached through a later share")
	}
}

// Something withdrawn before it was ever taken simply goes away. Leaving it in
// the held list would offer an Admit for content the author has already
// recalled -- and taking it would put recalled content into the agent's memory.
func TestRevokingSomethingStillHeldWithdrawsItEntirely(t *testing.T) {
	s := newServer(t)
	s.Members = threeMembers{}

	_, out := call(t, s, "/internal/v1/publish", map[string]any{
		"tuple": tup("alice"), "as": "person",
		"to":     []string{actor.ServiceID("bob")},
		"object": map[string]any{"type": "MemoryNote", "cell": "soil-ph", "content": "6.4"},
	}, true)
	objID := out["activity"].(map[string]any)["object"].(map[string]any)["id"].(string)

	bobSees := func() (held, claims int) {
		t.Helper()
		_, out := call(t, s, "/internal/v1/timeline", map[string]any{
			"tuple": tup("bob"), "reading": "received",
		}, true)
		h, _ := out["held"].([]any)
		c, _ := out["claims"].([]any)
		return len(h), len(c)
	}

	// bob has NOT admitted it: it is held.
	if h, _ := bobSees(); h != 1 {
		t.Fatalf("expected one held item before the revoke, got %d", h)
	}

	rec, _ := call(t, s, "/internal/v1/revoke", map[string]any{
		"tuple": tup("alice"), "as": "person", "objectId": objID, "cell": "soil-ph",
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: %d", rec.Code)
	}

	h, _ := bobSees()
	if h != 0 {
		t.Errorf("a recalled item is still offered for admission: %d held", h)
	}
}

// TestARejectedGroupPublicationReachesNobody pins a defect that shipped and that
// looked, from the deciding member's side, exactly like it had worked.
//
// One boolean answered two different questions: "has a role holder dealt with
// this?", which decides whether it stays in the pending list, and "may the scope
// read it?", which decides whether it travels. Both were set by a Reject as well
// as an Accept, so REJECTING A PUBLICATION PUBLISHED IT TO THE ENTIRE SCOPE. It
// also left the pending list at the same moment, so the only visible evidence
// agreed with the decision the member thought they had made.
func TestARejectedGroupPublicationReachesNobody(t *testing.T) {
	s := newServer(t)
	s.Members = threeMembers{}

	publishToGroup := func(cell string) string {
		t.Helper()
		_, out := call(t, s, "/internal/v1/publish", map[string]any{
			"tuple": tup("alice"), "as": "person", "groupsLicensed": true,
			"to":     []string{actor.SubscriptionGroupID("s1")},
			"object": map[string]any{"type": "MemoryNote", "cell": cell, "content": "x"},
		}, true)
		return out["activity"].(map[string]any)["id"].(string)
	}
	decide := func(activityID string, accept bool) {
		t.Helper()
		rec, _ := call(t, s, "/internal/v1/decide", map[string]any{
			"tuple": tup("bob"), "as": "person", "activityId": activityID,
			"accept": accept, "governs": true,
		}, true)
		if rec.Code != http.StatusOK {
			t.Fatalf("decide(%v): %d", accept, rec.Code)
		}
	}
	carolSees := func() (claims, pending int) {
		t.Helper()
		_, out := call(t, s, "/internal/v1/timeline", map[string]any{
			"tuple": tup("carol"), "reading": "received",
		}, true)
		c, _ := out["claims"].([]any)
		_, out = call(t, s, "/internal/v1/timeline", map[string]any{
			"tuple": tup("carol"), "reading": "pending",
		}, true)
		p, _ := out["pending"].([]any)
		return len(c), len(p)
	}

	// Accepted at source, so it starts VISIBLE. That makes this the sharper
	// version of the test: the reject has to take away something the scope can
	// already read, rather than merely fail to grant it.
	rejected := publishToGroup("rejected-thing")
	if c, p := carolSees(); c != 1 || p != 0 {
		t.Fatalf("before the reject: claims=%d pending=%d, want 1 and 0", c, p)
	}

	decide(rejected, false)
	c, p := carolSees()
	if c != 0 {
		t.Errorf("a REJECTED publication reached the scope: %d claims", c)
	}
	if p != 0 {
		t.Errorf("a decided publication is still pending: %d", p)
	}

	// And a role holder can put it back, so the fix is not "a reject is final".
	decide(rejected, true)
	if c, _ := carolSees(); c != 1 {
		t.Errorf("a re-accepted publication did not reach the scope again: %d claims", c)
	}
}

// A role holder may change their mind, and the last decision is the one that
// counts. Without this, "reject then accept" and "accept then reject" would both
// depend on which happened to be seen last by an unordered read.
func TestTheLastGovernanceDecisionWins(t *testing.T) {
	for _, tc := range []struct {
		name  string
		first bool
		then  bool
		want  int
	}{
		{"reject then accept", false, true, 1},
		{"accept then reject", true, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newServer(t)
			s.Members = threeMembers{}
			_, out := call(t, s, "/internal/v1/publish", map[string]any{
				"tuple": tup("alice"), "as": "person", "groupsLicensed": true,
				"to":     []string{actor.SubscriptionGroupID("s1")},
				"object": map[string]any{"type": "MemoryNote", "cell": "c", "content": "x"},
			}, true)
			id := out["activity"].(map[string]any)["id"].(string)

			for _, accept := range []bool{tc.first, tc.then} {
				rec, _ := call(t, s, "/internal/v1/decide", map[string]any{
					"tuple": tup("bob"), "as": "person", "activityId": id,
					"accept": accept, "governs": true,
				}, true)
				if rec.Code != http.StatusOK {
					t.Fatalf("decide: %d", rec.Code)
				}
			}

			_, out = call(t, s, "/internal/v1/timeline", map[string]any{
				"tuple": tup("carol"), "reading": "received",
			}, true)
			claims, _ := out["claims"].([]any)
			if len(claims) != tc.want {
				t.Errorf("claims = %d, want %d", len(claims), tc.want)
			}
		})
	}
}

// TestASharedObjectReachesThePersonItWasSharedWith pins a feature that never
// worked, for agents or for members.
//
// A share is an Add: it carries no object of its own, only the id it widens and
// the new addressee. `Reduce` handled Create, Update, Delete, Like and Undo, and
// every reading skips an activity with no object -- so the Add was written to
// the log and then read by nothing. The reduction went on describing the
// audience the Create had, which is why a member could share a memory four times
// and watch the recipient see nothing.
func TestASharedObjectReachesThePersonItWasSharedWith(t *testing.T) {
	s := newServer(t)
	s.Members = threeMembers{}

	// Published PRIVATELY: nobody but the author can see it.
	_, out := call(t, s, "/internal/v1/publish", map[string]any{
		"tuple": tup("alice"), "as": "person",
		"object": map[string]any{"type": "MemoryNote", "cell": "soil-ph", "content": "6.4"},
	}, true)
	objID := out["activity"].(map[string]any)["object"].(map[string]any)["id"].(string)

	sees := func(who string) (claims, held int) {
		t.Helper()
		_, out := call(t, s, "/internal/v1/timeline", map[string]any{
			"tuple": tup(who), "reading": "received",
		}, true)
		c, _ := out["claims"].([]any)
		h, _ := out["held"].([]any)
		return len(c), len(h)
	}

	if c, h := sees("bob"); c != 0 || h != 0 {
		t.Fatalf("a private publication reached bob: claims=%d held=%d", c, h)
	}

	rec, out := call(t, s, "/internal/v1/share", map[string]any{
		"tuple": tup("alice"), "as": "person",
		"objectId": objID, "target": actor.ServiceID("bob"),
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("share: %d %s", rec.Code, rec.Body.String())
	}
	// AND IT DOES NOT CLAIM TO BE WAITING ON ANYBODY. It said `pending: true`
	// for every share, so the interface told the member their memory would reach
	// the group once somebody accepted it -- pointing at a queue that could never
	// hold an Add.
	if out["pending"] != false {
		t.Errorf("a share reported itself pending: %v", out["pending"])
	}

	if c, h := sees("bob"); c+h != 1 {
		t.Fatalf("the share reached nobody: bob sees claims=%d held=%d", c, h)
	}
	// carol was never named, by the Create or by the share.
	if c, h := sees("carol"); c != 0 || h != 0 {
		t.Errorf("the share reached somebody it did not name: carol claims=%d held=%d", c, h)
	}
}

// Sharing into a group widens it to the whole scope, and the audience the
// timeline reports says so -- a member has to be able to see where their memory
// went.
func TestSharingIntoAGroupWidensTheAudienceItReports(t *testing.T) {
	s := newServer(t)
	s.Members = threeMembers{}

	_, out := call(t, s, "/internal/v1/publish", map[string]any{
		"tuple": tup("alice"), "as": "person",
		"object": map[string]any{"type": "MemoryNote", "cell": "soil-ph", "content": "6.4"},
	}, true)
	objID := out["activity"].(map[string]any)["object"].(map[string]any)["id"].(string)

	rec, _ := call(t, s, "/internal/v1/share", map[string]any{
		"tuple": tup("alice"), "as": "person", "groupsLicensed": true,
		"objectId": objID, "target": actor.SubscriptionGroupID("s1"),
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("share to group: %d %s", rec.Code, rec.Body.String())
	}

	_, out = call(t, s, "/internal/v1/timeline", map[string]any{
		"tuple": tup("alice"), "reading": "published",
	}, true)
	claims, _ := out["claims"].([]any)
	if len(claims) != 1 {
		t.Fatalf("author sees %d claims", len(claims))
	}
	aud, _ := claims[0].(map[string]any)["audience"].([]any)
	var found bool
	for _, a := range aud {
		if a == actor.SubscriptionGroupID("s1") {
			found = true
		}
	}
	if !found {
		t.Errorf("the claim does not say where the share sent it: %v", aud)
	}
}

// THE TWO ACTORS ARE ONE MEMBER WHEN READING, AND TWO ONLY WHEN WRITING.
//
// A member has a person actor and a service actor, and the split is real: the
// agent publishes as itself, and `as` picks which one signs. It is NOT real on
// the way in. Whoever owns the bot reads everything either of their actors was
// addressed with, from one timeline -- there is no second inbox to check, and
// `handleTimeline` does not look at `as` at all.
//
// Asserted from BOTH sides, and with `as` set differently on otherwise identical
// requests, because "the reader's actor does not change the answer" is the claim
// and a single reading would not make it.
func TestAMemberReadsWhatEitherOfTheirActorsWasAddressed(t *testing.T) {
	s := newServer(t)

	for _, to := range []string{actor.PersonID("bob"), actor.ServiceID("bob")} {
		rec, _ := call(t, s, "/internal/v1/publish", map[string]any{
			"tuple": tup("alice"), "as": "person", "to": []string{to},
			"object": map[string]any{"type": "MemoryNote", "cell": "for-" + to, "content": "6.4"},
		}, true)
		if rec.Code != http.StatusOK {
			t.Fatalf("publish to %s: %d %s", to, rec.Code, rec.Body.String())
		}
	}

	for _, as := range []string{"person", "service"} {
		_, out := call(t, s, "/internal/v1/timeline", map[string]any{
			"tuple": tup("bob"), "as": as, "reading": "received",
		}, true)
		held, _ := out["held"].([]any)
		if len(held) != 2 {
			t.Errorf("reading as %s, bob holds %d of the 2 things addressed to his two actors", as, len(held))
		}
	}
}

// THE AUDIENCE SAYING SO IS NOT THE SAME AS SOMEBODY SEEING IT, and the test
// above asserts only the first. Shipped, that gap was total: a member sharing
// something with their subscription or their tenant reached NOBODY, while
// sharing the same object with a person worked -- because the reach gate asked
// a group route for an accepted governance decision, and no code path emits one
// for a share. The Add was in the log, the reduction reported the wider
// audience, and the timeline dropped it one layer later.
func TestSharingIntoAGroupReachesTheWholeScope(t *testing.T) {
	s := newServer(t)
	s.Members = threeMembers{}

	// Published to nobody: the object exists and reaches only its author, so the
	// share is the ONLY thing that can put it in front of anybody.
	_, out := call(t, s, "/internal/v1/publish", map[string]any{
		"tuple": tup("alice"), "as": "person",
		"object": map[string]any{"type": "MemoryNote", "cell": "soil-ph", "content": "6.4"},
	}, true)
	objID := out["activity"].(map[string]any)["object"].(map[string]any)["id"].(string)

	sees := func(who string) int {
		t.Helper()
		_, out := call(t, s, "/internal/v1/timeline", map[string]any{
			"tuple": tup(who), "reading": "received",
		}, true)
		claims, _ := out["claims"].([]any)
		return len(claims)
	}
	if n := sees("bob"); n != 0 {
		t.Fatalf("before the share bob already sees %d -- the test asserts nothing", n)
	}

	rec, _ := call(t, s, "/internal/v1/share", map[string]any{
		"tuple": tup("alice"), "as": "person", "groupsLicensed": true,
		"objectId": objID, "target": actor.SubscriptionGroupID("s1"),
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("share to group: %d %s", rec.Code, rec.Body.String())
	}

	// EVERY member of the scope, not merely one: a group is the whole set, and
	// carol is in it without ever having been named.
	for _, who := range []string{"bob", "carol"} {
		if n := sees(who); n != 1 {
			t.Errorf("%s sees %d claims after it was shared with their subscription", who, n)
		}
	}

	// AND NOTHING IS WAITING ON ANYBODY. `needsDecision` reads the audience, and an
	// Add's own `to` IS the group -- so it answers true for one. The pending reading
	// skips it only because an Add carries no object, which is an accident of shape
	// rather than a decision. A role holder watching a queue fill with entries they
	// cannot act on is the failure this pins.
	_, out = call(t, s, "/internal/v1/timeline", map[string]any{
		"tuple": tup("alice"), "reading": "pending",
	}, true)
	if q, _ := out["pending"].([]any); len(q) != 0 {
		t.Errorf("sharing queued %d decisions that nobody can take", len(q))
	}
}

// A share is not a way to overturn a decision. A governance Reject names the
// ACTIVITY it refused, so an Accept raised on behalf of a share would land on
// that same activity and undo it -- which is why the gate reads the ROUTE
// rather than having `handleShare` emit an acceptance.
func TestSharingDoesNotRevivePublicationTheScopeRejected(t *testing.T) {
	s := newServer(t)
	s.Members = threeMembers{}

	_, out := call(t, s, "/internal/v1/publish", map[string]any{
		"tuple": tup("alice"), "as": "person", "groupsLicensed": true,
		"to":     []string{actor.SubscriptionGroupID("s1")},
		"object": map[string]any{"type": "MemoryNote", "cell": "soil-ph", "content": "6.4"},
	}, true)
	act := out["activity"].(map[string]any)
	actID := act["id"].(string)
	objID := act["object"].(map[string]any)["id"].(string)

	// Whoever governs the scope turns it down, after it was accepted at source.
	rec, _ := call(t, s, "/internal/v1/decide", map[string]any{
		"tuple": tup("alice"), "as": "person", "governs": true,
		"activityId": actID, "accept": false,
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("decide: %d %s", rec.Code, rec.Body.String())
	}

	sees := func() int {
		t.Helper()
		_, out := call(t, s, "/internal/v1/timeline", map[string]any{
			"tuple": tup("bob"), "reading": "received",
		}, true)
		claims, _ := out["claims"].([]any)
		return len(claims)
	}
	if n := sees(); n != 0 {
		t.Fatalf("a rejected publication reaches bob: %d", n)
	}

	// Sharing it with a DIFFERENT person is ordinary and must still work; what it
	// must not do is put the rejected publication back in front of the scope.
	rec, _ = call(t, s, "/internal/v1/share", map[string]any{
		"tuple": tup("alice"), "as": "person",
		"objectId": objID, "target": actor.PersonID("carol"),
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("share to a person: %d %s", rec.Code, rec.Body.String())
	}
	if n := sees(); n != 0 {
		t.Errorf("bob sees %d after a share to somebody else revived a rejected publication", n)
	}
}

// A Remove takes back what an Add granted. Without this a member could unshare
// and the recipient would go on reading it.
func TestUnsharingTakesItBack(t *testing.T) {
	s := newServer(t)
	s.Members = threeMembers{}

	_, out := call(t, s, "/internal/v1/publish", map[string]any{
		"tuple": tup("alice"), "as": "person",
		"object": map[string]any{"type": "MemoryNote", "cell": "soil-ph", "content": "6.4"},
	}, true)
	objID := out["activity"].(map[string]any)["object"].(map[string]any)["id"].(string)

	bobSees := func() int {
		t.Helper()
		_, out := call(t, s, "/internal/v1/timeline", map[string]any{
			"tuple": tup("bob"), "reading": "received",
		}, true)
		c, _ := out["claims"].([]any)
		h, _ := out["held"].([]any)
		return len(c) + len(h)
	}

	for _, undo := range []bool{false, true} {
		rec, _ := call(t, s, "/internal/v1/share", map[string]any{
			"tuple": tup("alice"), "as": "person",
			"objectId": objID, "target": actor.ServiceID("bob"), "undo": undo,
		}, true)
		if rec.Code != http.StatusOK {
			t.Fatalf("share(undo=%v): %d", undo, rec.Code)
		}
	}
	if n := bobSees(); n != 0 {
		t.Errorf("bob still reads a memory that was unshared: %d", n)
	}
}
