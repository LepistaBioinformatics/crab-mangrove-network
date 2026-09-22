package mangrovelog

import (
	"testing"

	"github.com/LepistaBioinformatics/crab-mangrove-network/internal/activity"
	"github.com/LepistaBioinformatics/crab-mangrove-network/internal/actor"
)

func newStore(t *testing.T) (*actor.Store, *Log) {
	t.Helper()
	dir := t.TempDir()
	as, err := actor.NewStore(dir)
	if err != nil {
		t.Fatalf("actor store: %v", err)
	}
	lg, err := New(dir)
	if err != nil {
		t.Fatalf("log: %v", err)
	}
	return as, lg
}

func tuple(acc string) actor.Tuple {
	return actor.Tuple{TenantID: "t1", SubsAccID: "s1", Role: "alpha", UserAccID: acc}
}

// publish signs as acc's Service actor and appends.
func publish(t *testing.T, as *actor.Store, lg *Log, acc string, a activity.Activity) activity.Activity {
	t.Helper()
	_, svc, err := as.Ensure(tuple(acc))
	if err != nil {
		t.Fatalf("ensure %s: %v", acc, err)
	}
	a.Actor = svc.ID
	if a.To == nil {
		a.To = []string{}
	}
	if a.CC == nil {
		a.CC = []string{}
	}
	priv, err := as.PrivateKey(svc.ID)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	if err := activity.Sign(&a, priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := lg.Append("t1", "s1", a, as); err != nil {
		t.Fatalf("append: %v", err)
	}
	return a
}

func note(id, cell, content, published string) activity.Activity {
	return activity.Activity{
		ID:        id,
		Type:      activity.Create,
		Object:    &activity.Object{ID: "obj-" + id, Type: activity.MemoryNote, Cell: cell, Content: content},
		Published: published,
	}
}

// TestTwoAuthorsSameCellBothSurvive is the convergence guarantee. Reduction is
// keyed by (cell, author), so cross-author overwrite is unrepresentable rather
// than merely checked for. Without it, shared memory becomes an edit war.
func TestTwoAuthorsSameCellBothSurvive(t *testing.T) {
	as, lg := newStore(t)
	publish(t, as, lg, "alice", note("1", "soil-ph", "5.8", "2026-09-21T10:00:00Z"))
	publish(t, as, lg, "bob", note("2", "soil-ph", "6.4", "2026-09-21T11:00:00Z"))

	acts, err := lg.Read("t1", "s1")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	claims := Reduce(acts)["soil-ph"]
	if len(claims) != 2 {
		t.Fatalf("got %d claims on the cell, want both authors' claims to survive", len(claims))
	}
	seen := map[string]string{}
	for _, c := range claims {
		seen[c.Author] = c.Object.Content
	}
	if seen[actor.ServiceID("alice")] != "5.8" || seen[actor.ServiceID("bob")] != "6.4" {
		t.Errorf("claims were merged or overwritten: %v", seen)
	}
}

// Within one author, the latest write wins -- that half IS last-writer-wins.
func TestSameAuthorLatestWins(t *testing.T) {
	as, lg := newStore(t)
	publish(t, as, lg, "alice", note("1", "soil-ph", "5.8", "2026-09-21T10:00:00Z"))
	publish(t, as, lg, "alice", note("2", "soil-ph", "6.0", "2026-09-21T12:00:00Z"))

	acts, _ := lg.Read("t1", "s1")
	claims := Reduce(acts)["soil-ph"]
	if len(claims) != 1 {
		t.Fatalf("got %d claims, want 1 for a single author", len(claims))
	}
	if claims[0].Object.Content != "6.0" {
		t.Errorf("content = %q, want the later write", claims[0].Object.Content)
	}
}

// An out-of-order arrival must not let an older write win. Federation makes
// this normal, not exotic.
func TestOlderArrivalDoesNotWin(t *testing.T) {
	as, lg := newStore(t)
	publish(t, as, lg, "alice", note("1", "soil-ph", "new", "2026-09-21T12:00:00Z"))
	publish(t, as, lg, "alice", note("2", "soil-ph", "old", "2026-09-21T09:00:00Z"))

	acts, _ := lg.Read("t1", "s1")
	claims := Reduce(acts)["soil-ph"]
	if claims[0].Object.Content != "new" {
		t.Errorf("content = %q, want the later-published write to survive a late arrival", claims[0].Object.Content)
	}
}

func TestAppendRefusesAForgedSignature(t *testing.T) {
	as, lg := newStore(t)
	a := publish(t, as, lg, "alice", note("1", "soil-ph", "5.8", "2026-09-21T10:00:00Z"))

	// Same signature, different content.
	tampered := a
	obj := *a.Object
	obj.Content = "9.9"
	tampered.Object = &obj
	tampered.ID = "mangrove:act:tampered"

	if err := lg.Append("t1", "s1", tampered, as); err == nil {
		t.Fatal("appended a tampered activity; verification must be a precondition of the write")
	}
}

func TestAppendRefusesAnUnsignedActivity(t *testing.T) {
	as, lg := newStore(t)
	_, svc, _ := as.Ensure(tuple("alice"))
	a := note("1", "soil-ph", "5.8", "2026-09-21T10:00:00Z")
	a.Actor = svc.ID
	if err := lg.Append("t1", "s1", a, as); err == nil {
		t.Fatal("appended an unsigned activity")
	}
}

func TestAppendRefusesANonMangroveActor(t *testing.T) {
	as, lg := newStore(t)
	a := note("1", "soil-ph", "x", "2026-09-21T10:00:00Z")
	a.Actor = "https://mastodon.example/users/mallory"
	if err := lg.Append("t1", "s1", a, as); err == nil {
		t.Fatal("appended an activity from an identity this mangrove did not mint")
	}
}

// A shard nobody has written to is an empty log, not a failure. "Nothing shared
// yet" must never read as "the service is broken".
func TestMissingShardReadsEmpty(t *testing.T) {
	_, lg := newStore(t)
	acts, err := lg.Read("t9", "s9")
	if err != nil {
		t.Fatalf("a never-written shard errored: %v", err)
	}
	if len(acts) != 0 {
		t.Fatalf("got %d activities from an empty shard", len(acts))
	}
}

// Evidence is a count of endorsers, never a verdict, and an Undo withdraws one.
func TestEvidenceIsWeightNotVerdict(t *testing.T) {
	as, lg := newStore(t)
	a := publish(t, as, lg, "alice", note("1", "soil-ph", "5.8", "2026-09-21T10:00:00Z"))

	publish(t, as, lg, "bob", activity.Activity{ID: "l1", Type: activity.Like, InReplyTo: a.Object.ID, Published: "2026-09-21T11:00:00Z"})
	publish(t, as, lg, "carol", activity.Activity{ID: "l2", Type: activity.Like, InReplyTo: a.Object.ID, Published: "2026-09-21T11:01:00Z"})
	// Liking twice still weighs one.
	publish(t, as, lg, "carol", activity.Activity{ID: "l3", Type: activity.Like, InReplyTo: a.Object.ID, Published: "2026-09-21T11:02:00Z"})

	acts, _ := lg.Read("t1", "s1")
	claims := Reduce(acts)["soil-ph"]
	if len(claims) != 1 || claims[0].Evidence != 2 {
		t.Fatalf("evidence = %d, want 2 distinct endorsers", claims[0].Evidence)
	}

	publish(t, as, lg, "bob", activity.Activity{
		ID: "u1", Type: activity.Undo, UndoType: activity.Like,
		InReplyTo: a.Object.ID, Published: "2026-09-21T12:00:00Z",
	})
	acts, _ = lg.Read("t1", "s1")
	if got := Reduce(acts)["soil-ph"][0].Evidence; got != 1 {
		t.Errorf("evidence after Undo = %d, want 1", got)
	}
}

// Undoing a READ RECEIPT must not withdraw an ENDORSEMENT of the same object.
// They are different verbs; an Undo that does not name which one it withdraws
// is ambiguous, and guessing costs a signal nobody asked to lose.
func TestUndoingAReadDoesNotWithdrawALike(t *testing.T) {
	as, lg := newStore(t)
	a := publish(t, as, lg, "alice", note("1", "soil-ph", "5.8", "2026-09-21T10:00:00Z"))

	publish(t, as, lg, "bob", activity.Activity{ID: "l1", Type: activity.Like, InReplyTo: a.Object.ID, Published: "2026-09-21T11:00:00Z"})
	publish(t, as, lg, "bob", activity.Activity{ID: "r1", Type: activity.Read, InReplyTo: a.Object.ID, Published: "2026-09-21T11:30:00Z"})

	// Bob withdraws only the receipt.
	publish(t, as, lg, "bob", activity.Activity{
		ID: "u1", Type: activity.Undo, UndoType: activity.Read,
		InReplyTo: a.Object.ID, Published: "2026-09-21T12:00:00Z",
	})

	acts, _ := lg.Read("t1", "s1")
	if got := Reduce(acts)["soil-ph"][0].Evidence; got != 1 {
		t.Errorf("evidence = %d after undoing a READ; the endorsement must survive", got)
	}
}

// The reduction orders by instant, not by byte.
//
// RFC 3339 admits a fractional part that may be absent and an offset that may
// be `Z` or numeric, and both break a lexicographic comparison: '.' (0x2E)
// sorts before 'Z' (0x5A), so "10:00:00.5Z" < "10:00:00Z" as strings while the
// first is the LATER instant. Last-writer-wins rests entirely on this ordering.
func TestOrderingIsByInstantNotByString(t *testing.T) {
	// Guard the premise, so this test still means something if Go ever changes.
	if !("2026-09-21T10:00:00.5Z" < "2026-09-21T10:00:00Z") {
		t.Skip("byte ordering no longer inverts these; the risk this pins is gone")
	}

	as, lg := newStore(t)
	publish(t, as, lg, "alice", note("1", "soil-ph", "whole second", "2026-09-21T10:00:00Z"))
	publish(t, as, lg, "alice", note("2", "soil-ph", "half a second later", "2026-09-21T10:00:00.5Z"))

	acts, _ := lg.Read("t1", "s1")
	claims := Reduce(acts)["soil-ph"]
	if len(claims) != 1 {
		t.Fatalf("got %d claims for one author", len(claims))
	}
	if claims[0].Object.Content != "half a second later" {
		t.Errorf("content = %q; the sub-second write is the later instant and must win", claims[0].Object.Content)
	}
}

// The same hazard from the other direction: a numeric offset naming an EARLIER
// instant than a `Z` timestamp that sorts below it.
func TestOrderingHandlesOffsets(t *testing.T) {
	as, lg := newStore(t)
	// 09:30:00Z, written as 10:30 in +01:00 -- earlier than 10:00:00Z by instant,
	// later by string.
	publish(t, as, lg, "alice", note("1", "soil-ph", "later", "2026-09-21T10:00:00Z"))
	publish(t, as, lg, "alice", note("2", "soil-ph", "earlier", "2026-09-21T10:30:00+01:00"))

	acts, _ := lg.Read("t1", "s1")
	if got := Reduce(acts)["soil-ph"][0].Object.Content; got != "later" {
		t.Errorf("content = %q; 10:30+01:00 is 09:30Z and must not beat 10:00Z", got)
	}
}

// A Delete tombstones; the log keeps the history. Nothing is erased, because
// nothing CAN be erased from replicas already delivered.
func TestDeleteTombstonesAndKeepsHistory(t *testing.T) {
	as, lg := newStore(t)
	publish(t, as, lg, "alice", note("1", "soil-ph", "5.8", "2026-09-21T10:00:00Z"))
	publish(t, as, lg, "alice", activity.Activity{
		ID: "d1", Type: activity.Delete, Published: "2026-09-21T13:00:00Z",
		Object: &activity.Object{ID: "obj-1", Type: activity.MemoryNote, Cell: "soil-ph"},
	})

	acts, _ := lg.Read("t1", "s1")
	if len(acts) != 2 {
		t.Fatalf("log holds %d lines, want the Delete appended rather than the Create removed", len(acts))
	}
	claims := Reduce(acts)["soil-ph"]
	if len(claims) != 1 || !claims[0].Deleted {
		t.Fatalf("claim not tombstoned: %+v", claims)
	}
}
