package mangrovelog

import (
	"testing"

	"github.com/LepistaBioinformatics/crab-mangrove-network/internal/activity"
)

// WHAT HAPPENED, said by the log rather than worked out by whoever reads it.
//
// A client could count an author's writes on a cell -- but the activities it is
// given are filtered to what that reader may see, so one member would count two
// and another one, and the same card would read "updated" to the first and
// "published" to the second. The reduction has the whole log and says it once.
func TestTheReductionNamesTheWinningVerb(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind activity.Type
		want string
	}{
		{"a first write is a publication", activity.Create, "published"},
		{"a rewrite of a cell the author holds", activity.Update, "updated"},
		{"a tombstone", activity.Delete, "revoked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acts := []activity.Activity{{
				Type:      tc.kind,
				Actor:     "mangrove:actor:alice:service",
				Object:    &activity.Object{ID: "o1", Cell: "soil-ph"},
				Published: "2026-09-22T10:00:00Z",
			}}
			claims := Reduce(acts)["soil-ph"]
			if len(claims) != 1 {
				t.Fatalf("want one claim, got %d", len(claims))
			}
			if claims[0].Action != tc.want {
				t.Errorf("action = %q, want %q", claims[0].Action, tc.want)
			}
		})
	}
}

// `Deleted` KEEPS ANSWERING on its own. A reader that predates the verb still
// has the tombstone, which is the only one of the three that changes what a card
// may be used for -- so the two must not be able to disagree.
func TestTheTombstoneAndTheVerbAgree(t *testing.T) {
	acts := []activity.Activity{
		{
			Type:      activity.Create,
			Actor:     "mangrove:actor:alice:service",
			Object:    &activity.Object{ID: "o1", Cell: "soil-ph"},
			Published: "2026-09-22T10:00:00Z",
		},
		{
			Type:      activity.Delete,
			Actor:     "mangrove:actor:alice:service",
			Object:    &activity.Object{ID: "o1", Cell: "soil-ph"},
			Published: "2026-09-22T11:00:00Z",
		},
	}
	c := Reduce(acts)["soil-ph"][0]
	if !c.Deleted || c.Action != "revoked" {
		t.Errorf("deleted=%v action=%q; the tombstone and the verb must say the same thing",
			c.Deleted, c.Action)
	}
}

// An author who writes the same cell twice leaves ONE claim, and it is the later
// write that survives -- so the verb a reader sees is the later one's.
func TestTheLaterWritesVerbIsTheOneThatSurvives(t *testing.T) {
	acts := []activity.Activity{
		{
			Type:      activity.Create,
			Actor:     "mangrove:actor:alice:service",
			Object:    &activity.Object{ID: "o1", Cell: "soil-ph"},
			Published: "2026-09-22T10:00:00Z",
		},
		{
			Type:      activity.Update,
			Actor:     "mangrove:actor:alice:service",
			Object:    &activity.Object{ID: "o2", Cell: "soil-ph"},
			Published: "2026-09-22T12:00:00Z",
		},
	}
	claims := Reduce(acts)["soil-ph"]
	if len(claims) != 1 {
		t.Fatalf("want one claim for one author on one cell, got %d", len(claims))
	}
	if claims[0].Action != "updated" {
		t.Errorf("action = %q, want the later write's verb", claims[0].Action)
	}
}
