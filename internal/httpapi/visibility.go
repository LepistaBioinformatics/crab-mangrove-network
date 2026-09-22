package httpapi

import (
	"strings"

	"github.com/LepistaBioinformatics/crab-mangrove-network/internal/activity"
	"github.com/LepistaBioinformatics/crab-mangrove-network/internal/actor"
)

// Who sees what, in one place.
//
// This decision used to live inline in handleTimeline's `received` arm, which
// was fine while the timeline was the only thing asking. It is not any more: a
// blob fetch has to answer the same question, and a SECOND implementation of it
// would drift from the first silently -- the symptom being content that stays
// readable after the post carrying it was revoked.
//
// So the rule is a function, the timeline calls it, and anything else that needs
// to know calls the same one.

// reachOf is how an activity reaches one member. Exactly one value applies, and
// authorship wins: an activity you wrote is yours, whoever else it was addressed
// to.
type reachOf int

const (
	// reachNone: not addressed to this member in any way they can act on.
	reachNone reachOf = iota
	// reachOwn: this member wrote it, as either of their two actors.
	reachOwn
	// reachHeld: addressed AT them and not yet admitted BY them. Visible to the
	// human, not yet in their agent's memory.
	reachHeld
	// reachVisible: theirs to read -- admitted, or reaching them through a group
	// whose publication a governing role has accepted.
	reachVisible
)

// viewer answers reachOf for one member over one shard. It is built once per
// request because admissions and governance decisions are themselves derived
// from the whole shard.
type viewer struct {
	me, mine string
	admitted map[string]map[string]bool
	governed map[string]bool
}

func newViewer(t actor.Tuple, acts []activity.Activity) viewer {
	return viewer{
		me:       actor.PersonID(t.UserAccID),
		mine:     actor.ServiceID(t.UserAccID),
		admitted: admissions(acts),
		governed: governanceDecisions(acts),
	}
}

// admittedByMe is admitted BY THIS MEMBER, not by anybody. One recipient
// accepting must not clear another recipient's hold.
func (v viewer) admittedByMe(activityID string) bool {
	return v.admitted[activityID][v.me] || v.admitted[activityID][v.mine]
}

func (v viewer) reach(a activity.Activity) reachOf {
	if a.Actor == v.me || a.Actor == v.mine {
		return reachOwn
	}
	direct := false
	viaGroup := false
	for _, addr := range a.Audience() {
		if addr == v.me || addr == v.mine {
			direct = true
		}
		if strings.HasPrefix(addr, "mangrove:group:") {
			viaGroup = true
		}
	}
	if !direct && !(viaGroup && v.governed[a.ID]) {
		return reachNone
	}

	// A TOMBSTONE IS NEVER HELD. The hold exists so that content does not enter
	// an agent's memory before its human takes it; a Delete is not content, and
	// nobody admits a withdrawal. Held, it would sit waiting for an admission
	// that never comes while the claim it withdraws went on reading as live --
	// which is exactly the shipped defect this rule was extracted to stop
	// happening twice.
	if a.Type == activity.Delete {
		return reachVisible
	}

	if direct && !v.admittedByMe(a.ID) {
		return reachHeld
	}
	return reachVisible
}

// reachable is every activity in the shard this member can see at all, in any
// of the three ways. It is what a question about CONTENT -- rather than about
// one reading -- has to start from, because a member may legitimately open a
// file they published, one they were sent and admitted, and one still held.
func (v viewer) reachable(acts []activity.Activity) []activity.Activity {
	out := make([]activity.Activity, 0, len(acts))
	for _, a := range acts {
		if v.reach(a) != reachNone {
			out = append(out, a)
		}
	}
	return out
}
