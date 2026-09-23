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
	// shared is who a SHARE added to an object after it was published, per
	// object id. An Add carries no object of its own -- only the id it widens
	// and the new addressee -- so an activity's own `to` is not the whole
	// audience, and reading it as though it were is what made a share reach
	// nobody.
	shared map[string]map[string]bool
}

func newViewer(t actor.Tuple, acts []activity.Activity) viewer {
	return viewer{
		me:       actor.PersonID(t.UserAccID),
		mine:     actor.ServiceID(t.UserAccID),
		admitted: admissions(acts),
		governed: governanceDecisions(acts),
		shared:   sharedAddressees(acts),
	}
}

// admittedByMe is admitted BY THIS MEMBER, not by anybody. One recipient
// accepting must not clear another recipient's hold.
func (v viewer) admittedByMe(activityID string) bool {
	return v.admitted[activityID][v.me] || v.admitted[activityID][v.mine]
}

// sharedAddressees collects what each Add granted and each Remove took back,
// per object id. Last one wins: a member may share and unshare the same person
// more than once.
func sharedAddressees(acts []activity.Activity) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, a := range acts {
		if a.Type != activity.Add && a.Type != activity.Remove {
			continue
		}
		if a.InReplyTo == "" || a.Target == "" {
			continue
		}
		if out[a.InReplyTo] == nil {
			out[a.InReplyTo] = map[string]bool{}
		}
		out[a.InReplyTo][a.Target] = a.Type == activity.Add
	}
	return out
}

// addressing is who an activity reaches, and BY WHICH OF THE TWO ROUTES. The
// routes are not interchangeable, which is why this is not one list of strings.
type addressing struct {
	// direct: this member, as either of their two actors -- whether the
	// activity said so itself or a later share added them.
	direct bool
	// ownGroup: a group in the activity's OWN `to`. A publication crossing into
	// a scope, which waits on whoever governs that scope.
	ownGroup bool
	// sharedGroup: a group a later Add put it in front of. Already vetted, by
	// the gate that let the Add through -- see `reach`.
	sharedGroup bool
}

// addressingOf reads both sources: where an activity was addressed, and
// wherever it has been shared since. One answer, so no caller has to remember
// the second -- and two fields, so no caller can forget they differ.
func (v viewer) addressingOf(a activity.Activity) addressing {
	var at addressing
	for _, addr := range a.Audience() {
		if addr == v.me || addr == v.mine {
			at.direct = true
		}
		if strings.HasPrefix(addr, "mangrove:group:") {
			at.ownGroup = true
		}
	}
	if a.Object == nil {
		return at
	}
	for addr, on := range v.shared[a.Object.ID] {
		if !on {
			continue
		}
		if addr == v.me || addr == v.mine {
			at.direct = true
		}
		if strings.HasPrefix(addr, "mangrove:group:") {
			at.sharedGroup = true
		}
	}
	return at
}

func (v viewer) reach(a activity.Activity) reachOf {
	if a.Actor == v.me || a.Actor == v.mine {
		return reachOwn
	}
	at := v.addressingOf(a)
	// Reaching somebody through a group the activity ADDRESSED takes an ACCEPTED
	// decision, not merely a decision. Reading this as "was decided" is what let a
	// Reject publish to the whole scope.
	accepted, decided := v.governed[a.ID]
	//
	// A GROUP REACHED BY A SHARE NEEDS NO SECOND DECISION, and requiring one is
	// the defect this distinction exists to fix. `handleShare` runs the same
	// `reach.Check` a publication does, so an Add naming a group MEANS its author
	// held the licence for that group -- the vetting a decision exists to obtain
	// has already happened, by the same person, at the moment they shared. It is
	// the identical argument `handlePublish` makes when it accepts at source.
	//
	// The symptom was exact and total: sharing something with a subscription or a
	// tenant reached NOBODY, while sharing the same thing with a person worked,
	// because only the group route asked for a decision no code path emits. The
	// Add was written, the audience widened, the reduction reported it -- and this
	// gate dropped it on the floor one layer later.
	//
	// AND THE FIX IS NOT TO EMIT AN ACCEPT FROM `handleShare`. A governance
	// decision names the ACTIVITY it decides, so an Accept raised by a share would
	// land on the original Create -- reversing any Reject already recorded against
	// it, and letting a share of a rejected publication publish it after all. The
	// route is what differs, so the route is what the gate reads.
	if !at.direct && !at.sharedGroup && !(at.ownGroup && decided && accepted) {
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

	if at.direct && !v.admittedByMe(a.ID) {
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
