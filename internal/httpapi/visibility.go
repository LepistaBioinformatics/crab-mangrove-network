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
	// reachVisible: theirs to read -- addressed at them, or reaching them
	// through a group whose publication a governing role has accepted.
	//
	// THERE USED TO BE A FOURTH, `reachHeld`: addressed at somebody and not yet
	// admitted by them, described as "visible to the human, not yet in their
	// agent's memory". It never was that. The held item was returned WITH ITS
	// OBJECT, and the viewer is built from the tuple and never from the calling
	// actor, so the agent's `mangrove_timeline` got the same bytes the person's
	// did -- and the tool's own description told it so out loud. On top of
	// which the agent had a `mangrove_admit` of its own and could clear the
	// hold unasked.
	//
	// What actually keeps shared memory out of an agent is AD-031: merging a
	// fragment into the graph is a person's act, in their interface, and that
	// is untouched. This was a gate in the comments only, so it is gone rather
	// than left half-enforced. Read receipts carry what it was really being
	// read as -- whether this member has opened the thing yet.
	reachVisible
)

// viewer answers reachOf for one member over one shard. It is built once per
// request because admissions and governance decisions are themselves derived
// from the whole shard.
type viewer struct {
	me, mine string
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
		governed: governanceDecisions(acts),
		shared:   sharedAddressees(acts),
	}
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

	// A TOMBSTONE USED TO NEED SAYING HERE. While there was a hold, a Delete
	// addressed at somebody sat in it waiting for an admission nobody gives to
	// a withdrawal, while the claim it withdrew went on reading as live -- a
	// shipped defect, and the reason this function was extracted at all. With
	// the hold gone the exception has nothing left to be an exception to, which
	// is the good kind of deletion: the case cannot come back because the state
	// it depended on no longer exists.
	return reachVisible
}

// reachable is every activity in the shard this member can see at all, in any
// of the ways. It is what a question about CONTENT -- rather than about one
// reading -- has to start from, because a member may legitimately open a file
// they published and one they were sent.
func (v viewer) reachable(acts []activity.Activity) []activity.Activity {
	out := make([]activity.Activity, 0, len(acts))
	for _, a := range acts {
		if v.reach(a) != reachNone {
			out = append(out, a)
		}
	}
	return out
}
