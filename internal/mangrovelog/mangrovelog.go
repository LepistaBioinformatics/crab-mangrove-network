// Package mangrovelog is the memory: an append-only log of signed activities, and
// the reduction that turns it back into readable state.
//
// MEMORY IS A LOG, NOT A DOCUMENT. Update and Delete append; they never
// overwrite. That is what makes divergence survivable -- and divergence is a
// normal state here, not an error to prevent. Two readers may hold different
// prefixes of the same log and still converge, which is also what keeps
// cross-deployment federation an extension later rather than a rewrite.
//
// REDUCTION IS LAST-WRITER-WINS PER AUTHOR, NEVER BY GLOBAL TIMESTAMP. The map
// is keyed by (cell, author): each author has authority over their own claims
// about a cell, and nobody's write overwrites anybody else's. Cross-author
// overwrite is not prevented by a check -- it is UNREPRESENTABLE, because there
// is nowhere in the data structure to put it. Without this, shared memory
// degenerates into an edit war.
//
// TRUST IS WEIGHT OF EVIDENCE, NEVER A TRUTH PREDICATE. A claim carries a count
// of the actors who endorsed it (Like). Nothing anywhere marks a claim true or
// false, and no reduction resolves two authors' disagreement into one answer.
// Presenting both, with their evidence, is the answer.
//
// The file format is JSONL, one activity per line, matching what
// crab-shell-proxy's memory graph already writes. Append-only is the natural
// shape of an append-only file.
package mangrovelog

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/LepistaBioinformatics/crab-mangrove-network/internal/activity"
	"github.com/LepistaBioinformatics/crab-mangrove-network/internal/actor"
)

// Keys resolves the verification key for an author. actor.Store satisfies it.
type Keys interface {
	PublicKey(actorID string) (ed25519.PublicKey, error)
}

// Log is sharded by (tenant, subscription): the widest unit any single read
// needs, which keeps one subscription's volume off another's read path.
type Log struct{ root string }

func New(root string) (*Log, error) {
	if err := os.MkdirAll(filepath.Join(root, "log"), 0o700); err != nil {
		return nil, fmt.Errorf("mangrovelog: %w", err)
	}
	return &Log{root: root}, nil
}

func (l *Log) shard(tenantID, subsAccID string) string {
	return filepath.Join(l.root, "log", sanitize(tenantID), sanitize(subsAccID)+".jsonl")
}

func sanitize(s string) string {
	r := strings.NewReplacer("/", "-", "\\", "-", "..", "-", string(os.PathSeparator), "-")
	out := strings.TrimSpace(r.Replace(s))
	if out == "" || out == "." {
		return "unknown"
	}
	return out
}

// Append verifies the signature and then writes one line. Verification is a
// PRECONDITION, not a later audit: an unverified line never lands, so anything
// read back out of the log was signed by the actor it names.
func (l *Log) Append(tenantID, subsAccID string, a activity.Activity, k Keys) error {
	if !a.Type.Known() {
		return fmt.Errorf("mangrovelog: unknown activity type %q", a.Type)
	}
	if actor.AccIDOf(a.Actor) == "" {
		return fmt.Errorf("mangrovelog: %q is not a mangrove actor id", a.Actor)
	}
	pub, err := k.PublicKey(a.Actor)
	if err != nil {
		return fmt.Errorf("mangrovelog: resolve key for %s: %w", a.Actor, err)
	}
	if err := activity.Verify(a, pub); err != nil {
		return err
	}

	p := l.shard(tenantID, subsAccID)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("mangrovelog: %w", err)
	}
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("mangrovelog: open shard: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("mangrovelog: append: %w", err)
	}
	return nil
}

// Read returns every activity in a shard, in write order. A missing shard is an
// empty log, not an error: a subscription nobody has published in yet is a
// normal state and must not read as a failure.
func (l *Log) Read(tenantID, subsAccID string) ([]activity.Activity, error) {
	f, err := os.Open(l.shard(tenantID, subsAccID))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("mangrovelog: open shard: %w", err)
	}
	defer f.Close()

	var out []activity.Activity
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var a activity.Activity
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			return nil, fmt.Errorf("mangrovelog: decode line: %w", err)
		}
		out = append(out, a)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("mangrovelog: scan: %w", err)
	}
	return out, nil
}

// newer reports whether a supersedes prev for the same (cell, author).
//
// IT PARSES RATHER THAN COMPARING STRINGS. `published` is an RFC 3339 instant,
// and RFC 3339 has two properties that make lexicographic comparison wrong: a
// fractional part that may be present or absent, and an offset that may be `Z`
// or `+01:00`. Either one inverts the order for some pair of real timestamps.
// This is the ordering the whole last-writer-wins reduction rests on, so it is
// done on time.Time.
//
// An unparseable timestamp loses to a parseable one, and two equally
// unparseable ones fall back to a string comparison so the result stays
// deterministic instead of depending on log order.
func newer(a, prev activity.Activity) bool {
	at, aErr := time.Parse(time.RFC3339, a.Published)
	pt, pErr := time.Parse(time.RFC3339, prev.Published)
	switch {
	case aErr == nil && pErr == nil:
		if at.Equal(pt) {
			// A genuine tie: pick deterministically rather than by arrival.
			return a.ID > prev.ID
		}
		return at.After(pt)
	case aErr == nil:
		return true
	case pErr == nil:
		return false
	default:
		return a.Published > prev.Published
	}
}

// Claim is one author's current position on one cell.
type Claim struct {
	Cell      string          `json:"cell"`
	Author    string          `json:"author"`
	Object    activity.Object `json:"object"`
	Published string          `json:"published"`
	Deleted   bool            `json:"deleted"`
	// Evidence counts distinct actors who endorsed this claim with Like.
	// It is a weight, not a verdict. Nothing reads it as truth.
	Evidence int `json:"evidence"`
	// Audience is the addressing of the winning activity, so a reader can see
	// how far this claim travelled.
	Audience []string `json:"audience"`
	// ReadBy is every actor that emitted a Read receipt against this claim's
	// object, sorted. AS2's Read is "the actor has read the object", and the
	// react endpoint has emitted it since before anything consumed it -- this
	// is the consumer.
	//
	// ACTOR IDS AND NOT A COUNT, because who read it is the question and the
	// two actors of one member are different answers. A person's receipt is
	// that member reading their mail; their agent's is a turn passing over it,
	// which is not something to tell a sender their colleague did.
	//
	// It is keyed on the OBJECT id, like Evidence beside it, so an Update keeps
	// the receipts the Create earned -- somebody who read a memory has read it,
	// and a correction by its author does not make that untrue.
	ReadBy []string `json:"readBy,omitempty"`
	// Read is "the reader this response was built for has opened it", and it is
	// what a RECIPIENT is told. ReadBy goes to the author, who addressed the
	// thing and may know who opened it; telling every recipient who else had
	// would be a different feature nobody asked for. The reduction fills ReadBy
	// and the handler collapses it -- one of the two is always nil on the wire.
	Read bool `json:"read,omitempty"`
	// Action is the winning activity's verb, in the vocabulary a reader speaks:
	// "published", "updated" or "revoked".
	//
	// SAID HERE AND NOT DERIVED BY THE READER, and that is the whole reason it
	// exists. A client could count an author's writes on a cell -- but the
	// activities it is given are filtered to what that reader may see, so one
	// member would count two and another one, and the same card would read
	// "updated" to the first and "published" to the second. The log knows, once.
	//
	// `Deleted` is not replaced by it. A reader that predates this field still
	// has the tombstone, which is the only one of the three that changes what a
	// card may be used for.
	Action string `json:"action"`
}

// verb names an activity in the vocabulary a reader speaks.
//
// Anything that is not an Update or a Delete reads as a publication, including
// the activity types this reduction does not fold: a claim exists because
// SOMETHING wrote it, and "published" is the truthful default for a write whose
// verb we have no better word for.
func verb(t activity.Type) string {
	switch t {
	case activity.Update:
		return "updated"
	case activity.Delete:
		return "revoked"
	default:
		return "published"
	}
}

// audienceWith is who a claim reaches: where it was published, plus wherever it
// has been shared since, less whatever a Remove took back.
//
// The added names are sorted, so two readers of one log render the same page --
// the same reason Reduce sorts its claims at the bottom.
func audienceWith(a activity.Activity, shares map[string]bool) []string {
	out := a.Audience()
	if len(shares) == 0 {
		return out
	}
	have := make(map[string]bool, len(out))
	for _, addr := range out {
		have[addr] = true
	}
	added := make([]string, 0, len(shares))
	for addr, on := range shares {
		if on && !have[addr] {
			added = append(added, addr)
		}
	}
	sort.Strings(added)
	return append(out, added...)
}

// Reduce folds a log into claims, keyed by cell and then by author.
//
// The two-level map IS the guarantee. There is no code path that lets one
// author's entry replace another's, because they do not share a slot.
func Reduce(acts []activity.Activity) map[string][]Claim {
	type key struct{ cell, author string }
	latest := map[key]activity.Activity{}
	// Endorsements are counted per (object id, endorsing actor) so that one
	// actor liking the same object twice still weighs one.
	endorsed := map[string]map[string]bool{}
	// Receipts, counted the same way and for the same reason: one actor reading
	// the same object twice has read it once.
	readBy := map[string]map[string]bool{}
	// Addressees a share ADDED after publication, per object id, and whether
	// they are still on it.
	shared := map[string]map[string]bool{}

	for _, a := range acts {
		switch a.Type {
		case activity.Create, activity.Update, activity.Delete:
			if a.Object == nil {
				continue
			}
			k := key{cell: a.Object.Cell, author: a.Actor}
			if prev, ok := latest[k]; !ok || newer(a, prev) {
				latest[k] = a
			}
		case activity.Like:
			if a.InReplyTo == "" {
				continue
			}
			if endorsed[a.InReplyTo] == nil {
				endorsed[a.InReplyTo] = map[string]bool{}
			}
			endorsed[a.InReplyTo][a.Actor] = true
		case activity.Read:
			if a.InReplyTo == "" {
				continue
			}
			if readBy[a.InReplyTo] == nil {
				readBy[a.InReplyTo] = map[string]bool{}
			}
			readBy[a.InReplyTo][a.Actor] = true
		case activity.Add, activity.Remove:
			// A SHARE WIDENS AN OBJECT THAT ALREADY EXISTS. It carries no object
			// of its own -- only the id in InReplyTo and the new addressee -- so
			// this loop used to skip it entirely and a shared memory reached
			// nobody: the reduction went on describing the audience the Create
			// had, and every reader asked the reduction.
			//
			// Remove withdraws what Add granted. Last one wins, because a member
			// may share and unshare the same person more than once.
			if a.InReplyTo == "" || a.Target == "" {
				continue
			}
			if shared[a.InReplyTo] == nil {
				shared[a.InReplyTo] = map[string]bool{}
			}
			shared[a.InReplyTo][a.Target] = a.Type == activity.Add

		case activity.Undo:
			// ONLY an Undo that says it withdraws a Like touches the evidence
			// count. Undoing a Read receipt must not silently remove an
			// endorsement of the same object -- they are different verbs and
			// an Undo that does not name one is ambiguous, so it is ignored
			// here rather than guessed at.
			if a.InReplyTo == "" {
				continue
			}
			switch a.UndoType {
			case activity.Like:
				if endorsed[a.InReplyTo] != nil {
					delete(endorsed[a.InReplyTo], a.Actor)
				}
			case activity.Read:
				// Marking something unread again. The comment above is why this
				// has to name the verb: without UndoType the two are one
				// activity and this would withdraw an endorsement instead.
				if readBy[a.InReplyTo] != nil {
					delete(readBy[a.InReplyTo], a.Actor)
				}
			}
		}
	}

	out := map[string][]Claim{}
	for k, a := range latest {
		c := Claim{
			Cell:      k.cell,
			Author:    k.author,
			Published: a.Published,
			Deleted:   a.Type == activity.Delete,
			Action:    verb(a.Type),
			Evidence:  len(endorsed[a.Object.ID]),
			ReadBy:    sortedActors(readBy[a.Object.ID]),
			Audience:  audienceWith(a, shared[a.Object.ID]),
		}
		if a.Object != nil {
			c.Object = *a.Object
		}
		out[k.cell] = append(out[k.cell], c)
	}
	// Stable order so two readers of the same log render the same page.
	for cell := range out {
		claims := out[cell]
		sort.Slice(claims, func(i, j int) bool { return claims[i].Author < claims[j].Author })
		out[cell] = claims
	}
	return out
}

// sortedActors is the stable rendering of a receipt set. Nil for none rather
// than an empty slice, so `omitempty` keeps it off the wire for the overwhelming
// majority of claims nobody has opened yet.
func sortedActors(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
