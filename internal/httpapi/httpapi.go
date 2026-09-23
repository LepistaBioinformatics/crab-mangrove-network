// Package httpapi is the mangrove's only surface, and it has exactly one caller.
//
// crab-shell-proxy authenticates every agent and every human before the mangrove
// hears about them, so the mangrove does not verify JWTs, does not decode mycelium
// profiles, and has no public route. It trusts one caller, proven by a shared
// secret, and that caller hands it an ALREADY-VERIFIED workspace tuple.
//
// THE ACTOR IS NEVER READ FROM THE REQUEST BODY. Every handler derives it from
// the tuple. A body field naming an actor would be a client-declared identity,
// which is the thing this whole stack refuses -- crab-shell-proxy takes the
// account from the gateway's profile header and the ganglion takes the project
// from a turn-context header rather than a tool argument, for the same reason.
//
// TWO FIELDS IN THE BODY ARE TRUSTED, AND BOTH ARE THE PROXY'S TO SET:
//
//	as             -- "person" for a human acting in the webapp, "service" for
//	                  an agent acting in a turn. It selects which of the
//	                  workspace's two actors signs.
//	tenantLicensed -- whether the caller's real mycelium profile licenses the
//	                  tenant. The proxy sets it ONLY on a request that arrived
//	                  with a profile, never from an agent's MCP token, which
//	                  cannot prove it. See internal/reach.
//
// If the proxy is compromised, so is the mangrove. That is stated rather than
// defended against: the proxy already runs as root with a Docker socket and
// reads every workspace, so a trust boundary between them would be decorative.
package httpapi

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/LepistaBioinformatics/crab-mangrove-network/internal/activity"
	"github.com/LepistaBioinformatics/crab-mangrove-network/internal/actor"
	"github.com/LepistaBioinformatics/crab-mangrove-network/internal/blob"
	"github.com/LepistaBioinformatics/crab-mangrove-network/internal/mangrovelog"
	"github.com/LepistaBioinformatics/crab-mangrove-network/internal/reach"
)

type Server struct {
	Actors  *actor.Store
	Log     *mangrovelog.Log
	Blobs   *blob.Store
	Members reach.Members
	Token   string
	Now     func() time.Time
	Logger  *slog.Logger
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

// base is the part of every request body that is about the caller rather than
// the operation.
type base struct {
	Tuple          actor.Tuple `json:"tuple"`
	As             string      `json:"as"`
	TenantLicensed bool        `json:"tenantLicensed"`
	GroupsLicensed bool        `json:"groupsLicensed"`
}

// licences reads the two widening licences off a request. They travel together
// because they are answered by one identity: only crab-shell-proxy may set
// either, and only from a mycelium profile the gateway injected.
func (b base) licences() reach.Options {
	return reach.Options{
		TenantLicensed: b.TenantLicensed,
		GroupsLicensed: b.GroupsLicensed,
	}
}

// signer resolves which of the workspace's two actors is acting, provisioning
// both on first use.
func (s *Server) signer(b base) (*actor.Actor, *actor.Actor, error) {
	person, service, err := s.Actors.Ensure(b.Tuple)
	if err != nil {
		return nil, nil, err
	}
	if strings.EqualFold(b.As, "person") {
		return person, person, nil
	}
	return service, person, nil
}

func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("POST /internal/v1/blob", s.auth(s.handleBlobPut))
	mux.Handle("POST /internal/v1/blob/fetch", s.auth(s.handleBlobGet))
	mux.Handle("POST /internal/v1/publish", s.auth(s.handlePublish))
	mux.Handle("POST /internal/v1/share", s.auth(s.handleShare))
	mux.Handle("POST /internal/v1/react", s.auth(s.handleReact))
	mux.Handle("POST /internal/v1/admit", s.auth(s.handleAdmit))
	mux.Handle("POST /internal/v1/decide", s.auth(s.handleDecide))
	mux.Handle("POST /internal/v1/revoke", s.auth(s.handleRevoke))
	mux.Handle("POST /internal/v1/timeline", s.auth(s.handleTimeline))
	return mux
}

// auth is a constant-time bearer check. The mangrove refuses to boot without a
// token (see cmd), so this can never degrade into an open endpoint.
func (s *Server) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if s.Token == "" || !hmac.Equal([]byte(got), []byte(s.Token)) {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	})
}

// readJSON decodes a request body. Bounded, because every caller here is
// describing an operation rather than carrying content -- the bytes go through
// the blob route, which streams.
func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// writeRefusal turns a reachability refusal into a 403 that NAMES the
// addressee. A caller that cannot see which entry failed cannot fix it.
func writeRefusal(w http.ResponseWriter, err error) bool {
	var ref *reach.Refusal
	if errors.As(err, &ref) {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":     ref.Error(),
			"addressee": ref.Addressee,
			"reason":    ref.Reason,
			// Stated explicitly so a client never renders a partial success.
			"delivered": false,
		})
		return true
	}
	return false
}

func newID(prefix string) string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return prefix + hex.EncodeToString(b[:])
}

// emit signs an activity as the given actor and appends it. Signing and
// appending are one step so that nothing unsigned can reach the log by a path
// that forgot to sign.
func (s *Server) emit(t actor.Tuple, author *actor.Actor, a *activity.Activity) error {
	a.Actor = author.ID
	if a.ID == "" {
		a.ID = newID("mangrove:act:")
	}
	if a.Published == "" {
		a.Published = s.now().Format(activity.TimeFormat)
	}
	if a.To == nil {
		a.To = []string{}
	}
	if a.CC == nil {
		a.CC = []string{}
	}
	priv, err := s.Actors.PrivateKey(author.ID)
	if err != nil {
		return err
	}
	if err := activity.Sign(a, priv); err != nil {
		return err
	}
	return s.Log.Append(t.TenantID, t.SubsAccID, *a, s.Actors)
}

// ---------------------------------------------------------------- publish

type publishReq struct {
	base
	Object activity.Object `json:"object"`
	To     []string        `json:"to"`
}

func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request) {
	var req publishReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed body")
		return
	}
	author, _, err := s.signer(req.base)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// THE GATE. Every widening verb passes here and nowhere else.
	if err := reach.Check(req.Tuple, s.Members, req.To, req.licences()); err != nil {
		if writeRefusal(w, err) {
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if req.Object.Cell == "" {
		writeErr(w, http.StatusBadRequest, "object.cell is required: it is what the reduction is keyed by")
		return
	}
	if err := s.checkObject(req.Object); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Object.ID == "" {
		req.Object.ID = newID("mangrove:obj:")
	}

	a := activity.Activity{Type: activity.Create, Object: &req.Object, To: req.To}
	if err := s.emit(req.Tuple, author, &a); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// ACCEPTED AT SOURCE, when the author is the one who would have to approve it.
	//
	// The pending step exists so a role holder vets what travels to their scope.
	// Reaching this line with a group in the audience MEANS the author holds the
	// licence for that group -- the gate above refuses everybody else -- so the
	// vetting has already happened, by the same person, at the moment they
	// published. Asking them to then approve their own post is ceremony that
	// reads as a malfunction: the author watches their publication reach nobody
	// and has no reason to look in a tab called Pending.
	//
	// The Accept is EMITTED rather than inferred, so the log still shows who let
	// it travel and when. Nothing downstream learns a special case: the reduction,
	// the pending reading and the reach gate all go on reading decisions the only
	// way they ever did.
	//
	// The decide route and the pending reading stay. Today no unlicensed caller
	// can address a group at all (AD-030), so nothing else can reach them -- but
	// they are the mechanism that answers "somebody proposed this to my scope",
	// and deleting a correct answer because the current rules never ask the
	// question is how it gets rebuilt worse later.
	pending := false
	if needsDecision(a) {
		accept := activity.Activity{
			Type: activity.Accept, InReplyTo: a.ID, Target: scopeOf(a),
		}
		if err := s.emit(req.Tuple, author, &accept); err != nil {
			// The publication is already in the log. Saying it is pending is the
			// honest answer: it exists and has not been accepted, which is
			// exactly the state a role holder can still resolve by hand.
			if s.Logger != nil {
				s.Logger.Error("accept at source failed", "activity", a.ID, "err", err)
			}
			pending = true
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"activity": a,
		"pending":  pending,
	})
}

// needsDecision reports whether an activity crossed out of the author's own
// member scope and therefore waits on a role holder (FR-F1). Addressing a
// specific colleague is not a scope crossing -- it waits on that person instead
// (FR-B7, handleAdmit).
// checkObject is the first place this service has ever treated its two object
// types differently. Until now both were validated against the same membership
// test and then handled identically, which is how MemoryFile came to mean
// nothing at all.
//
// A file's bytes live in the blob store and its `content` is empty; a note's
// content is inline and it names no blob. Refusing the mixtures is what keeps a
// reader from having to ask which of the two a given object really is.
func (s *Server) checkObject(o activity.Object) error {
	switch o.Type {
	case activity.MemoryNote:
		if o.Blob != "" || o.FileName != "" || o.Size != 0 {
			return errors.New("a MemoryNote carries its content inline and names no blob")
		}
		return nil

	case activity.MemoryFile:
		if o.Content != "" {
			return errors.New("a MemoryFile carries its bytes in the blob store, not in object.content")
		}
		if o.Blob == "" || o.FileName == "" {
			return errors.New("a MemoryFile needs object.blob and object.fileName")
		}
		if s.Blobs == nil || !s.Blobs.Has(o.Blob) {
			// Refused HERE rather than at read: a post naming content nobody
			// holds is a broken promise made to every recipient, and the author
			// is the only one who can still fix it.
			return errors.New("object.blob names content this mangrove does not hold; upload it first")
		}
		return nil

	default:
		return errors.New("object.type must be MemoryNote or MemoryFile")
	}
}

func needsDecision(a activity.Activity) bool {
	for _, addr := range a.Audience() {
		if strings.HasPrefix(addr, "mangrove:group:") {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- share

type shareReq struct {
	base
	ObjectID string `json:"objectId"`
	Target   string `json:"target"`
	Undo     bool   `json:"undo"`
}

func (s *Server) handleShare(w http.ResponseWriter, r *http.Request) {
	var req shareReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed body")
		return
	}
	if req.ObjectID == "" || req.Target == "" {
		writeErr(w, http.StatusBadRequest, "objectId and target are required")
		return
	}
	author, _, err := s.signer(req.base)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Remove narrows and needs no reach check; Add widens and does.
	if !req.Undo {
		if err := reach.Check(req.Tuple, s.Members, []string{req.Target}, req.licences()); err != nil {
			if writeRefusal(w, err) {
				return
			}
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	typ := activity.Add
	if req.Undo {
		typ = activity.Remove
	}
	a := activity.Activity{Type: typ, Target: req.Target, InReplyTo: req.ObjectID, To: []string{req.Target}}
	if err := s.emit(req.Tuple, author, &a); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// NOT PENDING. This said `!req.Undo` -- every share reported itself as
	// waiting on a decision, and the interface told the member "it reaches the
	// group when whoever governs it accepts". Nothing was waiting: there is no
	// pending mechanism for an Add at all, and the pending reading skips it for
	// want of an object, so the sentence pointed at a queue that could never
	// hold it.
	//
	// Nor should there be one. Reaching this line MEANS the caller holds the
	// licence for what they addressed -- the gate refuses everybody else -- so
	// the vetting a decision exists to obtain has already happened, which is the
	// same argument that accepts a group publication at source.
	writeJSON(w, http.StatusOK, map[string]any{"activity": a, "pending": false})
}

// ---------------------------------------------------------------- react

type reactReq struct {
	base
	Kind string `json:"kind"` // read | like | flag
	Ref  string `json:"ref"`
	Undo bool   `json:"undo"`
}

// handleReact folds Read, Like and Flag into one endpoint, and their Undo with
// them. They differ only in which standard verb is emitted.
//
// Read is the receipt and MUST be emitted on ingestion, not on delivery: a
// receipt that fires because something appeared in a listing is a receipt for
// nothing. Like is endorsement, weight of evidence. Flag reports.
func (s *Server) handleReact(w http.ResponseWriter, r *http.Request) {
	var req reactReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed body")
		return
	}
	if req.Ref == "" {
		writeErr(w, http.StatusBadRequest, "ref is required")
		return
	}
	var typ activity.Type
	switch strings.ToLower(req.Kind) {
	case "read":
		typ = activity.Read
	case "like":
		typ = activity.Like
	case "flag":
		typ = activity.Flag
	default:
		writeErr(w, http.StatusBadRequest, "kind must be read, like or flag")
		return
	}
	author, _, err := s.signer(req.base)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a := activity.Activity{Type: typ, InReplyTo: req.Ref}
	if req.Undo {
		// UndoType names WHICH verb is being withdrawn. Without it, undoing a
		// read receipt and undoing an endorsement are the same activity, and
		// the reduction would treat the first as the second.
		a = activity.Activity{Type: activity.Undo, InReplyTo: req.Ref, UndoType: typ}
	}
	if err := s.emit(req.Tuple, author, &a); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"activity": a})
}

// ---------------------------------------------------------------- admit

type admitReq struct {
	base
	ActivityID string `json:"activityId"`
}

// handleAdmit is FR-B7: an object addressed directly at somebody becomes
// visible to that HUMAN, and does not enter their AGENT's memory until it is
// admitted.
//
// Without this, placing text into a colleague's agent's memory would be one
// share away -- and since memory steers turns, so would steering their agent.
// The subordination of bot to human would then hold only for one's own bot,
// which is the half that does not need protecting.
func (s *Server) handleAdmit(w http.ResponseWriter, r *http.Request) {
	var req admitReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed body")
		return
	}
	if req.ActivityID == "" {
		writeErr(w, http.StatusBadRequest, "activityId is required")
		return
	}
	author, _, err := s.signer(req.base)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a := activity.Activity{Type: activity.Accept, InReplyTo: req.ActivityID}
	if err := s.emit(req.Tuple, author, &a); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"activity": a, "admitted": req.ActivityID})
}

// ---------------------------------------------------------------- decide

type decideReq struct {
	base
	ActivityID string `json:"activityId"`
	Accept     bool   `json:"accept"`
	// Governs is set by the proxy when the caller's mycelium profile carries a
	// role governing the scope in question -- subscriptions-manager for a
	// subscription Group, tenant-manager or tenant-owner for a tenant Group.
	// The mangrove does not resolve roles; it is not the component that can.
	Governs bool `json:"governs"`
}

// handleDecide is FR-F2: Accept or Reject on a pending cross-scope publication.
//
// A Reject is NOT a failure. It is a result the author's agent can read and
// explain, mirroring how the approver loop already treats a denied tool call.
func (s *Server) handleDecide(w http.ResponseWriter, r *http.Request) {
	var req decideReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed body")
		return
	}
	if req.ActivityID == "" {
		writeErr(w, http.StatusBadRequest, "activityId is required")
		return
	}
	if !req.Governs {
		writeErr(w, http.StatusForbidden, "only a holder of the governing role may decide this scope")
		return
	}
	author, _, err := s.signer(req.base)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// The scope goes in `target`, which is what makes this a GOVERNANCE
	// decision rather than an admission. Without it the two are the same
	// activity and one would satisfy the other -- see admissions().
	acts, err := s.Log.Read(req.Tuple.TenantID, req.Tuple.SubsAccID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	scope := ""
	for _, prior := range acts {
		if prior.ID == req.ActivityID {
			scope = scopeOf(prior)
			break
		}
	}
	if scope == "" {
		writeErr(w, http.StatusBadRequest, "no pending cross-scope publication with that id")
		return
	}

	typ := activity.Reject
	if req.Accept {
		typ = activity.Accept
	}
	a := activity.Activity{Type: typ, InReplyTo: req.ActivityID, Target: scope}
	if err := s.emit(req.Tuple, author, &a); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"activity": a})
}

// ---------------------------------------------------------------- revoke

type revokeReq struct {
	base
	ObjectID string `json:"objectId"`
	Cell     string `json:"cell"`
}

// handleRevoke is the human's asymmetric authority (FR-E3).
//
// A Person may Delete anything their own Service authored. A Service may not
// reverse it: handleReact refuses an Undo of a Delete authored by the Person,
// which is checked in undoBlocked below. Authority runs one way on purpose.
//
// A Delete TOMBSTONES. It does not erase: ActivityPub cannot un-deliver, and
// this is documented rather than pretended otherwise.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var req revokeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed body")
		return
	}
	if req.ObjectID == "" || req.Cell == "" {
		writeErr(w, http.StatusBadRequest, "objectId and cell are required")
		return
	}
	author, person, err := s.signer(req.base)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if author.ID != person.ID {
		writeErr(w, http.StatusForbidden, "only the human may revoke; an agent cannot revoke on its own authority")
		return
	}
	// THE TOMBSTONE HAS TO TRAVEL WHERE THE CLAIM TRAVELLED.
	//
	// A Delete with no audience reaches nobody but its author. The reduction
	// only ever sees the activities a reader can reach, so a recipient's copy of
	// the claim never learned it had been tombstoned -- the author saw
	// `deleted: true` and everybody they had shared with went on reading it as
	// live, with not even a strikethrough. A revoke that only convinces the
	// person who performed it is worse than no revoke at all.
	reached, err := s.audienceOf(req.Tuple, author.ID, req.Cell, req.ObjectID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a := activity.Activity{
		Type:      activity.Delete,
		Object:    &activity.Object{ID: req.ObjectID, Type: activity.MemoryNote, Cell: req.Cell},
		InReplyTo: req.ObjectID,
		To:        reached,
	}
	if err := s.emit(req.Tuple, author, &a); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"activity": a,
		"note":     "tombstoned, not erased: anything already delivered to another scope stays delivered",
	})
}

// ---------------------------------------------------------------- timeline

type timelineReq struct {
	base
	// Reading selects which of the three the tab asks for.
	Reading string `json:"reading"` // received | published | pending
}

type timelineResp struct {
	Reading string              `json:"reading"`
	Claims  []mangrovelog.Claim `json:"claims,omitempty"`
	Held    []heldItem          `json:"held,omitempty"`
	Pending []pendingDecision   `json:"pending,omitempty"`
}

type heldItem struct {
	ActivityID string          `json:"activityId"`
	From       string          `json:"from"`
	Object     activity.Object `json:"object"`
	Published  string          `json:"published"`
}

type pendingDecision struct {
	ActivityID string          `json:"activityId"`
	Author     string          `json:"author"`
	Scope      string          `json:"scope"`
	Object     activity.Object `json:"object"`
	Published  string          `json:"published"`
}

// audienceOf is everywhere this author's claim on this cell has been addressed,
// so a tombstone can be addressed the same way.
//
// It is the UNION across every activity the author wrote for the cell, not just
// the last one: an object published privately and shared onward later has
// reached more people than its Create says, and a tombstone that copied only
// the Create would leave exactly those later recipients still reading it.
//
// Duplicates are dropped and order is kept, because the audience is signed:
// two revokes of the same thing should produce the same bytes.
func (s *Server) audienceOf(t actor.Tuple, authorID, cell, objectID string) ([]string, error) {
	acts, err := s.Log.Read(t.TenantID, t.SubsAccID)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, a := range acts {
		if a.Actor != authorID {
			continue
		}
		// TWO SHAPES, because widening happens in two shapes. A Create or
		// Update carries the object and names the cell; a Share emits an Add
		// with NO object at all -- only a Target and the object id in
		// InReplyTo. Matching on the cell alone would miss every recipient who
		// arrived through a share, which is precisely the set a tombstone
		// copying only the Create would leave behind.
		byCell := a.Object != nil && a.Object.Cell == cell
		byObject := objectID != "" && a.InReplyTo == objectID
		if !byCell && !byObject {
			continue
		}
		for _, addr := range a.Audience() {
			if !seen[addr] {
				seen[addr] = true
				out = append(out, addr)
			}
		}
	}
	return out, nil
}

func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	var req timelineReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed body")
		return
	}
	if !req.Tuple.Valid() {
		writeErr(w, http.StatusBadRequest, "incomplete workspace tuple")
		return
	}
	acts, err := s.Log.Read(req.Tuple.TenantID, req.Tuple.SubsAccID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	v := newViewer(req.Tuple, acts)
	governed := v.governed

	switch strings.ToLower(req.Reading) {
	case "published":
		var own []activity.Activity
		for _, a := range acts {
			if v.reach(a) == reachOwn {
				own = append(own, a)
			}
		}
		reduced := mangrovelog.Reduce(own)
		writeJSON(w, http.StatusOK, timelineResp{Reading: "published", Claims: flatten(reduced)})

	case "pending":
		// Absent, not empty, for somebody with no governing role -- the proxy
		// decides that by not calling this reading at all. Here we answer the
		// data question only.
		var out []pendingDecision
		for _, a := range acts {
			_, decided := governed[a.ID]
			if !needsDecision(a) || decided || a.Object == nil {
				continue
			}
			scope := scopeOf(a)
			out = append(out, pendingDecision{
				ActivityID: a.ID, Author: a.Actor, Scope: scope,
				Object: *a.Object, Published: a.Published,
			})
		}
		writeJSON(w, http.StatusOK, timelineResp{Reading: "pending", Pending: out})

	default: // received
		var visible []activity.Activity
		var held []heldItem
		// (cell, author) pairs this member has been told are withdrawn.
		tombstoned := map[string]bool{}

		for _, a := range acts {
			if a.Object == nil {
				continue
			}
			switch v.reach(a) {
			case reachHeld:
				// FR-B7: visible to the human, NOT yet in the agent's memory.
				// The hold is cleared only by THIS member admitting it.
				held = append(held, heldItem{
					ActivityID: a.ID, From: a.Actor,
					Object: *a.Object, Published: a.Published,
				})
			case reachVisible:
				visible = append(visible, a)
				if a.Type == activity.Delete {
					tombstoned[a.Object.Cell+"\x00"+a.Actor] = true
				}
			}
		}

		// Something withdrawn before it was ever taken simply goes away. Leaving
		// it in the held list would offer an Admit for content the author has
		// already recalled.
		if len(tombstoned) > 0 {
			kept := held[:0]
			for _, h := range held {
				if !tombstoned[h.Object.Cell+"\x00"+h.From] {
					kept = append(kept, h)
				}
			}
			held = kept
		}
		writeJSON(w, http.StatusOK, timelineResp{
			Reading: "received",
			Claims:  flatten(mangrovelog.Reduce(visible)),
			Held:    held,
		})
	}
}

// admissions and governanceDecisions are TWO DIFFERENT THINGS, and collapsing
// them into one "has it been decided" set is a real hole rather than an
// untidiness.
//
// Both are expressed as Accept/Reject on a prior activity, because those are
// the right standard verbs for both. They differ in who is answering and on
// whose behalf:
//
//	ADMISSION  -- a recipient letting an object into THEIR OWN agent's memory
//	              (FR-B7). Keyed by activity AND by the actor who admitted.
//	GOVERNANCE -- a role holder deciding whether a cross-scope publication may
//	              travel (FR-F2). Carries the scope in `target`.
//
// Keying admission by activity alone would mean one recipient's Accept cleared
// the hold for EVERY other addressee of the same activity -- and a governing
// role holder accepting a group publication would clear it for every direct
// addressee too. That is exactly the failure FR-B7 exists to prevent: memory
// entering somebody's agent without that person admitting it.
func admissions(acts []activity.Activity) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, a := range acts {
		if a.Type != activity.Accept || a.InReplyTo == "" {
			continue
		}
		if strings.HasPrefix(a.Target, "mangrove:group:") {
			continue // a governance decision, not an admission
		}
		if out[a.InReplyTo] == nil {
			out[a.InReplyTo] = map[string]bool{}
		}
		out[a.InReplyTo][a.Actor] = true
	}
	return out
}

// governanceDecisions maps a group publication to HOW it was decided: present in
// the map means decided at all, and the value says whether it was accepted.
//
// TWO QUESTIONS, AND THEY ARE NOT THE SAME ONE. "Has a role holder dealt with
// this?" decides whether it still belongs in the pending list; "may the scope
// read it?" decides whether it travels. A single boolean meaning "decided"
// answered both, so a REJECT published the thing to the entire scope -- the
// exact opposite of what rejecting it means, and the decision that looked most
// like it had worked.
//
// The last decision wins, because iteration follows log order. A role holder
// changing their mind is a normal thing for them to do.
func governanceDecisions(acts []activity.Activity) map[string]bool {
	out := map[string]bool{}
	for _, a := range acts {
		if a.Type != activity.Accept && a.Type != activity.Reject {
			continue
		}
		if a.InReplyTo == "" || !strings.HasPrefix(a.Target, "mangrove:group:") {
			continue
		}
		out[a.InReplyTo] = a.Type == activity.Accept
	}
	return out
}

// scopeOf returns the group an activity was addressed to, or "".
func scopeOf(a activity.Activity) string {
	for _, addr := range a.Audience() {
		if strings.HasPrefix(addr, "mangrove:group:") {
			return addr
		}
	}
	return ""
}

func flatten(m map[string][]mangrovelog.Claim) []mangrovelog.Claim {
	var out []mangrovelog.Claim
	for _, cs := range m {
		out = append(out, cs...)
	}
	return out
}
