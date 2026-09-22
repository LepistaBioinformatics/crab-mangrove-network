// Package activity is the reef's Activity Streams 2.0 surface: the verbs, the
// two object types, and the signature that makes an entry in the log
// attributable to exactly one actor.
//
// EVERY VERB HERE IS STANDARD. All fourteen are Activity Types defined in the
// AS2 Vocabulary, section 3.1 -- checked against the specification, not
// recalled. Two are worth naming because the temptation is to improvise them:
//
//	Read -- "Indicates that the actor has read the object."
//	Like -- "Indicates that the actor likes, recommends or endorses the object."
//
// So Read is the receipt, and Like keeps its own definition for endorsement.
// Overloading Like as a receipt would spend a distinct signal for nothing and
// lose the one that matters: trust here is weight of evidence, never a truth
// predicate on a memory.
//
// THE SIGNATURE COVERS THE ADDRESSING. Canonical() serialises every semantic
// field including to and cc, so re-addressing a signed activity invalidates it.
// This is not incidental. The classic break in a group-encryption scheme is a
// signature that covers the ciphertext but not the recipient list: any member
// can then re-wrap the key for an intruder, forward the originally signed
// envelope, and the receiver verifies it successfully -- signature intact,
// destination swapped. The reef does not ship envelope encryption (see
// Envelope below), but the addressing list is exposed to the same attack, so it
// is inside the signed bytes from the start.
package activity

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Type is an AS2 activity type. The set is closed on purpose: a verb that is
// not here is not something the reef knows how to reduce.
type Type string

const (
	Create   Type = "Create"
	Update   Type = "Update"
	Delete   Type = "Delete"
	Add      Type = "Add"
	Remove   Type = "Remove"
	Follow   Type = "Follow"
	Accept   Type = "Accept"
	Reject   Type = "Reject"
	Announce Type = "Announce"
	Read     Type = "Read"
	Like     Type = "Like"
	Flag     Type = "Flag"
	Block    Type = "Block"
	Undo     Type = "Undo"
)

var known = map[Type]bool{
	Create: true, Update: true, Delete: true, Add: true, Remove: true,
	Follow: true, Accept: true, Reject: true, Announce: true, Read: true,
	Like: true, Flag: true, Block: true, Undo: true,
}

func (t Type) Known() bool { return known[t] }

// Widening reports whether this verb can increase who can reach an object. The
// reachability gate must run for exactly these, and reach.Check is called from
// one place per verb -- see internal/reach.
func (t Type) Widening() bool {
	switch t {
	case Create, Update, Add, Announce:
		return true
	}
	return false
}

// TimeFormat is FIXED WIDTH, and that is the whole point of it existing.
//
// time.RFC3339Nano uses "9" digits in its fractional part, which means Go ELIDES
// trailing zeros: the same clock produces "10:00:00Z" and "10:00:00.5Z". Those
// two do not order correctly as strings -- '.' is 0x2E and 'Z' is 0x5A, so
// "10:00:00.5Z" sorts BEFORE "10:00:00Z" -- and the log's reduction is an
// ordering over exactly this field. A whole-second write would lose to an
// earlier sub-second one.
//
// Reduction parses rather than compares strings (see reeflog), so this is
// belt and braces; it also keeps the log readable and diffable.
const TimeFormat = "2006-01-02T15:04:05.000000000Z07:00"

// ObjectType is what a memory object is. Two kinds, matching what this stack
// actually accumulates: knowledge-graph material and workspace files.
type ObjectType string

const (
	MemoryNote ObjectType = "MemoryNote"
	MemoryFile ObjectType = "MemoryFile"
)

// Object is one unit of shared memory.
//
// Cell is the identity of the thing being remembered -- a graph entity name, a
// file path. It is what the reduction is keyed by, together with the author:
// two authors may hold different claims about the same cell and neither
// overwrites the other.
type Object struct {
	ID        string     `json:"id"`
	Type      ObjectType `json:"type"`
	Cell      string     `json:"cell"`
	Content   string     `json:"content,omitempty"`
	MediaType string     `json:"mediaType,omitempty"`
}

// Signature is detached and covers Canonical(a).
type Signature struct {
	Alg   string `json:"alg"`
	Value string `json:"value"`
}

// Activity is one line of the log.
type Activity struct {
	ID        string     `json:"id"`
	Type      Type       `json:"type"`
	Actor     string     `json:"actor"`
	To        []string   `json:"to"`
	CC        []string   `json:"cc"`
	Object    *Object    `json:"object,omitempty"`
	Target    string     `json:"target,omitempty"`
	InReplyTo string     `json:"inReplyTo,omitempty"`
	Published string     `json:"published"`
	Signature *Signature `json:"signature,omitempty"`

	// UndoType names the verb an Undo withdraws.
	//
	// Without it, every Undo of a Read, a Like and a Flag on the same object is
	// the SAME activity, and the reduction cannot tell them apart -- so undoing
	// a read receipt would silently withdraw an endorsement. AS2 models Undo as
	// referring to the prior activity; this field carries that intent without
	// requiring every reader to resolve the reference first.
	UndoType Type `json:"undoType,omitempty"`
}

// Audience is every actor or group this activity is addressed to, to and cc
// together. The reachability gate takes this, not the raw fields, so a future
// addressing field cannot be added without passing through the same check.
func (a Activity) Audience() []string {
	out := make([]string, 0, len(a.To)+len(a.CC))
	out = append(out, a.To...)
	out = append(out, a.CC...)
	return out
}

// Canonical is the exact byte sequence a signature covers: the whole activity
// with the signature removed.
//
// Determinism comes from encoding/json's own guarantees -- struct fields
// marshal in declaration order, and the type contains no maps. Taking the whole
// struct rather than a hand-listed subset is deliberate: a field added later is
// covered automatically, whereas a hand-written list is a thing to forget.
func Canonical(a Activity) ([]byte, error) {
	a.Signature = nil
	return json.Marshal(a)
}

// Sign attaches a signature. It does not check the key belongs to a.Actor --
// the caller resolves the key by actor id, and Verify is what enforces the
// pairing on the way back in.
func Sign(a *Activity, priv ed25519.PrivateKey) error {
	if a == nil {
		return errors.New("activity: nil")
	}
	if !a.Type.Known() {
		return fmt.Errorf("activity: unknown type %q", a.Type)
	}
	b, err := Canonical(*a)
	if err != nil {
		return err
	}
	a.Signature = &Signature{
		Alg:   "ed25519",
		Value: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b)),
	}
	return nil
}

// ErrBadSignature is returned for every verification failure, whatever the
// cause. Callers must not branch on why: a forged signature and a mutated
// audience are the same answer to the only question being asked.
var ErrBadSignature = errors.New("activity: signature does not verify")

// Verify checks the signature against the author's public key. It is a
// precondition of appending to the log -- an unverified line never lands.
func Verify(a Activity, pub ed25519.PublicKey) error {
	if a.Signature == nil {
		return ErrBadSignature
	}
	if a.Signature.Alg != "ed25519" {
		return fmt.Errorf("activity: unsupported signature algorithm %q", a.Signature.Alg)
	}
	sig, err := base64.StdEncoding.DecodeString(a.Signature.Value)
	if err != nil {
		return ErrBadSignature
	}
	b, err := Canonical(a)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, b, sig) {
		return ErrBadSignature
	}
	return nil
}

// Envelope is the confidentiality interface, DEFINED AND NOT IMPLEMENTED.
//
// The reef is a trusted service: it reads content in the clear, and mycelium
// roles govern who else does. That is a deliberate trade and not an oversight.
// End-to-end encryption and role-based governance are mutually exclusive for
// the same content -- under a blind router, access is key possession, so
// promoting somebody to subscriptions-manager grants them nothing until keys
// are re-wrapped, and re-wrapping needs a component holding both the keys and
// the role graph. In this stack that component would be crab-shell-proxy, which
// already runs as root with a Docker socket and reads every workspace.
// Encrypting against a party that is already omniscient is theatre.
//
// FORWARD SECRECY, STATED HERE AND NOT ONLY IN THE README: rotating a group key
// does NOT give forward secrecy. Somebody who leaves keeps everything they have
// already read; what stops is new material. That is the industry-standard
// position and it is defensible precisely because it is written down.
//
// IF THIS IS EVER IMPLEMENTED, the signature must cover Recipients. Omitting it
// is the break described in this package's doc comment.
type Envelope struct {
	KeyGeneration int
	Ciphertext    []byte
	Nonce         []byte
	Recipients    []struct {
		MemberID   string
		WrappedKey []byte
	}
}

// Seal is the unimplemented half. It returns an error rather than silently
// passing content through: a caller that believes it encrypted something and
// did not is worse than a caller that fails.
func (Envelope) Seal([]byte) ([]byte, error) {
	return nil, errors.New("activity: envelope encryption is not implemented; the reef is a trusted service by design -- see the Envelope doc comment and the README threat model")
}
