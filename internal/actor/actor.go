// Package actor holds the two identities every workspace gets on the mangrove: a
// Person for the human, and a Service for the agent that works for them.
//
// THE AGENT IS NOT A PEER OF THE HUMAN. A Service actor carries attributedTo
// naming its Person, so anything it publishes is readable as "this bot, owned
// by that account" rather than as a claim from nowhere. Activity Streams 2.0
// has no normative "this bot belongs to that person" property; attributedTo is
// defined with a domain of Link | Object (AS2 Vocabulary section 4) and every
// actor type extends Object (section 3.2), so this is the vocabulary used as
// specified rather than an extension of it.
//
// IDS DERIVE FROM THE ACCOUNT ID, NEVER THE EMAIL. crab-shell-proxy already
// settled this for workspaces -- the email is mutable, so it cannot be an
// isolation key. The same reasoning is sharper here: an actor id that changed
// when somebody changed their email address would orphan every object they had
// ever authored, and every signature over it.
package actor

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Kind is an AS2 actor type. Only the two this project mints are listed.
type Kind string

const (
	KindPerson  Kind = "Person"
	KindService Kind = "Service"
)

// Tuple is the verified workspace identity crab-shell-proxy resolves before it
// ever calls the mangrove. It is the ONLY source of identity in this service: no
// handler accepts an actor id from a request body.
//
// It mirrors docker.WorkspaceKey in the proxy. Role is the agent key.
type Tuple struct {
	TenantID  string `json:"tenantId"`
	SubsAccID string `json:"subsAccId"`
	Role      string `json:"role"`
	UserAccID string `json:"userAccId"`
}

// Valid reports whether every dimension of the tuple is present. A partially
// populated tuple is refused rather than defaulted: a blank tenant would
// otherwise silently address a different shard of the log.
func (t Tuple) Valid() bool {
	return t.TenantID != "" && t.SubsAccID != "" && t.Role != "" && t.UserAccID != ""
}

// Actor is the stored document. The private key is deliberately NOT a field --
// it never travels with the actor, and never leaves the keys directory.
type Actor struct {
	ID           string `json:"id"`
	Type         Kind   `json:"type"`
	AttributedTo string `json:"attributedTo,omitempty"`
	AccID        string `json:"accId"`
	TenantID     string `json:"tenantId"`
	SubsAccID    string `json:"subsAccId"`
	PublicKey    string `json:"publicKey"`
	Published    string `json:"published"`
}

// PersonID and ServiceID are the two derivations. Both take the account id and
// nothing else, so they are stable across a rename, an email change, or a move
// between agents.
func PersonID(accID string) string  { return "mangrove:actor:" + sanitizeID(accID) + ":person" }
func ServiceID(accID string) string { return "mangrove:actor:" + sanitizeID(accID) + ":service" }

// SubscriptionGroupID and TenantGroupID name the two Group actors a scope is
// addressed through.
func SubscriptionGroupID(subsAccID string) string {
	return "mangrove:group:subscription:" + sanitizeID(subsAccID)
}
func TenantGroupID(tenantID string) string {
	return "mangrove:group:tenant:" + sanitizeID(tenantID)
}

// AccIDOf recovers the account id from an actor id, or "" if the id is not one
// of ours. Used by the reachability gate to decide whether an addressee is a
// member of a subscription the caller can already see.
func AccIDOf(actorID string) string {
	rest, ok := strings.CutPrefix(actorID, "mangrove:actor:")
	if !ok {
		return ""
	}
	for _, suffix := range []string{":person", ":service"} {
		if acc, ok := strings.CutSuffix(rest, suffix); ok {
			return acc
		}
	}
	return ""
}

var (
	unsafeName  = regexp.MustCompile(`[^a-zA-Z0-9._-]`)
	pathSegment = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)
)

// sanitizeID mirrors identity.SanitizeID in crab-shell-proxy, deliberately
// rather than by import: this is a separate module with no dependency on the
// proxy, and the two must not drift silently. An accId is normally a UUID and
// already safe; this guards a pathological one from escaping a directory.
func sanitizeID(id string) string {
	s := unsafeName.ReplaceAllString(strings.TrimSpace(id), "-")
	s = strings.Trim(s, "-._")
	if s == "" || !pathSegment.MatchString(s) {
		sum := sha256.Sum256([]byte(id))
		return hex.EncodeToString(sum[:])[:16]
	}
	return s
}

// Store is the on-disk actor registry. Two directories, one purpose each.
type Store struct{ root string }

func NewStore(root string) (*Store, error) {
	for _, d := range []string{"actors", "keys"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			return nil, fmt.Errorf("actor store: %w", err)
		}
	}
	return &Store{root: root}, nil
}

func (s *Store) actorPath(id string) string {
	return filepath.Join(s.root, "actors", sanitizeID(id)+".json")
}
func (s *Store) keyPath(id string) string {
	return filepath.Join(s.root, "keys", sanitizeID(id)+".ed25519")
}

// Ensure provisions both actors for a workspace, idempotently, and returns
// them. Calling it twice returns the same ids and the same keys -- a new
// keypair on every call would invalidate every signature already in the log.
func (s *Store) Ensure(t Tuple) (person, service *Actor, err error) {
	if !t.Valid() {
		return nil, nil, errors.New("actor: incomplete workspace tuple")
	}
	person, err = s.ensureOne(PersonID(t.UserAccID), KindPerson, "", t)
	if err != nil {
		return nil, nil, err
	}
	service, err = s.ensureOne(ServiceID(t.UserAccID), KindService, person.ID, t)
	if err != nil {
		return nil, nil, err
	}
	return person, service, nil
}

func (s *Store) ensureOne(id string, kind Kind, owner string, t Tuple) (*Actor, error) {
	if a, err := s.Load(id); err == nil {
		return a, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("actor: generate key: %w", err)
	}
	// 0600 and above nothing the agent can reach. The container boundary is the
	// confinement for a ganglion agent; this file is on the other side of it.
	if err := os.WriteFile(s.keyPath(id), []byte(base64.StdEncoding.EncodeToString(priv)), 0o600); err != nil {
		return nil, fmt.Errorf("actor: write key: %w", err)
	}

	a := &Actor{
		ID:           id,
		Type:         kind,
		AttributedTo: owner,
		AccID:        t.UserAccID,
		TenantID:     t.TenantID,
		SubsAccID:    t.SubsAccID,
		PublicKey:    base64.StdEncoding.EncodeToString(pub),
		Published:    time.Now().UTC().Format(time.RFC3339),
	}
	b, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(s.actorPath(id), b, 0o600); err != nil {
		return nil, fmt.Errorf("actor: write actor: %w", err)
	}
	return a, nil
}

// Load reads an actor document. The error wraps os.ErrNotExist when absent, so
// callers can distinguish "no such actor" from a broken store.
func (s *Store) Load(id string) (*Actor, error) {
	b, err := os.ReadFile(s.actorPath(id))
	if err != nil {
		return nil, err
	}
	var a Actor
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, fmt.Errorf("actor: decode %s: %w", id, err)
	}
	return &a, nil
}

// PrivateKey loads a signing key. Nothing serves this over HTTP; the only
// caller is the signing path, inside this process.
func (s *Store) PrivateKey(id string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(s.keyPath(id))
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("actor: decode key %s: %w", id, err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("actor: key %s has wrong size %d", id, len(raw))
	}
	return ed25519.PrivateKey(raw), nil
}

// PublicKey resolves a verification key from the stored document.
func (s *Store) PublicKey(id string) (ed25519.PublicKey, error) {
	a, err := s.Load(id)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(a.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("actor: decode public key %s: %w", id, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("actor: public key %s has wrong size %d", id, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}
