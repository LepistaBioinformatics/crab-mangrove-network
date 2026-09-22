package actor

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func store(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	return s, dir
}

var alice = Tuple{TenantID: "t1", SubsAccID: "s1", Role: "alpha", UserAccID: "acc-alice"}

// The agent is the human's bot, and the document has to say so.
func TestServiceIsAttributedToItsPerson(t *testing.T) {
	s, _ := store(t)
	person, service, err := s.Ensure(alice)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if person.Type != KindPerson || service.Type != KindService {
		t.Fatalf("types are %s/%s", person.Type, service.Type)
	}
	if service.AttributedTo != person.ID {
		t.Errorf("service.attributedTo = %q, want the person id %q", service.AttributedTo, person.ID)
	}
	if person.AttributedTo != "" {
		t.Errorf("person carries attributedTo = %q; a human is not attributed to anybody", person.AttributedTo)
	}
}

// Ids derive from the account id. An email-derived id would break on a change
// of address and orphan every signature already written.
func TestIDsDeriveFromAccountIDNotEmail(t *testing.T) {
	if !strings.Contains(PersonID("acc-alice"), "acc-alice") {
		t.Errorf("person id does not carry the account id: %s", PersonID("acc-alice"))
	}
	if PersonID("acc-alice") == ServiceID("acc-alice") {
		t.Error("the human and the bot share an id")
	}
	if got := AccIDOf(ServiceID("acc-alice")); got != "acc-alice" {
		t.Errorf("AccIDOf round trip = %q", got)
	}
	if got := AccIDOf("https://mastodon.example/users/bob"); got != "" {
		t.Errorf("AccIDOf accepted a foreign id: %q", got)
	}
}

// Provisioning twice must not mint new keys: every signature already in the log
// verifies against the old ones.
func TestEnsureIsIdempotent(t *testing.T) {
	s, _ := store(t)
	p1, s1, err := s.Ensure(alice)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	p2, s2, err := s.Ensure(alice)
	if err != nil {
		t.Fatalf("ensure again: %v", err)
	}
	if p1.PublicKey != p2.PublicKey || s1.PublicKey != s2.PublicKey {
		t.Fatal("a second Ensure rotated the keys, invalidating every signature in the log")
	}
	if p1.Published != p2.Published {
		t.Error("a second Ensure rewrote the actor document")
	}
}

func TestPrivateKeyIsNotWorldReadableAndNotInTheDocument(t *testing.T) {
	s, dir := store(t)
	_, service, err := s.Ensure(alice)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}

	fi, err := os.Stat(filepath.Join(dir, "keys", "reef-actor-acc-alice-service.ed25519"))
	if err != nil {
		// The filename is sanitized; find it rather than guess.
		entries, _ := os.ReadDir(filepath.Join(dir, "keys"))
		if len(entries) == 0 {
			t.Fatal("no key file was written")
		}
		fi, err = os.Stat(filepath.Join(dir, "keys", entries[0].Name()))
		if err != nil {
			t.Fatalf("stat key: %v", err)
		}
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %o, want 600", perm)
	}

	b, err := json.Marshal(service)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	priv, err := s.PrivateKey(service.ID)
	if err != nil {
		t.Fatalf("private key: %v", err)
	}
	if strings.Contains(string(b), string(priv)) {
		t.Fatal("the serialised actor document contains the private key")
	}
	for _, field := range []string{"privateKey", "private_key", "secret"} {
		if strings.Contains(string(b), field) {
			t.Errorf("actor document carries a %q field", field)
		}
	}
}

func TestIncompleteTupleIsRefused(t *testing.T) {
	s, _ := store(t)
	for _, tp := range []Tuple{
		{SubsAccID: "s1", Role: "alpha", UserAccID: "a"},
		{TenantID: "t1", Role: "alpha", UserAccID: "a"},
		{TenantID: "t1", SubsAccID: "s1", UserAccID: "a"},
		{TenantID: "t1", SubsAccID: "s1", Role: "alpha"},
	} {
		if _, _, err := s.Ensure(tp); err == nil {
			t.Errorf("provisioned from an incomplete tuple %+v", tp)
		}
	}
}

// A pathological id must not escape its directory.
func TestSanitizeContainsPathTraversal(t *testing.T) {
	for _, bad := range []string{"../../etc/passwd", "a/b", "..", "", "   "} {
		got := sanitizeID(bad)
		if strings.ContainsAny(got, "/\\") || got == ".." || got == "" {
			t.Errorf("sanitizeID(%q) = %q, which is still a path", bad, got)
		}
	}
}

func TestPublicKeyRoundTrips(t *testing.T) {
	s, _ := store(t)
	_, service, _ := s.Ensure(alice)
	pub, err := s.PublicKey(service.ID)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	priv, err := s.PrivateKey(service.ID)
	if err != nil {
		t.Fatalf("private key: %v", err)
	}
	if !ed25519.Verify(pub, []byte("round trip"), ed25519.Sign(priv, []byte("round trip"))) {
		t.Error("the stored public key does not verify what the stored private key signs")
	}
}
