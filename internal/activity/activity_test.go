package activity

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func sample() Activity {
	return Activity{
		ID:        "mangrove:act:1",
		Type:      Create,
		Actor:     "mangrove:actor:alice:service",
		To:        []string{"mangrove:group:subscription:s1"},
		CC:        []string{},
		Object:    &Object{ID: "mangrove:obj:1", Type: MemoryNote, Cell: "soil-ph", Content: "5.8"},
		Published: "2026-09-21T10:00:00Z",
	}
}

func TestSignRoundTrip(t *testing.T) {
	pub, priv := key(t)
	a := sample()
	if err := Sign(&a, priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Verify(a, pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestSignatureCoversAddressing is the negative test the threat model turns on.
//
// The classic break in a group scheme is a signature that covers the payload
// but not the recipient list: a member re-addresses a validly signed activity,
// forwards it, and the receiver verifies it successfully. If this test ever
// passes with `to` removed from the signed bytes, the mangrove has that hole.
func TestSignatureCoversAddressing(t *testing.T) {
	pub, priv := key(t)

	for _, tc := range []struct {
		name   string
		mutate func(*Activity)
	}{
		{"to is swapped", func(a *Activity) { a.To = []string{"mangrove:group:tenant:t1"} }},
		{"to gains an entry", func(a *Activity) { a.To = append(a.To, "mangrove:actor:mallory:service") }},
		{"cc gains an entry", func(a *Activity) { a.CC = append(a.CC, "mangrove:actor:mallory:service") }},
		{"to is emptied", func(a *Activity) { a.To = []string{} }},
		{"actor is swapped", func(a *Activity) { a.Actor = "mangrove:actor:mallory:service" }},
		{"content is edited", func(a *Activity) { a.Object.Content = "9.9" }},
		{"cell is moved", func(a *Activity) { a.Object.Cell = "soil-nitrogen" }},
		{"target is set", func(a *Activity) { a.Target = "mangrove:group:tenant:t1" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := sample()
			if err := Sign(&a, priv); err != nil {
				t.Fatalf("sign: %v", err)
			}
			// Keep the original signature; change only the covered content.
			tampered := a
			obj := *a.Object
			tampered.Object = &obj
			tc.mutate(&tampered)

			if err := Verify(tampered, pub); err == nil {
				t.Fatalf("a re-addressed/edited activity verified: the signature does not cover this field")
			}
		})
	}
}

func TestUnsignedIsRefused(t *testing.T) {
	pub, _ := key(t)
	if err := Verify(sample(), pub); err == nil {
		t.Fatal("an unsigned activity verified")
	}
}

func TestWrongKeyIsRefused(t *testing.T) {
	_, priv := key(t)
	otherPub, _ := key(t)
	a := sample()
	if err := Sign(&a, priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Verify(a, otherPub); err == nil {
		t.Fatal("an activity verified against somebody else's key")
	}
}

// The verb set is closed, and the widening subset is what the reachability gate
// must cover. Pinning it here means adding a verb that widens reach without
// adding it to the gate fails a test rather than shipping a hole.
func TestWideningVerbsArePinned(t *testing.T) {
	want := map[Type]bool{Create: true, Update: true, Add: true, Announce: true}
	for typ := range known {
		if got := typ.Widening(); got != want[typ] {
			t.Errorf("%s: Widening()=%v, want %v -- if this verb can increase who reaches an object, the reach gate must run for it", typ, got, want[typ])
		}
	}
}

func TestUnknownTypeIsRefusedAtSigning(t *testing.T) {
	_, priv := key(t)
	a := sample()
	a.Type = "Yeet"
	if err := Sign(&a, priv); err == nil {
		t.Fatal("signed an activity with a type outside the AS2 set")
	}
}

// The envelope is defined and deliberately unimplemented. It must FAIL rather
// than pass content through: a caller that believes it encrypted something and
// did not is worse than one that errors.
func TestEnvelopeSealRefusesRatherThanPassingThrough(t *testing.T) {
	out, err := Envelope{}.Seal([]byte("secret"))
	if err == nil {
		t.Fatal("Seal returned no error; unimplemented encryption must never look like success")
	}
	if out != nil {
		t.Fatalf("Seal returned %q alongside an error", out)
	}
}
