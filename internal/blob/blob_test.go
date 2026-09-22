package blob

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func store(t *testing.T, max int64) *Store {
	t.Helper()
	s, err := New(t.TempDir(), max)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return s
}

func put(t *testing.T, s *Store, content string) string {
	t.Helper()
	d, n, err := s.Put(strings.NewReader(content))
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if n != int64(len(content)) {
		t.Fatalf("size = %d, want %d", n, len(content))
	}
	return d
}

func TestDigestIsTheContent(t *testing.T) {
	s := store(t, 0)
	d := put(t, s, "soil ph 6.4")
	want := sha256.Sum256([]byte("soil ph 6.4"))
	if d != hex.EncodeToString(want[:]) {
		t.Errorf("digest = %s, want the sha-256 of the content", d)
	}
}

func TestRoundTrip(t *testing.T) {
	s := store(t, 0)
	content := strings.Repeat("a memory\n", 1000)
	d := put(t, s, content)

	r, n, err := s.Open(d)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer r.Close()
	got, _ := io.ReadAll(r)
	if string(got) != content {
		t.Errorf("content did not survive the round trip")
	}
	if n != int64(len(content)) {
		t.Errorf("size = %d, want %d", n, len(content))
	}
}

// Content addressing is the point: two members sharing one document must not
// cost two copies, and re-sharing must cost nothing.
func TestIdenticalContentStoresOnce(t *testing.T) {
	s := store(t, 0)
	d1 := put(t, s, "the same document")
	d2 := put(t, s, "the same document")
	if d1 != d2 {
		t.Fatalf("identical content got two digests: %s / %s", d1, d2)
	}
	entries, err := os.ReadDir(s.root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("store holds %d files, want 1: %v", len(entries), names)
	}
}

// Re-sharing must cost NOTHING, which storing-once alone does not prove: a
// rename over an existing path also leaves one file. This pins the
// short-circuit by its observable consequence -- the stored file is not
// replaced, so it is still the same inode.
func TestReSharingDoesNotRewriteTheStoredFile(t *testing.T) {
	s := store(t, 0)
	d := put(t, s, "a document worth re-sharing")

	before, err := os.Stat(s.path(d))
	if err != nil {
		t.Fatal(err)
	}
	put(t, s, "a document worth re-sharing")
	after, err := os.Stat(s.path(d))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Error("re-sharing replaced the stored file; the short-circuit is not short-circuiting")
	}
}

// Refused at WRITE. An oversized file is refused when somebody tries to share
// it, not when somebody tries to read it.
func TestOverTheLimitIsRefused(t *testing.T) {
	s := store(t, 64)
	_, _, err := s.Put(strings.NewReader(strings.Repeat("x", 65)))
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	// Exactly at the limit is fine: the bound is inclusive.
	if _, _, err := s.Put(strings.NewReader(strings.Repeat("x", 64))); err != nil {
		t.Errorf("content exactly at the limit was refused: %v", err)
	}
}

// A refusal must not leave the oversized bytes on disk, and must not leave a
// temp file behind either.
func TestARefusedPutLeavesNothing(t *testing.T) {
	s := store(t, 64)
	_, _, _ = s.Put(strings.NewReader(strings.Repeat("x", 4096)))
	entries, err := os.ReadDir(s.root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("a refused put left %d files behind", len(entries))
	}
}

// The bound is enforced while streaming rather than after, so a caller cannot
// make the store read an arbitrarily large body in order to earn a refusal.
func TestTheLimitStopsReading(t *testing.T) {
	s := store(t, 1024)
	counted := &countingReader{}
	_, _, err := s.Put(counted)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	if counted.n > 1024+4096 {
		t.Errorf("read %d bytes to refuse a 1024-byte limit; it is not stopping early", counted.n)
	}
}

type countingReader struct{ n int64 }

func (c *countingReader) Read(p []byte) (int, error) {
	c.n += int64(len(p))
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

// Rejecting a malformed digest is also what keeps a caller from steering Open
// at a path of their choosing.
func TestOnlyADigestReachesTheFilesystem(t *testing.T) {
	s := store(t, 0)
	real := put(t, s, "secret")

	// A neighbour file the caller must not be able to name.
	outside := filepath.Join(filepath.Dir(s.root), "keys.ed25519")
	if err := os.WriteFile(outside, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, bad := range []string{
		"../keys.ed25519",
		"..%2fkeys.ed25519",
		strings.ToUpper(real), // hex is lowercase; an alias is not the name
		real[:63],             // short
		real + "0",            // long
		"",
		"g" + real[1:], // not hex
		filepath.Join("..", real),
	} {
		if _, _, err := s.Open(bad); !errors.Is(err, ErrBadDigest) {
			t.Errorf("Open(%q) = %v, want ErrBadDigest", bad, err)
		}
		if s.Has(bad) {
			t.Errorf("Has(%q) is true", bad)
		}
	}
}

func TestUnknownDigestIsNotFound(t *testing.T) {
	s := store(t, 0)
	absent := hex.EncodeToString(bytes.Repeat([]byte{0xab}, sha256.Size))
	if _, _, err := s.Open(absent); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	if s.Has(absent) {
		t.Error("Has is true for content never stored")
	}
}

// A half-written file under a digest would be worse than a missing one: the
// name would be a lie about the contents. Nothing may appear at the final path
// until it is complete.
func TestStoredFileIsNotWorldReadable(t *testing.T) {
	s := store(t, 0)
	d := put(t, s, "private memory")
	st, err := os.Stat(s.path(d))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", st.Mode().Perm())
	}
}
