// Package blob holds the bytes a post carries, addressed by what they are.
//
// WHY THE BYTES ARE NOT IN THE LOG. The log is JSONL and its reader buffers a
// line to 8 MiB. A file encoded into an activity would put megabytes on one
// line, and exceeding that limit fails the read of the WHOLE SHARD -- every post
// in it, for every member -- rather than of the one post at fault. A failure out
// of all proportion to its cause.
//
// WHY CONTENT ADDRESSING RATHER THAN AN ID. An id needs a manifest mapping id to
// content, which is a second thing to keep consistent with the log. The digest
// IS the identity: the log line carrying it is the only index there is, two
// members sharing the same document cost one file, and re-sharing is a no-op.
//
// A DIGEST IS NOT A CAPABILITY. This package will hand the bytes to anybody who
// names them correctly; it is deliberately not where the question of WHO may
// read is answered. That lives with the visibility rule, because the answer has
// to be the same one the timeline gives.
package blob

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// DefaultMaxBytes bounds one blob. Generous for a document, far below anything
// that would make the store a file server.
const DefaultMaxBytes int64 = 10 << 20

// ErrTooLarge is the refusal for content over the limit. It is returned at
// WRITE, so an oversized file is refused when somebody tries to share it rather
// than when somebody tries to read it.
var ErrTooLarge = errors.New("blob: content exceeds the size limit")

// ErrNotFound is a digest nothing has stored.
var ErrNotFound = errors.New("blob: no such content")

// ErrBadDigest is a malformed digest. Rejecting it is also what keeps a caller
// from steering Open at a path of their choosing: the only strings that reach
// the filesystem are 64 lowercase hex characters.
var ErrBadDigest = errors.New("blob: not a sha-256 digest")

type Store struct {
	root string
	max  int64
}

func New(root string, max int64) (*Store, error) {
	if max <= 0 {
		max = DefaultMaxBytes
	}
	dir := filepath.Join(root, "blobs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("blob: create store: %w", err)
	}
	return &Store{root: dir, max: max}, nil
}

// Max is the limit this store enforces, so a caller can refuse early and say
// the number rather than discovering it mid-upload.
func (s *Store) Max() int64 { return s.max }

func validDigest(d string) bool {
	if len(d) != sha256.Size*2 {
		return false
	}
	for i := 0; i < len(d); i++ {
		c := d[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func (s *Store) path(digest string) string { return filepath.Join(s.root, digest) }

// Put stores everything r yields and returns its digest and size.
//
// The limit is enforced WHILE STREAMING, not after: reading an arbitrarily large
// body to the end before checking would let a caller fill the disk to earn a
// refusal. The temp file is written first and renamed into place, so a
// half-written file never appears under a digest -- which would be worse than
// missing, since the name would then be a lie about the contents.
func (s *Store) Put(r io.Reader) (digest string, size int64, err error) {
	tmp, err := os.CreateTemp(s.root, ".incoming-*")
	if err != nil {
		return "", 0, fmt.Errorf("blob: temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName) // no-op once renamed
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return "", 0, fmt.Errorf("blob: chmod: %w", err)
	}

	h := sha256.New()
	// One byte past the limit is enough to know, and stops there.
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(r, s.max+1))
	if err != nil {
		return "", 0, fmt.Errorf("blob: write: %w", err)
	}
	if n > s.max {
		return "", 0, ErrTooLarge
	}
	if err := tmp.Close(); err != nil {
		return "", 0, fmt.Errorf("blob: close: %w", err)
	}

	digest = hex.EncodeToString(h.Sum(nil))
	final := s.path(digest)
	if _, err := os.Stat(final); err == nil {
		return digest, n, nil // already held; identical content is one file
	}
	if err := os.Rename(tmpName, final); err != nil {
		return "", 0, fmt.Errorf("blob: commit: %w", err)
	}
	return digest, n, nil
}

// Open returns the content and its size.
func (s *Store) Open(digest string) (io.ReadCloser, int64, error) {
	if !validDigest(digest) {
		return nil, 0, ErrBadDigest
	}
	f, err := os.Open(s.path(digest))
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, fmt.Errorf("blob: open: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, fmt.Errorf("blob: stat: %w", err)
	}
	return f, st.Size(), nil
}

// Has reports whether the content is held, without opening it.
func (s *Store) Has(digest string) bool {
	if !validDigest(digest) {
		return false
	}
	_, err := os.Stat(s.path(digest))
	return err == nil
}
