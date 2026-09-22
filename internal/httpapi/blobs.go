package httpapi

import (
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/LepistaBioinformatics/crab-mangrove-network/internal/actor"
	"github.com/LepistaBioinformatics/crab-mangrove-network/internal/blob"
	"github.com/LepistaBioinformatics/crab-mangrove-network/internal/mangrovelog"
)

// The bytes a post carries, in and out.
//
// UPLOAD IS UNCONDITIONAL AND READ IS NOT, which looks backwards and is not.
// Uploading costs the uploader a round trip and gains them nothing until they
// publish something naming the digest -- and publishing goes through the gate
// like everything else. Reading is where the question "may this member have
// these bytes" is actually asked, and it is asked of the same rule the timeline
// answers with.

// handleBlobPut stores content and answers with its digest. The caller then
// publishes an object naming it.
func (s *Server) handleBlobPut(w http.ResponseWriter, r *http.Request) {
	if s.Blobs == nil {
		writeErr(w, http.StatusServiceUnavailable, "no blob store configured")
		return
	}
	digest, size, err := s.Blobs.Put(r.Body)
	switch {
	case errors.Is(err, blob.ErrTooLarge):
		writeErr(w, http.StatusRequestEntityTooLarge,
			"content exceeds the limit of "+strconv.FormatInt(s.Blobs.Max(), 10)+" bytes")
		return
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"blob": digest, "size": size})
}

// handleBlobGet serves the bytes to a member who can see a live post naming
// them.
func (s *Server) handleBlobGet(w http.ResponseWriter, r *http.Request) {
	if s.Blobs == nil {
		writeErr(w, http.StatusServiceUnavailable, "no blob store configured")
		return
	}
	var req struct {
		Tuple  actor.Tuple `json:"tuple"`
		Digest string      `json:"blob"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed body")
		return
	}
	if !req.Tuple.Valid() {
		writeErr(w, http.StatusBadRequest, "incomplete workspace tuple")
		return
	}

	ok, name, err := s.blobReadable(req.Tuple, req.Digest)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		// The same answer whether the content does not exist or the caller may
		// not have it. Distinguishing them would turn a digest into an oracle
		// for what this mangrove holds.
		writeErr(w, http.StatusNotFound, "no content by that name is visible to you")
		return
	}

	rc, size, err := s.Blobs.Open(req.Digest)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rc.Close()

	// Never inline, whatever the bytes are. This mirrors the invariant the proxy
	// already holds for workspace media: a member's file does not render from
	// the origin that serves it.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeFileName(name)+`"`)
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = io.Copy(w, rc)
}

// blobReadable asks the ONE visibility rule, over the LIVE reduction.
//
// Both halves matter. Reading the audience list of the activity that carried the
// digest would answer the easy case and get the important one wrong: a revoked
// post's bytes would stay readable forever, because the audience of a tombstoned
// activity is still whatever it always was. The reduction is what knows a claim
// is dead, so the reduction is what decides.
//
// It also returns the file name of the claim that granted access, so the
// download is called what its author called it.
func (s *Server) blobReadable(t actor.Tuple, digest string) (bool, string, error) {
	if digest == "" || !s.Blobs.Has(digest) {
		return false, "", nil
	}
	acts, err := s.Log.Read(t.TenantID, t.SubsAccID)
	if err != nil {
		return false, "", err
	}
	v := newViewer(t, acts)
	for _, claims := range mangrovelog.Reduce(v.reachable(acts)) {
		for _, c := range claims {
			if !c.Deleted && c.Object.Blob == digest {
				return true, c.Object.FileName, nil
			}
		}
	}
	return false, "", nil
}

// sanitizeFileName keeps a name from breaking out of the header it sits in. It
// is display only -- nothing here ever resolves it to a path.
func sanitizeFileName(name string) string {
	if name == "" {
		return "download"
	}
	out := make([]rune, 0, len(name))
	for _, r := range name {
		switch {
		case r == '"', r == '\\', r == '\r', r == '\n', r < 0x20:
			out = append(out, '_')
		default:
			out = append(out, r)
		}
	}
	return string(out)
}
