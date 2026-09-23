package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LepistaBioinformatics/crab-mangrove-network/internal/actor"
)

// upload stores content the way crab-shell-proxy does and returns its digest.
func upload(t *testing.T, s *Server, content string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/blob", strings.NewReader(content))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	d, _ := out["blob"].(string)
	if d == "" {
		t.Fatalf("upload returned no digest: %v", out)
	}
	return d
}

func fetchBlob(t *testing.T, s *Server, who, digest string) *httptest.ResponseRecorder {
	t.Helper()
	rec, _ := call(t, s, "/internal/v1/blob/fetch", map[string]any{
		"tuple": tup(who), "blob": digest,
	}, true)
	return rec
}

func publishFile(t *testing.T, s *Server, who, cell, digest, name string, to []string) string {
	t.Helper()
	rec, out := call(t, s, "/internal/v1/publish", map[string]any{
		"tuple": tup(who), "as": "person",
		"to": to,
		"object": map[string]any{
			"type": "MemoryFile", "cell": cell,
			"blob": digest, "fileName": name, "size": 11,
		},
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("publish file: %d %s", rec.Code, rec.Body.String())
	}
	return out["activity"].(map[string]any)["object"].(map[string]any)["id"].(string)
}

// THE DISCRIMINATING TEST, written first and on purpose.
//
// "A stranger is refused" passes against a gate that reads the audience list of
// the activity at face value. This one does not: the audience of a tombstoned
// activity is still whatever it always was, so only a gate wired to the LIVE
// reduction takes the bytes away again.
func TestRevokingAPostTakesItsBytesWithIt(t *testing.T) {
	s := newServer(t)
	s.Members = threeMembers{}
	digest := upload(t, s, "soil data\n")
	objID := publishFile(t, s, "alice", "soil-2026", digest, "soil.csv",
		[]string{actor.ServiceID("bob")})

	if rec := fetchBlob(t, s, "bob", digest); rec.Code != http.StatusOK {
		t.Fatalf("the addressee could not fetch what was shared with them: %d %s", rec.Code, rec.Body.String())
	}

	rec, _ := call(t, s, "/internal/v1/revoke", map[string]any{
		"tuple": tup("alice"), "as": "person",
		"objectId": objID, "cell": "soil-2026",
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body.String())
	}

	if rec := fetchBlob(t, s, "bob", digest); rec.Code != http.StatusNotFound {
		t.Fatalf("a revoked post's bytes are still readable: %d %s", rec.Code, rec.Body.String())
	}
	// And the author loses it too. A tombstone is not a hide-from-others.
	if rec := fetchBlob(t, s, "alice", digest); rec.Code != http.StatusNotFound {
		t.Fatalf("the author still reads the bytes of a post they revoked: %d", rec.Code)
	}
}

func TestOnlySomebodyTheFileReachedMayFetchIt(t *testing.T) {
	s := newServer(t)
	s.Members = threeMembers{}
	digest := upload(t, s, "soil data\n")
	publishFile(t, s, "alice", "soil-2026", digest, "soil.csv", []string{actor.ServiceID("bob")})

	if rec := fetchBlob(t, s, "bob", digest); rec.Code != http.StatusOK {
		t.Errorf("the addressee was refused: %d", rec.Code)
	}
	if rec := fetchBlob(t, s, "alice", digest); rec.Code != http.StatusOK {
		t.Errorf("the author was refused their own file: %d", rec.Code)
	}
	// carol is in the subscription and was never addressed.
	if rec := fetchBlob(t, s, "carol", digest); rec.Code != http.StatusNotFound {
		t.Errorf("a member the file never reached fetched it: %d", rec.Code)
	}
}

// THE BLOB GATE IS THE SAME GATE, which is why sharing a FILE into a group was
// broken in the same way and by the same line: `reachable` calls `reach`, so a
// member could see neither the card nor the bytes behind it. Asserted here as
// well as on the timeline, because "one rule, one implementation" is the reason
// `visibility.go` exists and a second copy of it would drift silently.
func TestAFileSharedIntoAGroupCanBeFetchedByTheScope(t *testing.T) {
	s := newServer(t)
	s.Members = threeMembers{}
	digest := upload(t, s, "soil data\n")
	// Addressed to nobody: the share is the only thing that can reach anyone.
	objID := publishFile(t, s, "alice", "soil-2026", digest, "soil.csv", nil)

	if rec := fetchBlob(t, s, "carol", digest); rec.Code != http.StatusNotFound {
		t.Fatalf("carol reached the bytes before the share: %d", rec.Code)
	}

	rec, _ := call(t, s, "/internal/v1/share", map[string]any{
		"tuple": tup("alice"), "as": "person", "groupsLicensed": true,
		"objectId": objID, "target": actor.SubscriptionGroupID("s1"),
	}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("share to group: %d %s", rec.Code, rec.Body.String())
	}

	for _, who := range []string{"bob", "carol"} {
		if rec := fetchBlob(t, s, who, digest); rec.Code != http.StatusOK {
			t.Errorf("%s cannot fetch a file shared with their subscription: %d", who, rec.Code)
		}
	}
}

// Holding the bytes is not the same as being allowed to read them. An upload
// that was never published reaches nobody -- including the uploader, who has to
// name it in a post like everybody else.
func TestUploadedButUnpublishedReachesNobody(t *testing.T) {
	s := newServer(t)
	s.Members = threeMembers{}
	digest := upload(t, s, "not shared with anyone\n")

	for _, who := range []string{"alice", "bob", "carol"} {
		if rec := fetchBlob(t, s, who, digest); rec.Code != http.StatusNotFound {
			t.Errorf("%s fetched content no post names: %d", who, rec.Code)
		}
	}
}

// Content nobody holds and content you may not have answer the same way.
// Distinguishing them would turn a digest into an oracle for what this mangrove
// is storing.
func TestAnAbsentBlobAndAForbiddenOneAnswerAlike(t *testing.T) {
	s := newServer(t)
	s.Members = threeMembers{}
	digest := upload(t, s, "soil data\n")
	publishFile(t, s, "alice", "soil-2026", digest, "soil.csv", []string{actor.ServiceID("bob")})

	forbidden := fetchBlob(t, s, "carol", digest)
	absent := fetchBlob(t, s, "carol", strings.Repeat("ab", 32))
	if forbidden.Code != absent.Code {
		t.Errorf("forbidden=%d absent=%d; they must not be distinguishable", forbidden.Code, absent.Code)
	}
	if forbidden.Body.String() != absent.Body.String() {
		t.Errorf("bodies differ:\n forbidden %s\n absent    %s", forbidden.Body.String(), absent.Body.String())
	}
}

// A post naming content nobody holds is a broken promise made to every
// recipient, and the author is the only one who can still fix it. So it is
// refused at publish, not discovered at read.
func TestAFileNamingContentTheMangroveLacksIsRefused(t *testing.T) {
	s := newServer(t)
	rec, _ := call(t, s, "/internal/v1/publish", map[string]any{
		"tuple": tup("alice"), "as": "person",
		"object": map[string]any{
			"type": "MemoryFile", "cell": "c",
			"blob": strings.Repeat("cd", 32), "fileName": "ghost.txt", "size": 1,
		},
	}, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400 for a dangling blob reference", rec.Code)
	}
}

// The first branch on object type this service has ever had. Refusing the
// mixtures is what keeps a reader from having to ask which of the two a given
// object really is.
func TestTheTwoObjectTypesAreNotInterchangeable(t *testing.T) {
	s := newServer(t)
	digest := upload(t, s, "real bytes\n")

	for _, tc := range []struct {
		name string
		obj  map[string]any
	}{
		{"a note naming a blob", map[string]any{
			"type": "MemoryNote", "cell": "c", "content": "x", "blob": digest}},
		{"a note with a file name", map[string]any{
			"type": "MemoryNote", "cell": "c", "content": "x", "fileName": "a.txt"}},
		{"a file with inline content", map[string]any{
			"type": "MemoryFile", "cell": "c", "content": "x",
			"blob": digest, "fileName": "a.txt"}},
		{"a file naming no blob", map[string]any{
			"type": "MemoryFile", "cell": "c", "fileName": "a.txt"}},
		{"a file with no name", map[string]any{
			"type": "MemoryFile", "cell": "c", "blob": digest}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, _ := call(t, s, "/internal/v1/publish", map[string]any{
				"tuple": tup("alice"), "as": "person", "object": tc.obj,
			}, true)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("code = %d, want 400 (%s)", rec.Code, rec.Body.String())
			}
		})
	}
}

// Never inline, whatever the bytes are: a member's file must not render from
// the origin that serves it.
func TestBytesAreServedAsAnAttachment(t *testing.T) {
	s := newServer(t)
	s.Members = threeMembers{}
	digest := upload(t, s, "<script>alert(1)</script>")
	publishFile(t, s, "alice", "page", digest, "evil.html", []string{actor.ServiceID("bob")})

	rec := fetchBlob(t, s, "bob", digest)
	if rec.Code != http.StatusOK {
		t.Fatalf("fetch: %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") {
		t.Errorf("Content-Disposition = %q, want an attachment", cd)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("no nosniff; the browser may sniff its way to rendering it anyway")
	}
	if rec.Body.String() != "<script>alert(1)</script>" {
		t.Error("the bytes did not survive")
	}
}

// A name goes into a header, so it must not be able to break out of one.
func TestAFileNameCannotBreakTheHeader(t *testing.T) {
	s := newServer(t)
	s.Members = threeMembers{}
	digest := upload(t, s, "bytes\n")
	publishFile(t, s, "alice", "c", digest,
		"a\"; filename=\"b\r\nX-Injected: yes", []string{actor.ServiceID("bob")})

	rec := fetchBlob(t, s, "bob", digest)
	cd := rec.Header().Get("Content-Disposition")
	if strings.Contains(cd, "\r") || strings.Contains(cd, "\n") {
		t.Errorf("newlines survived into the header: %q", cd)
	}
	if rec.Header().Get("X-Injected") != "" {
		t.Error("a header was injected through the file name")
	}
	if strings.Count(cd, `"`) != 2 {
		t.Errorf("quotes were not neutralised: %q", cd)
	}
}
