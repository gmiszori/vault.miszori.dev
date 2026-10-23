package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func reusablePackage(t *testing.T, s *Server) string {
	t.Helper()
	w := request(s, "POST", "/api/admin/packages", []byte(`{"ttlSeconds":3600,"oneTime":false}`), true, "")
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body)
	}
	var created struct{ ID, UploadToken string }
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 2; n++ {
		w = request(s, "PUT", "/api/admin/packages/"+created.ID+"/chunks/"+strconv.Itoa(n), bytes.Repeat([]byte{byte(n)}, 32), true, created.UploadToken)
		if w.Code != 204 {
			t.Fatal(w.Code, w.Body)
		}
	}
	w = request(s, "POST", "/api/admin/packages/"+created.ID+"/finalize", finalizeBody(2), true, created.UploadToken)
	if w.Code != 204 {
		t.Fatal(w.Code, w.Body)
	}
	return created.ID
}

func auditPage(t *testing.T, s *Server, id, query string) retrievalPage {
	t.Helper()
	w := request(s, "GET", "/api/admin/packages/"+id+"/retrievals"+query, nil, true, "")
	if w.Code != 200 {
		t.Fatalf("audit: %d %s", w.Code, w.Body)
	}
	var page retrievalPage
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	return page
}

func TestReusableProofAndRepeatedRetrieval(t *testing.T) {
	s := testServer(t)
	id := reusablePackage(t, s)
	for _, token := range []string{"", "invalid", downloadClaimHashFixture} {
		if w := directClaim(s, id, token, nil); w.Code != 404 {
			t.Fatal("invalid proof accepted", w.Code)
		}
	}
	if page := auditPage(t, s, id, ""); len(page.Retrievals) != 0 || page.NextCursor != "" {
		t.Fatal("invalid claims audited as retrievals", page)
	}
	var first []byte
	for i := 0; i < 3; i++ {
		r := httptest.NewRequest("POST", "/api/packages/"+id+"/consume", nil)
		r.Header.Set("X-Claim-Token", downloadClaimTokenFixture)
		r.Header.Set("User-Agent", fmt.Sprintf("Firefox/130 Linux retry-%d", i))
		r.RemoteAddr = fmt.Sprintf("192.0.2.%d:1234", i+1)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 200 || w.Body.Len() != 72 {
			t.Fatal(w.Code, w.Body)
		}
		if i == 0 {
			first = append([]byte(nil), w.Body.Bytes()...)
		} else if !bytes.Equal(first, w.Body.Bytes()) {
			t.Fatal("repeated retrieval changed ciphertext")
		}
	}
	p := s.packages[id]
	if p.OneTime || p.Status != "ready" || p.RetrievalCount != 3 {
		t.Fatal("reusable package consumed", p)
	}
	page := auditPage(t, s, id, "")
	if len(page.Retrievals) != 3 {
		t.Fatal(page)
	}
	for i, record := range page.Retrievals {
		if record.OpenedAt.IsZero() || record.OpenedIP != fmt.Sprintf("192.0.2.%d", i+1) || record.OpenedBrowser == nil || record.OpenedBrowser.UserAgent != fmt.Sprintf("Firefox/130 Linux retry-%d", i) {
			t.Fatal("incomplete retrieval audit", record)
		}
	}
}

type pausedRetrievalWriter struct {
	*httptest.ResponseRecorder
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *pausedRetrievalWriter) Write(data []byte) (int, error) {
	w.once.Do(func() {
		close(w.started)
		<-w.release
	})
	return w.ResponseRecorder.Write(data)
}

func startPausedRetrieval(t *testing.T, s *Server, id string) (*pausedRetrievalWriter, <-chan struct{}) {
	t.Helper()
	w := &pausedRetrievalWriter{ResponseRecorder: httptest.NewRecorder(), started: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		r := httptest.NewRequest("POST", "/api/packages/"+id+"/consume", nil)
		r.Header.Set("X-Claim-Token", downloadClaimTokenFixture)
		s.ServeHTTP(w, r)
	}()
	select {
	case <-w.started:
	case <-time.After(10 * time.Second):
		t.Fatal("retrieval did not start")
	}
	t.Cleanup(func() {
		select {
		case <-w.release:
		default:
			close(w.release)
		}
		<-done
	})
	return w, done
}

func TestReusableParallelGateAndDurableAudit(t *testing.T) {
	s := testServer(t)
	id := reusablePackage(t, s)
	writers := make([]*pausedRetrievalWriter, s.gate.limits.maxDownloads)
	dones := make([]<-chan struct{}, len(writers))
	for i := range writers {
		writers[i], dones[i] = startPausedRetrieval(t, s, id)
	}
	if w := directClaim(s, id, downloadClaimTokenFixture, nil); w.Code != 429 {
		t.Fatal("download gate bypassed", w.Code)
	}
	if page := auditPage(t, s, id, ""); len(page.Retrievals) != len(writers) {
		t.Fatal("started streams not all audited before bytes", page)
	}
	// Simulate a crash snapshot: audit counts and ready reusable data must survive restart.
	restarted, err := newServer(s.root, s.user, "", s.origin, s.quota)
	if err != nil {
		t.Fatal(err)
	}
	if p := restarted.packages[id]; p.OneTime || p.Status != "ready" || p.RetrievalCount != int64(len(writers)) {
		t.Fatal("restart destroyed active reusable package", p)
	}
	for i, w := range writers {
		close(w.release)
		<-dones[i]
		if w.Code != 200 || w.Body.Len() != 72 {
			t.Fatal("parallel retrieval truncated", w.Code)
		}
	}
	if w := directClaim(restarted, id, downloadClaimTokenFixture, nil); w.Code != 200 {
		t.Fatal("restarted reusable proof failed", w.Code)
	}
}

func TestReusableInterruptedRetry(t *testing.T) {
	s := testServer(t)
	id := reusablePackage(t, s)
	r := httptest.NewRequest("POST", "/api/packages/"+id+"/consume", nil)
	r.Header.Set("X-Claim-Token", downloadClaimTokenFixture)
	s.ServeHTTP(&brokenWriter{make(http.Header)}, r)
	if p := s.packages[id]; p.Status != "ready" || p.RetrievalCount != 1 {
		t.Fatal("interrupted reusable transfer consumed", p)
	}
	if w := directClaim(s, id, downloadClaimTokenFixture, nil); w.Code != 200 || w.Body.Len() != 72 {
		t.Fatal("retry failed", w.Code)
	}
	if page := auditPage(t, s, id, ""); len(page.Retrievals) != 2 {
		t.Fatal("interrupted start omitted", page)
	}
}

func TestReusableRevocationDefersCleanupWithoutResurrection(t *testing.T) {
	for _, action := range []string{"delete", "expire"} {
		t.Run(action, func(t *testing.T) {
			s := testServer(t)
			id := reusablePackage(t, s)
			first, firstDone := startPausedRetrieval(t, s, id)
			second, secondDone := startPausedRetrieval(t, s, id)
			want := "deleted"
			if action == "delete" {
				if w := request(s, "DELETE", "/api/admin/packages/"+id, nil, true, ""); w.Code != 204 {
					t.Fatal(w.Code, w.Body)
				}
			} else {
				want = "expired"
				s.mu.Lock()
				now := s.packages[id].ExpiresAt
				s.now = func() time.Time { return now }
				s.mu.Unlock()
			}
			var wg sync.WaitGroup
			errs := make(chan error, 8)
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() { defer wg.Done(); errs <- s.sweep() }()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			if w := directClaim(s, id, downloadClaimTokenFixture, nil); w.Code != 404 {
				t.Fatal("revoked package retrievable", w.Code)
			}
			if w := request(s, "GET", "/api/packages/"+id, nil, false, ""); w.Code != 404 {
				t.Fatal("revoked metadata visible", w.Code)
			}
			close(first.release)
			<-firstDone
			if _, err := os.Stat(s.chunk(id, 1)); err != nil {
				t.Fatal("cleanup raced remaining stream", err)
			}
			used, _ := storageStats(t, s)
			if used != 64 {
				t.Fatal("deferred ciphertext not counted", used)
			}
			close(second.release)
			<-secondDone
			if first.Body.Len() != 72 || second.Body.Len() != 72 || s.packages[id].Status != want {
				t.Fatal("active stream failed or resurrected package")
			}
			if _, err := os.Stat(s.chunk(id, 0)); !os.IsNotExist(err) {
				t.Fatal("deferred ciphertext not removed", err)
			}
			if len(auditPage(t, s, id, "").Retrievals) != 2 {
				t.Fatal("revocation lost audit")
			}
			restarted, err := newServer(s.root, s.user, "", s.origin, s.quota)
			if err != nil || restarted.packages[id].Status != want {
				t.Fatal("revocation lost on restart", err)
			}
			p := restarted.packages[id]
			restarted.now = func() time.Time { return p.ExpiresAt.Add(90 * 24 * time.Hour) }
			if err := restarted.sweep(); err != nil {
				t.Fatal(err)
			}
			if len(auditPage(t, restarted, id, "").Retrievals) != 2 {
				t.Fatal("audit retention shortened")
			}
			restarted.now = func() time.Time { return p.ExpiresAt.Add(90*24*time.Hour + time.Second) }
			if err := restarted.sweep(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(s.dir(id)); !os.IsNotExist(err) {
				t.Fatal("retention failed", err)
			}
		})
	}
}

func TestRetrievalPaginationPrivacyAndCount(t *testing.T) {
	s := testServer(t)
	id := reusablePackage(t, s)
	now := time.Now()
	s.now = func() time.Time { return now }
	for i := 0; i < 205; i++ {
		// Stay within the per-package claim limit while building a multi-page log.
		if i%maxClaimsPerPackagePerMinute == 0 {
			now = now.Add(time.Minute)
		}
		r := httptest.NewRequest("POST", "/api/packages/"+id+"/consume", nil)
		r.Header.Set("X-Claim-Token", downloadClaimTokenFixture)
		r.Header.Set("User-Agent", fmt.Sprintf("Firefox/130 Linux record-%d <script>", i))
		r.RemoteAddr = fmt.Sprintf("192.0.%d.%d:1234", i/100, i%100+1)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal("retrieval count capped", i, w.Code)
		}
	}
	path := "/api/admin/packages/" + id + "/retrievals"
	if w := request(s, "GET", path, nil, false, ""); w.Code != 401 {
		t.Fatal("unauthenticated audit", w.Code)
	}
	for _, path := range []string{"/api/packages/" + id, "/api/packages/" + id + "/retrievals", "/api/packages/" + id + "/" + retrievalLogName} {
		w := request(s, "GET", path, nil, false, "")
		for _, secret := range []string{"openedAt", "openedIp", "openedBrowser", "retrievalCount", "record-", "192.0."} {
			if strings.Contains(w.Body.String(), secret) {
				t.Fatal("public audit leak", path, secret)
			}
		}
	}
	cursor := ""
	total := 0
	for _, want := range []int{100, 100, 5} {
		query := ""
		if cursor != "" {
			query = "?cursor=" + cursor + "&limit=100"
		}
		page := auditPage(t, s, id, query)
		if len(page.Retrievals) != want {
			t.Fatal("page size", len(page.Retrievals), want)
		}
		for _, record := range page.Retrievals {
			if record.OpenedBrowser.UserAgent != fmt.Sprintf("Firefox/130 Linux record-%d <script>", total) {
				t.Fatal("duplicate or missing retrieval", total)
			}
			total++
		}
		cursor = page.NextCursor
		if total < 205 && cursor == "" {
			t.Fatal("missing continuation")
		}
	}
	if cursor != "" {
		t.Fatal("nonempty final cursor")
	}
	for _, query := range []string{"?cursor=-1", "?cursor=abc", "?cursor=1", "?cursor=999999999", "?cursor=9223372036854775808", "?cursor=0&cursor=0", "?cursor=%zz", "?limit=0", "?limit=101", "?limit=abc", "?limit=1&limit=2"} {
		if w := request(s, "GET", path+query, nil, true, ""); w.Code != 400 {
			t.Fatal("invalid pagination accepted", query, w.Code)
		}
	}
	page := auditPage(t, s, id, "?limit=1")
	if len(page.Retrievals) != 1 || page.NextCursor == "" {
		t.Fatal("small page failed")
	}
	info, err := os.Stat(filepath.Join(s.dir(id), retrievalLogName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("audit permissions", info.Mode())
	}
	if page := auditPage(t, s, id, "?cursor="+strconv.FormatInt(info.Size(), 10)); len(page.Retrievals) != 0 {
		t.Fatal("EOF cursor")
	}
	list := request(s, "GET", "/api/admin/packages", nil, true, "")
	if !bytes.Contains(list.Body.Bytes(), []byte(`"retrievalCount":205`)) || !bytes.Contains(list.Body.Bytes(), []byte(`"oneTime":false`)) {
		t.Fatal("admin schema missing", list.Body)
	}
	if bytes.Contains(list.Body.Bytes(), []byte("<script>")) {
		t.Fatal("unescaped audit profile")
	}
	restarted, err := newServer(s.root, s.user, "", s.origin, s.quota)
	if err != nil || restarted.packages[id].RetrievalCount != 205 {
		t.Fatal("audit count lost on restart", err)
	}
}

func TestLegacyOneTimeDefaultAndAuditFallback(t *testing.T) {
	s := testServer(t)
	id := readyPackage(t, s)
	if !s.packages[id].OneTime {
		t.Fatal("omitted oneTime did not default true")
	}
	name := filepath.Join(s.dir(id), "meta.json")
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var disk map[string]any
	if err := json.Unmarshal(data, &disk); err != nil {
		t.Fatal(err)
	}
	delete(disk, "oneTime")
	data, _ = json.Marshal(disk)
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
	restarted, err := newServer(s.root, s.user, "", s.origin, s.quota)
	if err != nil || !restarted.packages[id].OneTime {
		t.Fatal("legacy package became reusable", err)
	}
	meta := request(restarted, "GET", "/api/packages/"+id, nil, false, "")
	if !bytes.Contains(meta.Body.Bytes(), []byte(`"oneTime":true`)) {
		t.Fatal("public mode missing")
	}
	if w := directClaim(restarted, id, downloadClaimTokenFixture, nil); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := directClaim(restarted, id, downloadClaimTokenFixture, nil); w.Code != 404 {
		t.Fatal("legacy repeat accepted")
	}
	if err := os.Remove(filepath.Join(s.dir(id), retrievalLogName)); err != nil {
		t.Fatal(err)
	}
	restarted, err = newServer(s.root, s.user, "", s.origin, s.quota)
	if err != nil {
		t.Fatal(err)
	}
	page := auditPage(t, restarted, id, "")
	if len(page.Retrievals) != 1 || restarted.packages[id].RetrievalCount != 1 || page.NextCursor != "" {
		t.Fatal("legacy fallback missing", page)
	}
	// A historical reusable record is migrated once, not repeated on every append.
	p := restarted.packages[id]
	p.OneTime, p.Status = false, "ready"
	for i := 0; i < 2; i++ {
		if err := restarted.appendRetrieval(p, Retrieval{OpenedAt: time.Now(), OpenedIP: "192.0.2.5"}); err != nil {
			t.Fatal(err)
		}
	}
	if page := auditPage(t, restarted, id, ""); len(page.Retrievals) != 3 || p.RetrievalCount != 3 {
		t.Fatal("legacy duplicated", page)
	}
}

func TestRetrievalAuditDiskFailureBeforeBytes(t *testing.T) {
	for _, oneTime := range []bool{true, false} {
		t.Run(strconv.FormatBool(oneTime), func(t *testing.T) {
			s := testServer(t)
			id := reusablePackage(t, s)
			if oneTime {
				id = readyPackage(t, s)
			}
			path := filepath.Join(s.dir(id), retrievalLogName)
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			w := directClaim(s, id, downloadClaimTokenFixture, nil)
			if w.Code != 500 || w.Header().Get("Content-Type") == "application/octet-stream" || bytes.Contains(w.Body.Bytes(), make([]byte, 16)) {
				t.Fatal("audit error served ciphertext", w.Code)
			}
			if s.packages[id].RetrievalCount != 0 || s.packages[id].OpenedAt != nil {
				t.Fatal("failed audit counted")
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if w := directClaim(s, id, downloadClaimTokenFixture, nil); w.Code != 200 {
				t.Fatal("safe retry failed", w.Code)
			}
		})
	}
}

func TestRestartCleansDeferredRevocation(t *testing.T) {
	s := testServer(t)
	id := reusablePackage(t, s)
	writer, done := startPausedRetrieval(t, s, id)
	if w := request(s, "DELETE", "/api/admin/packages/"+id, nil, true, ""); w.Code != 204 {
		t.Fatal(w.Code)
	}
	restarted, err := newServer(s.root, s.user, "", s.origin, s.quota)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.chunk(id, 1)); !os.IsNotExist(err) {
		t.Fatal("restart retained revoked ciphertext", err)
	}
	if restarted.packages[id].Status != "deleted" || len(auditPage(t, restarted, id, "").Retrievals) != 1 {
		t.Fatal("restart lost revocation/audit")
	}
	close(writer.release)
	<-done
	if s.packages[id].Status != "deleted" {
		t.Fatal("revocation resurrected")
	}
}
