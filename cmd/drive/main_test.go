package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	s, e := newServer(t.TempDir(), "admin", testSetupToken, "https://drive.example", 100*1024*1024)
	if e != nil {
		t.Fatal(e)
	}
	if w := request(s, "POST", "/api/admin/setup", setupBody(testSetupToken, testAuthentication), false, ""); w.Code != 204 {
		t.Fatalf("setup: %d %s", w.Code, w.Body)
	}
	return s
}
func request(s *Server, method, path string, body []byte, auth bool, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.RemoteAddr = "192.0.2.55:1234"
	if auth {
		r.SetBasicAuth("admin", testAuthentication)
	}
	if token != "" {
		r.Header.Set("X-Upload-Token", token)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func createPackage(t *testing.T, s *Server) (string, string) {
	t.Helper()
	w := request(s, "POST", "/api/admin/packages", []byte(`{"ttlSeconds":3600}`), true, "")
	if w.Code != 201 {
		t.Fatalf("create %d %s", w.Code, w.Body)
	}
	var v struct{ ID, UploadToken string }
	if e := json.Unmarshal(w.Body.Bytes(), &v); e != nil {
		t.Fatal(e)
	}
	return v.ID, v.UploadToken
}
func readyPackage(t *testing.T, s *Server) string {
	t.Helper()
	id, token := createPackage(t, s)
	for i := 0; i < 2; i++ {
		w := request(s, "PUT", "/api/admin/packages/"+id+"/chunks/"+string(rune('0'+i)), bytes.Repeat([]byte{byte(i)}, 32), true, token)
		if w.Code != 204 {
			t.Fatalf("upload %d %s", w.Code, w.Body)
		}
	}
	w := request(s, "POST", "/api/admin/packages/"+id+"/finalize", []byte(`{"chunks":2}`), true, token)
	if w.Code != 204 {
		t.Fatal(w.Code, w.Body)
	}
	return id
}
func TestOneTimeDownload(t *testing.T) {
	s := testServer(t)
	id := readyPackage(t, s)
	if w := request(s, "GET", "/api/packages/"+id, nil, false, ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if s.packages[id].Status != "ready" {
		t.Fatal("GET consumed package")
	}
	w := request(s, "POST", "/api/packages/"+id+"/consume", nil, false, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	b := w.Body.Bytes()
	for i := 0; i < 2; i++ {
		n := binary.BigEndian.Uint32(b[:4])
		if n != 32 || !bytes.Equal(b[4:36], bytes.Repeat([]byte{byte(i)}, 32)) {
			t.Fatal("incorrect frame")
		}
		b = b[36:]
	}
	if len(b) != 0 {
		t.Fatal("extra bytes")
	}
	p := s.packages[id]
	if p.Status != "consumed" || p.OpenedIP != "192.0.2.55" || p.OpenedAt == nil {
		t.Fatal("missing audit data")
	}
	entries, _ := os.ReadDir(s.dir(id))
	if len(entries) != 1 || entries[0].Name() != "meta.json" {
		t.Fatal("ciphertext not deleted")
	}
	if request(s, "POST", "/api/packages/"+id+"/consume", nil, false, "").Code != 404 {
		t.Fatal("second download allowed")
	}
}
func TestConcurrentClaim(t *testing.T) {
	s := testServer(t)
	id := readyPackage(t, s)
	var wg sync.WaitGroup
	codes := make(chan int, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- request(s, "POST", "/api/packages/"+id+"/consume", nil, false, "").Code
		}()
	}
	wg.Wait()
	close(codes)
	success := 0
	for c := range codes {
		if c == 200 {
			success++
		} else if c != 404 {
			t.Fatal(c)
		}
	}
	if success != 1 {
		t.Fatalf("claims: %d", success)
	}
}
func TestExpiryAndRecovery(t *testing.T) {
	s := testServer(t)
	id := readyPackage(t, s)
	s.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if request(s, "GET", "/api/packages/"+id, nil, false, "").Code != 404 {
		t.Fatal("expired accessible")
	}
	if e := s.sweep(); e != nil {
		t.Fatal(e)
	}
	if s.packages[id].Status != "expired" {
		t.Fatal("not expired")
	}
	id2 := readyPackage(t, s)
	s.packages[id2].Status = "consuming"
	if e := s.save(s.packages[id2]); e != nil {
		t.Fatal(e)
	}
	s2, e := newServer(s.root, s.user, "", s.origin, s.quota)
	if e != nil {
		t.Fatal(e)
	}
	if s2.packages[id2].Status != "failed" {
		t.Fatal("crashed download not destroyed")
	}
	matches, _ := filepath.Glob(filepath.Join(s.dir(id2), "*.bin"))
	if len(matches) != 0 {
		t.Fatal("crashed download data retained")
	}
}
func TestUploadValidation(t *testing.T) {
	s := testServer(t)
	id, token := createPackage(t, s)
	base := "/api/admin/packages/" + id
	cases := []struct {
		method, path, body, token string
		code                      int
	}{{"PUT", base + "/chunks/0", strings.Repeat("x", 16), "wrong", 403}, {"PUT", base + "/chunks/1", strings.Repeat("x", 16), token, 409}, {"PUT", base + "/chunks/0", "short", token, 413}, {"POST", base + "/finalize", `{"chunks":1}`, token, 400}}
	for _, c := range cases {
		w := request(s, c.method, c.path, []byte(c.body), true, c.token)
		if w.Code != c.code {
			t.Fatalf("%s: %d want %d", c.path, w.Code, c.code)
		}
	}
	w := request(s, "PUT", base+"/chunks/0", make([]byte, maxChunk+1), true, token)
	if w.Code != 413 {
		t.Fatal("oversized chunk accepted")
	}
	s.quota = 16
	w = request(s, "PUT", base+"/chunks/0", make([]byte, 32), true, token)
	if w.Code != 413 {
		t.Fatal("quota ignored")
	}
}
func TestAuthAndCSRF(t *testing.T) {
	s := testServer(t)
	if request(s, "GET", "/api/admin/packages", nil, false, "").Code != 401 {
		t.Fatal("unauthorized admin")
	}
	r := httptest.NewRequest("POST", "/api/admin/packages", strings.NewReader(`{"ttlSeconds":3600}`))
	r.SetBasicAuth(s.user, testAuthentication)
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("cross-origin accepted")
	}
	for i := 0; i < 21; i++ {
		w = request(s, "GET", "/api/admin/packages", nil, false, "")
	}
	if w.Code != 429 {
		t.Fatal("no auth throttling")
	}
	if request(s, "GET", "/api/packages/../meta.json", nil, false, "").Code != 404 {
		t.Fatal("invalid path")
	}
}

type brokenWriter struct{ header http.Header }

func (w *brokenWriter) Header() http.Header       { return w.header }
func (w *brokenWriter) WriteHeader(int)           {}
func (w *brokenWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestDisconnectedClientDeletes(t *testing.T) {
	s := testServer(t)
	id := readyPackage(t, s)
	r := httptest.NewRequest("POST", "/api/packages/"+id+"/consume", nil)
	s.ServeHTTP(&brokenWriter{make(http.Header)}, r)
	if s.packages[id].Status != "failed" {
		t.Fatal("disconnect not recorded")
	}
	matches, _ := filepath.Glob(filepath.Join(s.dir(id), "*.bin"))
	if len(matches) != 0 {
		t.Fatal("disconnect retained ciphertext")
	}
}
func TestRestartPreservesReadyDropsUnfinished(t *testing.T) {
	s := testServer(t)
	ready := readyPackage(t, s)
	unfinished, token := createPackage(t, s)
	if w := request(s, "PUT", "/api/admin/packages/"+unfinished+"/chunks/0", bytes.Repeat([]byte{1}, 32), true, token); w.Code != 204 {
		t.Fatal(w.Code)
	}
	restarted, err := newServer(s.root, s.user, "", s.origin, s.quota)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.packages[unfinished].Status != "failed" {
		t.Fatal("unfinished upload survived restart")
	}
	matches, _ := filepath.Glob(filepath.Join(s.dir(unfinished), "*.bin"))
	if len(matches) != 0 {
		t.Fatal("unfinished ciphertext retained")
	}
	if w := request(restarted, "POST", "/api/packages/"+ready+"/consume", nil, false, ""); w.Code != 200 {
		t.Fatal("ready package did not survive restart", w.Code)
	}
}

func TestDeleteAndSecretFreeMetadata(t *testing.T) {
	s := testServer(t)
	id, token := createPackage(t, s)
	b, _ := os.ReadFile(filepath.Join(s.dir(id), "meta.json"))
	if bytes.Contains(b, []byte(token)) {
		t.Fatal("plaintext upload token persisted")
	}
	w := request(s, "GET", "/api/admin/packages", nil, true, "")
	if bytes.Contains(w.Body.Bytes(), []byte("tokenHash")) {
		t.Fatal("token hash exposed")
	}
	if request(s, "DELETE", "/api/admin/packages/"+id, nil, true, "").Code != 204 {
		t.Fatal("delete failed")
	}
	if s.packages[id].Status != "deleted" {
		t.Fatal("delete status")
	}
}
