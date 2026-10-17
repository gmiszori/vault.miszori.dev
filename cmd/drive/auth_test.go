package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testSetupToken = "test-enrollment-token-at-least-32-characters"
const testAuthentication = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"

func setupBody(token, authentication string) []byte {
	b, _ := json.Marshal(map[string]string{"setupToken": token, "authentication": authentication})
	return b
}

func freshServer(t *testing.T) *Server {
	t.Helper()
	s, err := newServer(t.TempDir(), "", testSetupToken, "https://drive.example", 100*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func basicRequest(s *Server, user, secret string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/api/admin/packages", nil)
	r.SetBasicAuth(user, secret)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func authDiscovery(t *testing.T, s *Server, initialized bool) {
	t.Helper()
	w := request(s, "GET", "/api/admin/auth", nil, false, "")
	var v struct {
		Initialized  bool     `json:"initialized"`
		Username     string   `json:"username"`
		LabelKey     LabelKey `json:"labelKey"`
		PublicOrigin string   `json:"publicOrigin"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &v) != nil || v.Initialized != initialized || v.Username != s.user || v.LabelKey != s.labelKey || v.PublicOrigin != s.origin {
		t.Fatalf("discovery: %d %s", w.Code, w.Body)
	}
}

func TestFirstEnrollmentAndVerifierOnlyStorage(t *testing.T) {
	s := freshServer(t)
	authDiscovery(t, s, false)
	for _, path := range []string{"config", "packages"} {
		if w := request(s, "GET", "/api/admin/"+path, nil, true, ""); w.Code != 401 {
			t.Fatalf("uninitialized admin allowed: %d", w.Code)
		}
	}
	if w := request(s, "POST", "/api/admin/setup", setupBody(testSetupToken, testAuthentication), false, ""); w.Code != 204 || w.Body.Len() != 0 {
		t.Fatalf("setup: %d %s", w.Code, w.Body)
	}
	authDiscovery(t, s, true)
	if w := basicRequest(s, "admin", testAuthentication); w.Code != 200 {
		t.Fatalf("correct secret denied: %d", w.Code)
	}
	decoded, _ := base64.RawURLEncoding.DecodeString(testAuthentication)
	digest := sha256.Sum256(decoded)
	verifier := hex.EncodeToString(digest[:])
	for _, secret := range []string{verifier, base64.RawURLEncoding.EncodeToString(digest[:]), testSetupToken, "password", testAuthentication + "="} {
		if w := basicRequest(s, "admin", secret); w.Code != 401 {
			t.Fatalf("non-secret credential accepted: %d", w.Code)
		}
	}
	if w := basicRequest(s, "other", testAuthentication); w.Code != 401 {
		t.Fatal("wrong username accepted")
	}
	id := readyPackage(t, s)
	paths := []string{filepath.Join(s.root, "auth.json"), filepath.Join(s.dir(id), "meta.json")}
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, decoded) {
			t.Fatalf("decoded authentication secret persisted in %s", path)
		}
		for _, secret := range []string{testSetupToken, testAuthentication, "password"} {
			if bytes.Contains(b, []byte(secret)) {
				t.Fatalf("credential persisted in %s", path)
			}
		}
	}
	b, _ := os.ReadFile(paths[0])
	var stored map[string]any
	if json.Unmarshal(b, &stored) != nil || len(stored) != 3 || stored["version"] != float64(1) || stored["username"] != "admin" || stored["verifier"] != verifier {
		t.Fatalf("bad auth record: %s", b)
	}
	if w := request(s, "POST", "/api/admin/setup", setupBody(testSetupToken, testAuthentication), false, ""); w.Code != 409 {
		t.Fatalf("duplicate enrollment: %d", w.Code)
	}
}

func TestSetupValidation(t *testing.T) {
	valid := string(setupBody(testSetupToken, testAuthentication))
	cases := []struct {
		name, body string
		code       int
	}{
		{"bad token", string(setupBody("wrong", testAuthentication)), 401},
		{"missing token", string(setupBody("", testAuthentication)), 400},
		{"missing authentication", `{"setupToken":"` + testSetupToken + `"}`, 400},
		{"null", "null", 400},
		{"array", "[]", 400},
		{"empty", "", 400},
		{"extra", strings.TrimSuffix(valid, "}") + `,"password":"not-allowed"}`, 400},
		{"trailing", valid + "{}", 400},
		{"wrong type", `{"setupToken":42,"authentication":"` + testAuthentication + `"}`, 400},
		{"oversized", strings.Repeat(" ", 4096) + valid, 400},
	}
	for _, secret := range []string{"", "x", testAuthentication + "=", testAuthentication[:42] + "F", base64.RawURLEncoding.EncodeToString(make([]byte, 31)), base64.RawURLEncoding.EncodeToString(make([]byte, 33)), strings.Repeat("/", 43), strings.Repeat("A", 42) + "\n"} {
		cases = append(cases, struct {
			name, body string
			code       int
		}{"invalid secret " + fmt.Sprint(len(cases)), string(setupBody(testSetupToken, secret)), 400})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := freshServer(t)
			if w := request(s, "POST", "/api/admin/setup", []byte(tc.body), false, ""); w.Code != tc.code {
				t.Fatalf("got %d want %d: %s", w.Code, tc.code, w.Body)
			}
			if _, err := os.Stat(filepath.Join(s.root, "auth.json")); !os.IsNotExist(err) {
				t.Fatal("invalid setup persisted", err)
			}
			authDiscovery(t, s, false)
		})
	}
}

func TestConcurrentSetup(t *testing.T) {
	s := freshServer(t)
	var wg sync.WaitGroup
	codes := make(chan int, 16)
	for i := 0; i < cap(codes); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- request(s, "POST", "/api/admin/setup", setupBody(testSetupToken, testAuthentication), false, "").Code
		}()
	}
	wg.Wait()
	close(codes)
	success := 0
	for code := range codes {
		if code == 204 {
			success++
		} else if code != 409 {
			t.Fatalf("unexpected setup status %d", code)
		}
	}
	if success != 1 {
		t.Fatalf("successful setups: %d", success)
	}
}

func TestAuthRestartAndFreshTokenRequirement(t *testing.T) {
	for _, token := range []string{"", strings.Repeat("x", 31)} {
		if _, err := newServer(t.TempDir(), "admin", token, "https://drive.example", 1000); err == nil {
			t.Fatal("fresh startup without strong setup token")
		}
	}
	s := testServer(t)
	before, err := os.ReadFile(filepath.Join(s.root, "label-salt"))
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := newServer(s.root, "changed-admin", "", s.origin, s.quota)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.user != "admin" || restarted.labelKey != s.labelKey {
		t.Fatal("persisted identity or salt changed")
	}
	if basicRequest(restarted, "admin", testAuthentication).Code != 200 {
		t.Fatal("restart login failed")
	}
	authDiscovery(t, restarted, true)
	for _, name := range []string{"auth.json", "label-salt"} {
		info, err := os.Stat(filepath.Join(s.root, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("wrong permissions", name, err)
		}
	}
	after, _ := os.ReadFile(filepath.Join(s.root, "label-salt"))
	if !bytes.Equal(before, after) {
		t.Fatal("salt rotated")
	}
	entries, _ := os.ReadDir(s.root)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".auth-") {
			t.Fatal("auth staging file retained")
		}
	}
}

func TestCorruptAuthFailsClosed(t *testing.T) {
	s := testServer(t)
	v := strings.Repeat("a", 64)
	for _, content := range []string{"", "null", "{}", "not json", `{"version":2,"username":"admin","verifier":"` + v + `"}`, `{"version":1,"username":"","verifier":"` + v + `"}`, `{"version":1,"username":"admin","verifier":"` + strings.Repeat("A", 64) + `"}`, `{"version":1,"username":"admin","verifier":"` + v + `","authentication":"secret"}`, `{"version":1,"username":"admin","verifier":"` + v + `"}{}`, strings.Repeat("x", 4097)} {
		if err := os.WriteFile(filepath.Join(s.root, "auth.json"), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := newServer(s.root, s.user, testSetupToken, s.origin, s.quota); err == nil {
			t.Fatalf("invalid auth accepted: %q", content)
		}
	}
}

func TestMissingAuthKeepsPublicDownloadsAndSalt(t *testing.T) {
	s := testServer(t)
	id := readyPackage(t, s)
	patchLabel(t, s, id, nameEnvelope(17))
	if err := os.Remove(filepath.Join(s.root, "auth.json")); err != nil {
		t.Fatal(err)
	}
	restarted, err := newServer(s.root, "new-admin", testSetupToken, s.origin, s.quota)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.labelKey != s.labelKey {
		t.Fatal("salt rotated")
	}
	authDiscovery(t, restarted, false)
	if w := request(restarted, "GET", "/api/admin/config", nil, true, ""); w.Code != 401 {
		t.Fatal("admin available without setup")
	}
	if w := request(restarted, "GET", "/api/packages/"+id, nil, false, ""); w.Code != 200 {
		t.Fatal("public metadata unavailable")
	}
	if w := request(restarted, "POST", "/api/packages/"+id+"/consume", nil, false, ""); w.Code != 200 {
		t.Fatal("public download unavailable")
	}
	if w := request(restarted, "POST", "/api/admin/setup", setupBody(testSetupToken, testAuthentication), false, ""); w.Code != 204 {
		t.Fatal("new enrollment with existing data denied")
	}
	if basicRequest(restarted, "new-admin", testAuthentication).Code != 200 {
		t.Fatal("configured username ignored")
	}
}

func TestEnrollmentCSRFAndRateLimits(t *testing.T) {
	for _, endpoint := range []string{"auth", "setup"} {
		for _, header := range []string{"Origin", "Sec-Fetch-Site"} {
			s := freshServer(t)
			method := "GET"
			if endpoint == "setup" {
				method = "POST"
			}
			r := httptest.NewRequest(method, "/api/admin/"+endpoint, bytes.NewReader(setupBody(testSetupToken, testAuthentication)))
			if header == "Origin" {
				r.Header.Set(header, "https://evil.example")
			} else {
				r.Header.Set(header, "cross-site")
			}
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != 403 {
				t.Fatalf("cross-origin %s accepted: %d", endpoint, w.Code)
			}
		}
	}
	s := freshServer(t)
	for i := 0; i < 20; i++ {
		if w := request(s, "POST", "/api/admin/setup", setupBody("wrong", testAuthentication), false, ""); w.Code != 401 {
			t.Fatal("early throttle", i, w.Code)
		}
	}
	if w := request(s, "POST", "/api/admin/setup", setupBody(testSetupToken, testAuthentication), false, ""); w.Code != 429 {
		t.Fatal("setup throttle bypassed", w.Code)
	}
	if w := request(s, "GET", "/api/admin/config", nil, true, ""); w.Code != 429 {
		t.Fatal("shared failure throttle bypassed", w.Code)
	}
	now := time.Now().Add(61 * time.Second)
	s.now = func() time.Time { return now }
	r := httptest.NewRequest("POST", "https://drive.example/api/admin/setup", bytes.NewReader(setupBody(testSetupToken, testAuthentication)))
	r.Header.Set("Origin", "https://drive.example")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatal("same-origin setup after throttle expiry denied", w.Code)
	}
	s = freshServer(t)
	for i := 0; i < 20; i++ {
		if w := request(s, "GET", "/api/admin/auth", nil, false, ""); w.Code != 200 {
			t.Fatal("early discovery throttle")
		}
	}
	if w := request(s, "GET", "/api/admin/auth", nil, false, ""); w.Code != 429 {
		t.Fatal("unbounded discovery")
	}
}

func TestConcurrentSetupAcrossServerInstances(t *testing.T) {
	first := freshServer(t)
	second, err := newServer(first.root, "other-admin", testSetupToken, first.origin, first.quota)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for _, s := range []*Server{first, second} {
		wg.Add(1)
		go func(s *Server) {
			defer wg.Done()
			codes <- request(s, "POST", "/api/admin/setup", setupBody(testSetupToken, testAuthentication), false, "").Code
		}(s)
	}
	wg.Wait()
	close(codes)
	success := 0
	for code := range codes {
		if code == 204 {
			success++
		} else if code != 409 {
			t.Fatalf("unexpected setup status %d", code)
		}
	}
	if success != 1 {
		t.Fatalf("successful setups: %d", success)
	}
	restarted, err := newServer(first.root, "ignored", "", first.origin, first.quota)
	if err != nil {
		t.Fatal(err)
	}
	if basicRequest(restarted, restarted.user, testAuthentication).Code != 200 {
		t.Fatal("winning enrollment was not persisted")
	}
}
