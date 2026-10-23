package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func directClaim(s *Server, id, token string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/packages/"+id+"/consume", bytes.NewReader(body))
	if token != "" {
		r.Header.Set("X-Claim-Token", token)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestClaimProofRejectedWithoutConsumption(t *testing.T) {
	s := testServer(t)
	id := readyPackage(t, s)
	for _, token := range []string{"", "invalid", downloadClaimHashFixture, "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"} {
		if w := directClaim(s, id, token, nil); w.Code != 404 {
			t.Fatalf("invalid proof: %d", w.Code)
		}
		p := s.packages[id]
		if p.Status != "ready" || p.OpenedAt != nil || p.OpenedBrowser != nil || p.OpenedIP != "" {
			t.Fatal("invalid proof changed package or audit")
		}
		if _, err := os.Stat(s.chunk(id, 0)); err != nil {
			t.Fatal("invalid proof destroyed ciphertext", err)
		}
	}
	if w := directClaim(s, id, downloadClaimTokenFixture, nil); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if w := directClaim(s, id, downloadClaimTokenFixture, nil); w.Code != 404 {
		t.Fatal("proof allowed a repeat claim")
	}
}

func TestFinalizeRequiresClaimVerifier(t *testing.T) {
	s := testServer(t)
	id, uploadToken := createPackage(t, s)
	if w := request(s, "PUT", "/api/admin/packages/"+id+"/chunks/0", bytes.Repeat([]byte{1}, 32), true, uploadToken); w.Code != 204 {
		t.Fatal(w.Code)
	}
	for _, claimHash := range []string{"", "invalid", downloadClaimTokenFixture} {
		body := []byte(fmt.Sprintf(`{"chunks":1,"claimHash":%q}`, claimHash))
		if w := request(s, "POST", "/api/admin/packages/"+id+"/finalize", body, true, uploadToken); w.Code != 400 {
			t.Fatal("invalid verifier accepted", w.Code)
		}
		if s.packages[id].Status != "uploading" {
			t.Fatal("invalid finalization changed package")
		}
	}
	if w := request(s, "POST", "/api/admin/packages/"+id+"/finalize", finalizeBody(1), true, uploadToken); w.Code != 204 {
		t.Fatal(w.Code)
	}
}

func TestLegacyAndBodyClaimsFailClosed(t *testing.T) {
	s := testServer(t)
	id := readyPackage(t, s)
	if w := directClaim(s, id, downloadClaimTokenFixture, []byte("unexpected body")); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if s.packages[id].Status != "ready" {
		t.Fatal("body-bearing request consumed package")
	}
	s.packages[id].ClaimHash = ""
	if err := s.save(s.packages[id]); err != nil {
		t.Fatal(err)
	}
	if w := request(s, "GET", "/api/packages/"+id, nil, false, ""); w.Code != 404 {
		t.Fatal("legacy metadata offered unprotected download")
	}
	if w := directClaim(s, id, downloadClaimTokenFixture, nil); w.Code != 404 {
		t.Fatal("legacy package consumed")
	}
	chunks, _ := filepath.Glob(filepath.Join(s.dir(id), "*.bin"))
	if len(chunks) != 2 {
		t.Fatal("legacy ciphertext deleted early")
	}
}

func TestGlobalAuthenticationFailureBudgetDoesNotBlockValidCredentials(t *testing.T) {
	s := testServer(t)
	limits := defaultGateLimits()
	limits.authFailuresPerMinute = 1
	s.gate = newRequestGate(limits)
	for n, expected := range []int{401, 429} {
		r := httptest.NewRequest("GET", "/api/admin/packages", nil)
		r.RemoteAddr = fmt.Sprintf("192.0.2.%d:1000", n+10)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != expected {
			t.Fatalf("global authentication budget: %d want %d", w.Code, expected)
		}
	}
	if w := request(s, "GET", "/api/admin/packages", nil, true, ""); w.Code != 200 {
		t.Fatal("global failure budget blocked valid credentials", w.Code)
	}
}

func TestGlobalBudgetsAndBusyClaimsPreserveData(t *testing.T) {
	s := testServer(t)
	id := readyPackage(t, s)
	limits := defaultGateLimits()
	limits.publicPerMinute = 2
	s.gate = newRequestGate(limits)
	unknown := strings.Repeat("ab", 32)
	for n := 0; n < 3; n++ {
		r := httptest.NewRequest("GET", "/api/packages/"+unknown, nil)
		r.RemoteAddr = fmt.Sprintf("192.0.2.%d:1000", n)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		want := 404
		if n == 2 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("global public failure budget: %d want %d", w.Code, want)
		}
	}
	for n := 0; n < 3; n++ {
		r := httptest.NewRequest("GET", "/api/packages/"+id, nil)
		r.RemoteAddr = fmt.Sprintf("192.0.2.%d:1000", n+10)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("exhausted failure budget blocked a valid link: %d", w.Code)
		}
	}
	s.gate = newRequestGate(defaultGateLimits())
	var release []func()
	for n := 0; n < defaultGateLimits().maxDownloads; n++ {
		r, ok := s.gate.acquire(httptest.NewRequest("POST", "/api/packages/"+id+"/consume", nil))
		if !ok {
			t.Fatal("could not occupy download slot")
		}
		release = append(release, r)
	}
	if w := directClaim(s, id, downloadClaimTokenFixture, nil); w.Code != 429 {
		t.Fatal("download admission ignored", w.Code)
	}
	if s.packages[id].Status != "ready" || s.packages[id].OpenedAt != nil {
		t.Fatal("busy response consumed package")
	}
	for _, r := range release {
		r()
	}
	if w := directClaim(s, id, downloadClaimTokenFixture, nil); w.Code != 200 {
		t.Fatal("capacity did not recover", w.Code)
	}
}
