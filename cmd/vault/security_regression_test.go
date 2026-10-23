package main

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBlockedClientCannotExhaustPublicBudget(t *testing.T) {
	s := testServer(t)
	s.now = func() time.Time { return time.Date(2026, 10, 18, 10, 0, 1, 0, time.UTC) }
	id := readyPackage(t, s)
	for n := 0; n < 600; n++ {
		r := httptest.NewRequest("GET", "/api/packages/invalid", nil)
		r.RemoteAddr = "192.0.2.10:1234"
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if n >= 120 && w.Code != 429 {
			t.Fatalf("blocked client request %d returned %d", n, w.Code)
		}
	}
	if s.gate.publicFailures.count != 120 {
		t.Fatalf("blocked client spent the shared budget: %d", s.gate.publicFailures.count)
	}
	r := httptest.NewRequest("GET", "/api/packages/"+id, nil)
	r.RemoteAddr = "192.0.2.20:1234"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 || s.packages[id].Status != "ready" {
		t.Fatalf("unrelated client blocked: %d %s", w.Code, w.Body)
	}
}

func TestPublicAndAdminDiscoveryBudgetsAreIndependent(t *testing.T) {
	s := testServer(t)
	now := time.Date(2026, 10, 18, 10, 0, 1, 0, time.UTC)
	s.now = func() time.Time { return now }
	s.gate = newRequestGate(defaultGateLimits())
	id := readyPackage(t, s)
	for s.gate.allowPublicFailure(now) {
	}
	for n := 0; n < 100; n++ {
		w := request(s, "GET", "/api/admin/auth", nil, false, "")
		want := 200
		if n >= 20 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("discovery request %d returned %d; want %d", n, w.Code, want)
		}
	}
	if s.gate.adminDiscovery.count != 20 {
		t.Fatalf("blocked discovery spent the shared budget: %d", s.gate.adminDiscovery.count)
	}
	for s.gate.allowAdminDiscovery(now) {
	}
	now = now.Add(time.Minute)
	if !s.gate.allowPublicFailure(now) {
		t.Fatal("public budget did not reset")
	}
	for s.gate.allowAdminDiscovery(now) {
	}
	if w := request(s, "GET", "/api/packages/"+id, nil, false, ""); w.Code != 200 {
		t.Fatalf("admin traffic exhausted public budget: %d", w.Code)
	}
}

func TestSetupBudgetIsIndependentOfPublicTraffic(t *testing.T) {
	s, err := newServer(t.TempDir(), "admin", testSetupToken, "https://vault.example", 100*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 18, 10, 0, 1, 0, time.UTC)
	s.now = func() time.Time { return now }
	for s.gate.allowPublicFailure(now) {
	}
	w := request(s, "POST", "/api/admin/setup", setupBody(testSetupToken, testAuthentication), false, "")
	if w.Code != 204 || s.auth == nil || s.gate.adminDiscovery.count != 1 {
		t.Fatalf("public traffic blocked setup: %d %s", w.Code, w.Body)
	}
	if s.gate.publicFailures.count != s.gate.limits.publicPerMinute {
		t.Fatal("setup changed public budget")
	}
}

func TestNoncanonicalClaimsCannotBypassDownloadCapacity(t *testing.T) {
	for _, prefix := range []string{"/", "//"} {
		for _, suffix := range []string{"", "/", "//"} {
			t.Run(prefix+"consume"+suffix, func(t *testing.T) {
				s := testServer(t)
				id := readyPackage(t, s)
				for n := 0; n < s.gate.limits.maxDownloads; n++ {
					s.gate.downloads <- struct{}{}
				}
				r := httptest.NewRequest("POST", prefix+"api/packages/"+id+"/consume"+suffix, nil)
				r.Header.Set("X-Claim-Token", downloadClaimTokenFixture)
				w := httptest.NewRecorder()
				s.ServeHTTP(w, r)
				if w.Code != 429 || s.packages[id].Status != "ready" || s.packages[id].OpenedAt != nil {
					t.Fatalf("claim bypassed capacity or modified audit: %d %s", w.Code, w.Body)
				}
				<-s.gate.downloads
				w = httptest.NewRecorder()
				s.ServeHTTP(w, r)
				if w.Code != 200 || s.packages[id].Status != "consumed" {
					t.Fatalf("capacity did not recover: %d %s", w.Code, w.Body)
				}
			})
		}
	}
}

func TestExhaustedFailureBudgetDoesNotBlockValidRecipients(t *testing.T) {
	s := testServer(t)
	s.now = func() time.Time { return time.Date(2026, 10, 18, 10, 0, 1, 0, time.UTC) }
	id := readyPackage(t, s)
	reusable := reusablePackage(t, s)
	// Many sources spraying unknown IDs and forged proofs exhaust only the failure budget.
	for n := 0; n < 700; n++ {
		path, method := "/api/packages/"+strings.Repeat("cd", 32), "GET"
		if n%2 == 1 {
			path, method = "/api/packages/"+reusable+"/consume", "POST"
		}
		r := httptest.NewRequest(method, path, nil)
		r.Header.Set("X-Claim-Token", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE")
		r.RemoteAddr = fmt.Sprintf("198.51.100.%d:1000", n%250)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if n >= s.gate.limits.publicPerMinute && w.Code != 429 {
			t.Fatalf("failure %d returned %d after the shared budget was spent", n, w.Code)
		}
	}
	if s.packages[reusable].RetrievalCount != 0 {
		t.Fatal("forged proofs created audit records")
	}
	r := httptest.NewRequest("GET", "/api/packages/"+id, nil)
	r.RemoteAddr = "203.0.113.7:1000"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("metadata for a real link was blocked: %d %s", w.Code, w.Body)
	}
	if w := directClaim(s, id, downloadClaimTokenFixture, nil); w.Code != 200 || s.packages[id].Status != "consumed" {
		t.Fatalf("claim for a real link was blocked: %d %s", w.Code, w.Body)
	}
}

func TestFullLimitTableKeepsTrackedClients(t *testing.T) {
	s := testServer(t)
	now := time.Date(2026, 10, 18, 10, 0, 1, 0, time.UTC)
	s.now = func() time.Time { return now }
	id := readyPackage(t, s)
	get := func(ip string) int {
		r := httptest.NewRequest("GET", "/api/packages/"+id, nil)
		r.RemoteAddr = ip + ":1000"
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w.Code
	}
	if code := get("203.0.113.1"); code != 200 {
		t.Fatal("tracked client setup", code)
	}
	s.mu.Lock()
	for n := 0; len(s.limits) < 10000; n++ {
		s.limits[fmt.Sprintf("public:flood-%d", n)] = bucket{start: now, count: 1}
	}
	s.mu.Unlock()
	if code := get("203.0.113.1"); code != 200 {
		t.Fatalf("full table blocked an already-tracked client: %d", code)
	}
	if code := get("203.0.113.2"); code != 429 {
		t.Fatalf("full table admitted a new key: %d", code)
	}
	now = now.Add(time.Minute)
	if code := get("203.0.113.2"); code != 200 {
		t.Fatalf("expired entries were not pruned: %d", code)
	}
}

func TestPerPackageClaimLimitPrecedesAudit(t *testing.T) {
	s := testServer(t)
	now := time.Date(2026, 10, 18, 10, 0, 1, 0, time.UTC)
	s.now = func() time.Time { return now }
	id := reusablePackage(t, s)
	for n := 0; n < maxClaimsPerPackagePerMinute; n++ {
		if w := directClaim(s, id, downloadClaimTokenFixture, nil); w.Code != 200 {
			t.Fatalf("claim %d: %d %s", n, w.Code, w.Body)
		}
	}
	w := directClaim(s, id, downloadClaimTokenFixture, nil)
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("per-package claim limit not enforced: %d", w.Code)
	}
	if p := s.packages[id]; p.RetrievalCount != maxClaimsPerPackagePerMinute || p.Status != "ready" {
		t.Fatalf("limited claim changed state: count %d status %s", p.RetrievalCount, p.Status)
	}
	if w := directClaim(s, readyPackage(t, s), downloadClaimTokenFixture, nil); w.Code != 200 {
		t.Fatal("limit leaked to another package", w.Code)
	}
	now = now.Add(time.Minute)
	if w := directClaim(s, id, downloadClaimTokenFixture, nil); w.Code != 200 {
		t.Fatal("per-package limit did not reset", w.Code)
	}
}
