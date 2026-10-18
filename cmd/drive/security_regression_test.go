package main

import (
	"net/http/httptest"
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
	if s.gate.public.count != 120 {
		t.Fatalf("blocked client spent the shared budget: %d", s.gate.public.count)
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
	for s.gate.allowPublic(now) {
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
	if !s.gate.allowPublic(now) {
		t.Fatal("public budget did not reset")
	}
	for s.gate.allowAdminDiscovery(now) {
	}
	if w := request(s, "GET", "/api/packages/"+id, nil, false, ""); w.Code != 200 {
		t.Fatalf("admin traffic exhausted public budget: %d", w.Code)
	}
}

func TestSetupBudgetIsIndependentOfPublicTraffic(t *testing.T) {
	s, err := newServer(t.TempDir(), "admin", testSetupToken, "https://drive.example", 100*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 18, 10, 0, 1, 0, time.UTC)
	s.now = func() time.Time { return now }
	for s.gate.allowPublic(now) {
	}
	w := request(s, "POST", "/api/admin/setup", setupBody(testSetupToken, testAuthentication), false, "")
	if w.Code != 204 || s.auth == nil || s.gate.adminDiscovery.count != 1 {
		t.Fatalf("public traffic blocked setup: %d %s", w.Code, w.Body)
	}
	if s.gate.public.count != s.gate.limits.publicPerMinute {
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
