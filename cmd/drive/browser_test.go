package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

func TestBrowserProfiles(t *testing.T) {
	cases := []struct {
		name, ua, browser, os, device string
	}{
		{"Chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36", "Chrome", "Windows", "desktop"},
		{"Edge", "Mozilla/5.0 (Windows NT 10.0) Chrome/130.0 Safari/537.36 Edg/130.0", "Edge", "Windows", "desktop"},
		{"Opera", "Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0 Safari/537.36 OPR/115.0", "Opera", "Linux", "desktop"},
		{"Samsung", "Mozilla/5.0 (Linux; Android 14) SamsungBrowser/27.0 Chrome/125.0 Mobile Safari/537.36", "Samsung Internet", "Android", "mobile"},
		{"Firefox", "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0", "Firefox", "Linux", "desktop"},
		{"Safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15", "Safari", "macOS", "desktop"},
		{"iPhone", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Version/18.0 Mobile/15E148 Safari/604.1", "Safari", "iOS", "mobile"},
		{"iPad", "Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) Version/18.0 Mobile/15E148 Safari/604.1", "Safari", "iOS", "tablet"},
		{"Android tablet", "Mozilla/5.0 (Linux; Android 14; Tablet) Chrome/130.0 Safari/537.36", "Chrome", "Android", "tablet"},
		{"Android without Mobile", "Mozilla/5.0 (Linux; Android 14) Chrome/130.0 Safari/537.36", "Chrome", "Android", "tablet"},
		{"Chrome iOS", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) CriOS/130.0 Mobile/15E148 Safari/604.1", "Chrome", "iOS", "mobile"},
		{"Edge iOS", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) CriOS/130.0 EdgiOS/130.0 Mobile/15E148 Safari/604.1", "Edge", "iOS", "mobile"},
		{"Firefox iOS", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) FxiOS/132.0 Mobile/15E148 Safari/604.1", "Firefox", "iOS", "mobile"},
		{"Chrome OS", "Mozilla/5.0 (X11; CrOS x86_64 16000) Chrome/130.0 Safari/537.36", "Chrome", "Chrome OS", "desktop"},
		{"Chromium", "Mozilla/5.0 (X11; Linux x86_64) Chromium/130.0", "Chromium", "Linux", "desktop"},
		{"unrecognized", "curl/8.0", "unknown", "unknown", "unknown"},
		{"empty", "", "unknown", "unknown", "unknown"},
		{"Safari token alone", "Something Safari/537.36", "unknown", "unknown", "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/", nil)
			r.Header.Set("User-Agent", c.ua)
			p := browserProfile(r)
			if p.Browser != c.browser || p.OS != c.os || p.DeviceType != c.device || p.UserAgent != c.ua {
				t.Fatalf("got %+v, want %s/%s/%s", p, c.browser, c.os, c.device)
			}
		})
	}
}

func TestBrowserHintsAreOptionalBoundedClaims(t *testing.T) {
	cases := []struct {
		name, ua, brands, platform, mobile, browser, os, device string
	}{
		{"Edge priority", "", `"Not_A Brand";v="99", "Chromium";v="130", "Google Chrome";v="130", "Microsoft Edge";v="130"`, `"Windows"`, "?0", "Edge", "Windows", "desktop"},
		{"Opera priority", "", `"Chromium";v="130", "Opera";v="115", "Google Chrome";v="130"`, `"Linux"`, "?0", "Opera", "Linux", "desktop"},
		{"Samsung priority", "", `"Google Chrome";v="130", "Samsung Internet";v="27"`, `"Android"`, "?1", "Samsung Internet", "Android", "mobile"},
		{"spoofed hints", "Firefox/130.0 (X11; Linux x86_64)", `"Google Chrome";v="130"`, `"Windows"`, "?1", "Chrome", "Windows", "mobile"},
		{"generic hint preserves Edge", "Chrome/130 Edg/130 Windows NT 10.0", `"Chromium";v="130"`, "", "", "Edge", "Windows", "desktop"},
		{"tablet not desktop", "Android 14 Tablet Chrome/130", `"Chromium";v="130"`, `"Android"`, "?0", "Chrome", "Android", "tablet"},
		{"grease ignored", "", `"Not_A Brand";v="99"`, `"Plan9"`, "?2", "unknown", "unknown", "unknown"},
		{"malformed ignored", "", `"Google Chrome";v="130", garbage`, `Windows`, "true", "unknown", "unknown", "unknown"},
		{"oversized ignored", "", strings.Repeat("x", 513), `"` + strings.Repeat("x", 65) + `"`, strings.Repeat("?1", 300), "unknown", "unknown", "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/", nil)
			r.Header.Set("User-Agent", c.ua)
			r.Header.Set("Sec-CH-UA", c.brands)
			r.Header.Set("Sec-CH-UA-Platform", c.platform)
			r.Header.Set("Sec-CH-UA-Mobile", c.mobile)
			p := browserProfile(r)
			if p.Browser != c.browser || p.OS != c.os || p.DeviceType != c.device {
				t.Fatalf("got %+v, want %s/%s/%s", p, c.browser, c.os, c.device)
			}
		})
	}
}

func TestUserAgentBoundedUTF8(t *testing.T) {
	for _, ua := range []string{strings.Repeat("a", 10000), strings.Repeat("a", 511) + "€more", strings.Repeat("界", 300), "bad\xff\xfe" + strings.Repeat("b", 600)} {
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set("User-Agent", ua)
		p := browserProfile(r)
		if len(p.UserAgent) > 512 || !utf8.ValidString(p.UserAgent) {
			t.Fatalf("unsafe raw UA: %d", len(p.UserAgent))
		}
	}
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("User-Agent", strings.Repeat("x", 512)+" Chrome/130 Windows NT 10.0")
	p := browserProfile(r)
	if p.Browser != "unknown" || p.OS != "unknown" {
		t.Fatal("parsed beyond bounded input")
	}
}

type claimWriter struct {
	*httptest.ResponseRecorder
	onWrite func()
}

func (w *claimWriter) Write(b []byte) (int, error) {
	if w.onWrite != nil {
		fn := w.onWrite
		w.onWrite = nil
		fn()
	}
	return w.ResponseRecorder.Write(b)
}

func TestBrowserClaimOnlyAndAtomicPersistence(t *testing.T) {
	s := testServer(t)
	id := readyPackage(t, s)
	path := "/api/packages/" + id
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("User-Agent", "Chrome/130 Windows NT 10.0")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 200 || s.packages[id].OpenedBrowser != nil || s.packages[id].OpenedAt != nil || s.packages[id].OpenedIP != "" {
			t.Fatal("preview recorded profile")
		}
		if w.Header().Get("Accept-CH") != "" || w.Header().Get("Critical-CH") != "" {
			t.Fatal("requested active client hints")
		}
	}
	r := httptest.NewRequest("POST", path+"/consume", nil)
	r.RemoteAddr = "192.0.2.123:4444"
	r.Header.Set("User-Agent", `Chrome/130 Windows NT 10.0 <script>alert('spoofed')</script>`)
	r.Header.Set("Sec-CH-UA-Model", "must not collect model")
	w := &claimWriter{ResponseRecorder: httptest.NewRecorder()}
	w.onWrite = func() {
		b, err := os.ReadFile(filepath.Join(s.dir(id), "meta.json"))
		if err != nil {
			t.Fatal(err)
		}
		var d diskPackage
		if err := json.Unmarshal(b, &d); err != nil {
			t.Fatal(err)
		}
		if d.Status != "consuming" || d.OpenedAt == nil || d.OpenedIP != "192.0.2.123" || d.OpenedBrowser == nil || d.OpenedBrowser.UserAgent != r.UserAgent() {
			t.Fatal("profile/IP/time not persisted with atomic claim")
		}
		if bytes.Contains(b, []byte("must not collect model")) || bytes.Contains(b, []byte("<script>")) {
			t.Fatal("high-entropy collection or unescaped JSON")
		}
		patchLabel(t, s, id, nameEnvelope(17))
	}
	s.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.Len() != 72 {
		t.Fatal("download changed", w.Code)
	}
	before := *s.packages[id].OpenedBrowser
	if request(s, "POST", path+"/consume", nil, false, "").Code != 404 || *s.packages[id].OpenedBrowser != before {
		t.Fatal("failed claim overwrote browser")
	}
	list := request(s, "GET", "/api/admin/packages", nil, true, "")
	if !bytes.Contains(list.Body.Bytes(), []byte("openedBrowser")) || bytes.Contains(list.Body.Bytes(), []byte("<script>")) {
		t.Fatal("admin profile absent or unescaped")
	}
	restarted, err := newServer(s.root, s.user, "", s.origin, s.quota)
	if err != nil || restarted.packages[id].OpenedBrowser == nil || *restarted.packages[id].OpenedBrowser != before {
		t.Fatal("browser did not survive restart", err)
	}
}

func TestConcurrentClaimCapturesOnlyWinnerProfile(t *testing.T) {
	s := testServer(t)
	id := readyPackage(t, s)
	var wg sync.WaitGroup
	type outcome struct {
		ua   string
		code int
	}
	results := make(chan outcome, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ua := fmt.Sprintf("Firefox/130 Linux winner-%d", i)
			r := httptest.NewRequest("POST", "/api/packages/"+id+"/consume", nil)
			r.Header.Set("User-Agent", ua)
			r.RemoteAddr = fmt.Sprintf("192.0.2.%d:1234", i+1)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			results <- outcome{ua, w.Code}
		}(i)
	}
	wg.Wait()
	close(results)
	wins := 0
	for result := range results {
		if result.code == 200 {
			wins++
			if s.packages[id].OpenedBrowser.UserAgent != result.ua {
				t.Fatal("losing request overwrote profile")
			}
		} else if result.code != 404 {
			t.Fatal("unexpected claim code", result.code)
		}
	}
	if wins != 1 {
		t.Fatal("claim count", wins)
	}
	b, err := os.ReadFile(filepath.Join(s.dir(id), "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d diskPackage
	if err := json.Unmarshal(b, &d); err != nil || d.OpenedBrowser == nil || *d.OpenedBrowser != *s.packages[id].OpenedBrowser {
		t.Fatal("winner profile not durable", err)
	}
}
